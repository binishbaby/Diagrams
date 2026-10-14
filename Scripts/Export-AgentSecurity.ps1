<#
.SYNOPSIS
    Exports the security posture and permissions of every AI agent in a Microsoft 365 / Entra tenant.

.DESCRIPTION
    Read-only inventory of Microsoft Entra Agent ID objects and the Agent 365 / Copilot agent catalog.
    No tenant settings are changed - every Graph call is a GET.

    Agents discovered
      - Agent identities              servicePrincipals/microsoft.graph.agentIdentity
      - Agent identity blueprints     applications/microsoft.graph.agentIdentityBlueprint
      - Blueprint principals          servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal
      - Agent users                   users/microsoft.graph.agentUser
      - Agent 365 / Copilot catalog   copilot/admin/catalog/packages (+ per-package details)
      - Agent 365 registry            copilot/agentRegistrations (fallback: agentRegistry/agentInstances)

    Collected per agent
      owners, sponsors, application permissions (direct + inherited from blueprint), delegated
      permissions (direct + inherited), directory roles (active + PIM eligible), group memberships,
      users/groups assigned to the agent, blueprint credentials and expiry, Conditional Access policies
      that target the agent, Entra ID Protection risk + risk detections, last sign-in, and
      (optional) a sign-in log summary.

    Output (in -OutputFolder\AgentSecurity_<tenant>_<timestamp>)
      AgentSecurity.xlsx   one tab per table (needs the ImportExcel module; skipped if missing)
      csv\*.csv            the same tables as CSV
      raw\*.json           everything Graph returned, unmodified - build new reports from this
                           without querying the tenant again
      Any endpoint that fails (licence, preview, permission) is logged on the Errors tab and the
      export carries on.

.PARAMETER TenantId
    Tenant ID or domain. Optional for interactive sign-in.

.PARAMETER OutputFolder
    Where the export folder is created. Defaults to the current directory.

.PARAMETER IncludeSignInLogs
    Also pulls agent sign-in logs for the last -SignInDays days and summarises them per agent. Slower.

.PARAMETER SignInDays
    Look-back window for -IncludeSignInLogs. Default 30 (Entra keeps 30 days with P1/P2).

.PARAMETER MaxSignIns
    Safety cap on sign-in records pulled per agent type. Default 50000.

.PARAMETER UseDeviceCode
    Use device-code sign-in (for machines without a browser).

.PARAMETER ClientId
    App registration for unattended (app-only) runs. Use with -CertificateThumbprint and -TenantId.
    The app needs the same permissions as application permissions, admin-consented.

.PARAMETER CertificateThumbprint
    Certificate for app-only authentication.

.PARAMETER ClientSecret
    Client secret (SecureString) for app-only authentication, as an alternative to a certificate.
    Prefer certificates for regular use.

.PARAMETER Scopes
    Override the delegated scopes requested at sign-in.

.EXAMPLE
    .\Export-AgentSecurity.ps1

.EXAMPLE
    $secret = Read-Host 'Client secret' -AsSecureString
    .\Export-AgentSecurity.ps1 -TenantId contoso.onmicrosoft.com -ClientId <app-id> -ClientSecret $secret

.EXAMPLE
    .\Export-AgentSecurity.ps1 -TenantId contoso.onmicrosoft.com -IncludeSignInLogs -SignInDays 14 -OutputFolder C:\Reports

.NOTES
    Requires PowerShell 7+ and Microsoft.Graph.Authentication. ImportExcel is optional (for .xlsx).
        Install-Module Microsoft.Graph.Authentication, ImportExcel -Scope CurrentUser
    Suggested role for the person running it: Global Reader + Security Reader.
    Agent ID, Agent 365 registry, risky agents and the catalog APIs are beta / preview and some need
    an Agent 365 licence - when unavailable they show up on the Errors tab, not as a failure.
#>
[CmdletBinding(DefaultParameterSetName = 'Delegated')]
param(
    [string]$TenantId,
    [string]$OutputFolder = (Get-Location).Path,
    [switch]$IncludeSignInLogs,
    [ValidateRange(1, 30)][int]$SignInDays = 30,
    [int]$MaxSignIns = 50000,
    [Parameter(ParameterSetName = 'Delegated')][switch]$UseDeviceCode,
    [Parameter(ParameterSetName = 'Delegated')][string[]]$Scopes,
    [Parameter(ParameterSetName = 'AppOnly', Mandatory)]
    [Parameter(ParameterSetName = 'AppSecret', Mandatory)][string]$ClientId,
    [Parameter(ParameterSetName = 'AppOnly', Mandatory)][string]$CertificateThumbprint,
    [Parameter(ParameterSetName = 'AppSecret', Mandatory)][securestring]$ClientSecret
)

#Requires -Version 7.0
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------------------------
# Scopes that exist in every tenant. Agent-specific scopes are tried first and dropped if the
# sign-in rejects them, so an unknown scope never blocks the export.
$BaseScopes = @(
    'Application.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All',
    'RoleManagement.Read.Directory', 'IdentityRiskyServicePrincipal.Read.All', 'IdentityRiskEvent.Read.All'
)
$AgentScopes = @('AgentIdentity.Read.All', 'AgentIdentity-Sponsor.Read.All', 'CopilotPackages.Read.All')

# Permissions treated as high privilege in the HighPrivilege column.
$HighPrivilegePatterns = @(
    '^Directory\.(ReadWrite|AccessAsUser)', '^RoleManagement\.ReadWrite', '^Application\.ReadWrite',
    '^AppRoleAssignment\.ReadWrite', '^User\.ReadWrite\.All', '^Group\.ReadWrite\.All', '^GroupMember\.ReadWrite',
    '^Mail\.(ReadWrite|Send)', '^Mail\.Read$', '^Files\.ReadWrite\.All', '^Sites\.(FullControl|ReadWrite|Manage)\.All',
    '^full_access_as_app$', '^Exchange\.ManageAsApp$', '^Policy\.ReadWrite', '^Domain\.ReadWrite',
    '^Organization\.ReadWrite', '^PrivilegedAccess\.ReadWrite', '^UserAuthenticationMethod\.ReadWrite',
    '^DeviceManagement\w*\.ReadWrite', '^Agent\w*\.ReadWrite', '^Chat\.ReadWrite\.All', '^ChannelMessage\.Read\.All',
    '^Calendars\.ReadWrite', '^Contacts\.ReadWrite', '^EWS\.AccessAsUser\.All', '^user_impersonation$'
)

$ExcelCellLimit = 32000

# ---------------------------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------------------------
$script:Tables = [ordered]@{}           # sheet name -> List[object]
$script:Raw = [ordered]@{}              # raw Graph payloads
$script:SpCache = @{}                   # servicePrincipal id -> resource info
$script:DirObjCache = @{}               # directory object id -> display info
$script:FicCache = @{}                  # blueprint federated credentials uri -> results
$script:Started = Get-Date

function Add-Row {
    param([string]$Table, [System.Collections.IDictionary]$Row)
    if (-not $script:Tables.Contains($Table)) { $script:Tables[$Table] = [System.Collections.Generic.List[object]]::new() }
    $script:Tables[$Table].Add([pscustomobject]$Row)
}

$script:ErrCount = @{}
function Add-ErrorRow {
    # Logs the first 3 failures per section; the rest are counted and rolled up at the end.
    param([string]$Section, [string]$Uri, [string]$Message)
    $script:ErrCount[$Section] = 1 + ($script:ErrCount[$Section] ?? 0)
    if ($script:ErrCount[$Section] -gt 3) { return }
    $short = ($Message -split "`n")[0]
    Add-Row 'Errors' ([ordered]@{ Section = $Section; Uri = $Uri; Error = $short; Time = (Get-Date).ToString('s') })
    Write-Warning "[$Section] $short"
}

function Join-Values {
    param($Values, [string]$Separator = '; ')
    if ($null -eq $Values) { return '' }
    (@($Values) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" }) -join $Separator
}

function Get-Prop {
    # Safe property read under StrictMode (missing properties return $null).
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# ---------------------------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------------------------
function Invoke-Graph {
    # Single GET with retry on throttling / transient errors. Returns PSCustomObject.
    param([string]$Uri, [hashtable]$Headers = @{})
    if ($Uri -notmatch '^https://') { $Uri = "https://graph.microsoft.com/$($Uri.TrimStart('/'))" }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $json = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $Headers -OutputType Json
            return ($json | ConvertFrom-Json -Depth 100)
        }
        catch {
            $status = $null
            $resp = Get-Prop $_.Exception 'Response'
            if ($resp) { $status = [int](Get-Prop $resp 'StatusCode') }
            $msg = "$($_.Exception.Message) $(Get-Prop $_.ErrorDetails 'Message')".Trim()
            if (-not $status -and $msg -match '\b(429|503|504)\b') { $status = [int]$Matches[1] }
            if (-not $status -and $msg -match 'TooManyRequests') { $status = 429 }
            if (-not $status -and $msg -match 'ServiceUnavailable|GatewayTimeout') { $status = 503 }
            if ($status -in 429, 503, 504 -and $attempt -le 6) {
                $wait = [math]::Min(60, [math]::Pow(2, $attempt))
                $ra = $null
                if ($resp -and (Get-Prop $resp 'Headers')) {
                    try { $ra = $resp.Headers.RetryAfter.Delta.TotalSeconds } catch { $ra = $null }
                }
                if ($ra) { $wait = [math]::Max($wait, $ra) }
                Write-Verbose "Throttled ($status) on $Uri - waiting $wait s"
                Start-Sleep -Seconds $wait
                continue
            }
            throw "GET $Uri failed: $msg"
        }
    }
}

function Get-GraphAll {
    # Follows @odata.nextLink. Returns an array of items.
    param([string]$Uri, [hashtable]$Headers = @{}, [int]$Max = [int]::MaxValue)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next -and $items.Count -lt $Max) {
        $page = Invoke-Graph -Uri $next -Headers $Headers
        if ($null -ne $page -and $page.PSObject.Properties['value']) { foreach ($v in @($page.value)) { if ($null -ne $v) { $items.Add($v) } } }
        elseif ($null -ne $page) { $items.Add($page) }
        $next = Get-Prop $page '@odata.nextLink'
    }
    return $items.ToArray()
}

function Invoke-Section {
    # Runs a collection step; on failure logs it and returns an empty array instead of stopping.
    param([string]$Section, [string]$Uri, [hashtable]$Headers = @{}, [int]$Max = [int]::MaxValue, [switch]$Single, [switch]$AllowNotFound)
    try {
        if ($Single) { return Invoke-Graph -Uri $Uri -Headers $Headers }
        return Get-GraphAll -Uri $Uri -Headers $Headers -Max $Max
    }
    catch {
        if (-not ($AllowNotFound -and $_.Exception.Message -match 'NotFound|\b404\b')) {
            Add-ErrorRow -Section $Section -Uri $Uri -Message $_.Exception.Message
        }
        if ($Single) { return $null }
        return @()
    }
}

function Get-ResourceSp {
    # Resource service principal with its app roles and delegated scopes (cached).
    param([string]$Id)
    if (-not $Id) { return $null }
    if (-not $script:SpCache.ContainsKey($Id)) {
        $sp = Invoke-Section -Section 'ResolveResource' -Single `
            -Uri "beta/servicePrincipals/$($Id)?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
        $script:SpCache[$Id] = $sp
    }
    return $script:SpCache[$Id]
}

function Resolve-DirectoryObject {
    # id -> "Name (type)" for owners, sponsors, consenting users, etc.
    param([string]$Id)
    if (-not $Id) { return '' }
    if (-not $script:DirObjCache.ContainsKey($Id)) {
        $o = Invoke-Section -Section 'ResolveObject' -Single `
            -Uri "beta/directoryObjects/$($Id)?`$select=id,displayName,userPrincipalName,appId"
        $script:DirObjCache[$Id] = $o
    }
    $o = $script:DirObjCache[$Id]
    if (-not $o) { return $Id }
    Format-DirectoryObject $o
}

function Format-DirectoryObject {
    param($o)
    $type = ((Get-Prop $o '@odata.type') -replace '#microsoft.graph.', '')
    $name = Get-Prop $o 'displayName'
    $upn = Get-Prop $o 'userPrincipalName'
    $label = if ($upn) { "$name <$upn>" } elseif ($name) { $name } else { Get-Prop $o 'id' }
    if ($type) { "$label [$type]" } else { $label }
}

function ConvertTo-JsonText {
    param($Value)
    if ($null -eq $Value) { return '' }
    $Value | ConvertTo-Json -Depth 20 -Compress
}

function Test-HighPrivilege {
    param([string]$Permission)
    foreach ($p in $HighPrivilegePatterns) { if ($Permission -match $p) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication
$haveExcel = [bool](Get-Module -ListAvailable ImportExcel)
if (-not $haveExcel) { Write-Warning 'ImportExcel module not found - CSV and JSON will be written, .xlsx skipped. (Install-Module ImportExcel -Scope CurrentUser)' }

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
    if (-not $TenantId) { throw '-TenantId is required with -ClientId / -CertificateThumbprint.' }
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
}
elseif ($PSCmdlet.ParameterSetName -eq 'AppSecret') {
    if (-not $TenantId) { throw '-TenantId is required with -ClientId / -ClientSecret.' }
    $cred = [pscredential]::new($ClientId, $ClientSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome
}
else {
    $connect = @{ NoWelcome = $true; ContextScope = 'Process' }
    if ($TenantId) { $connect.TenantId = $TenantId }
    if ($UseDeviceCode) { $connect.UseDeviceCode = $true }
    if ($Scopes) {
        Connect-MgGraph @connect -Scopes $Scopes
    }
    else {
        try { Connect-MgGraph @connect -Scopes ($BaseScopes + $AgentScopes) }
        catch {
            Write-Warning "Sign-in with agent-specific scopes failed ($($_.Exception.Message)). Retrying with base scopes only."
            Connect-MgGraph @connect -Scopes $BaseScopes
        }
    }
}
$ctx = Get-MgContext
if (-not $ctx) { throw 'Not connected to Microsoft Graph.' }
$tenantLabel = $ctx.TenantId
$org = @(Invoke-Section -Section 'Organization' -Uri 'v1.0/organization?$select=id,displayName,verifiedDomains')
if ($org.Count -gt 0) {
    $default = @($org[0].verifiedDomains | Where-Object isDefault) | Select-Object -First 1
    if ($default) { $tenantLabel = $default.name }
}
Write-Host "Connected to $tenantLabel as $($ctx.Account ?? $ctx.AppName)" -ForegroundColor Green

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutputFolder ("AgentSecurity_{0}_{1}" -f ($tenantLabel -replace '[^\w\.-]', '_'), $stamp)
New-Item -ItemType Directory -Path (Join-Path $outDir 'csv'), (Join-Path $outDir 'raw') -Force | Out-Null

# ---------------------------------------------------------------------------------------------
# 1. Discover agents
# ---------------------------------------------------------------------------------------------
Write-Host 'Discovering agents...' -ForegroundColor Cyan
$agentIdentities   = @(Invoke-Section 'AgentIdentities'      'beta/servicePrincipals/microsoft.graph.agentIdentity?$top=999')
$blueprintPrincs   = @(Invoke-Section 'BlueprintPrincipals'  'beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$top=999')
$blueprints        = @(Invoke-Section 'Blueprints'           'beta/applications/microsoft.graph.agentIdentityBlueprint?$top=999')
$agentUsers        = @(Invoke-Section 'AgentUsers'           'beta/users/microsoft.graph.agentUser?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,mail,jobTitle,department,assignedLicenses,identityParentId,signInActivity')
if ($agentUsers.Count -eq 0 -and @($script:Tables['Errors'] | Where-Object Section -eq 'AgentUsers').Count -gt 0) {
    # signInActivity needs AuditLog.Read.All + P1; retry without it.
    $before = $script:ErrCount['AgentUsers(noSignIn)'] ?? 0
    $agentUsers    = @(Invoke-Section 'AgentUsers(noSignIn)' 'beta/users/microsoft.graph.agentUser?$top=999')
    if (($script:ErrCount['AgentUsers(noSignIn)'] ?? 0) -eq $before) {
        # Retry worked - the first attempt is not a real failure.
        $script:ErrCount.Remove('AgentUsers')
        $errs = $script:Tables['Errors']
        foreach ($e in @($errs | Where-Object Section -eq 'AgentUsers')) { [void]$errs.Remove($e) }
    }
}
$script:Raw.AgentIdentities = $agentIdentities
$script:Raw.BlueprintPrincipals = $blueprintPrincs
$script:Raw.Blueprints = $blueprints
$script:Raw.AgentUsers = $agentUsers

Write-Host "  Agent identities: $($agentIdentities.Count)  Blueprints: $($blueprints.Count)  Blueprint principals: $($blueprintPrincs.Count)  Agent users: $($agentUsers.Count)"

# Blueprint lookup by appId (agentIdentityBlueprintId holds the blueprint's appId)
$blueprintByAppId = @{}
foreach ($b in $blueprints) {
    if (Get-Prop $b 'appId') { $blueprintByAppId[$b.appId] = $b }
    $blueprintByAppId[$b.id] = $b
}

# ---------------------------------------------------------------------------------------------
# 2. Tenant-wide lookups (fetched once)
# ---------------------------------------------------------------------------------------------
Write-Host 'Reading tenant-wide data (roles, Conditional Access, risk, sign-in activity)...' -ForegroundColor Cyan
$roleDefs     = @(Invoke-Section 'RoleDefinitions'       'beta/roleManagement/directory/roleDefinitions')
$roleAssigns  = @(Invoke-Section 'RoleAssignments'       'v1.0/roleManagement/directory/roleAssignments')
$roleEligible = @(Invoke-Section 'RoleEligibility'       'v1.0/roleManagement/directory/roleEligibilitySchedules')
$caPolicies   = @(Invoke-Section 'ConditionalAccess'     'beta/identity/conditionalAccess/policies')
$riskyAgents  = @(Invoke-Section 'RiskyAgents'           'beta/identityProtection/riskyAgents')
$riskDetects  = @(Invoke-Section 'AgentRiskDetections'   'beta/identityProtection/agentRiskDetections')
$spSignInAct  = @(Invoke-Section 'SpSignInActivity'      'beta/reports/servicePrincipalSignInActivities')
$script:Raw.RoleDefinitions = $roleDefs
$script:Raw.RoleAssignments = $roleAssigns
$script:Raw.RoleEligibilitySchedules = $roleEligible
$script:Raw.ConditionalAccessPolicies = $caPolicies
$script:Raw.RiskyAgents = $riskyAgents
$script:Raw.AgentRiskDetections = $riskDetects
$script:Raw.ServicePrincipalSignInActivities = $spSignInAct

$roleName = @{}; foreach ($r in $roleDefs) { $roleName[$r.id] = $r }
$riskById = @{}; foreach ($r in $riskyAgents) { $riskById[$r.id] = $r }
$detectionsById = @{}
foreach ($d in $riskDetects) {
    foreach ($k in @((Get-Prop $d 'agentId'), (Get-Prop $d 'identityId')) | Where-Object { $_ } | Select-Object -Unique) {
        if (-not $detectionsById.ContainsKey($k)) { $detectionsById[$k] = [System.Collections.Generic.List[object]]::new() }
        $detectionsById[$k].Add($d)
    }
}
$signInActByAppId = @{}; foreach ($s in $spSignInAct) { if (Get-Prop $s 'appId') { $signInActByAppId[$s.appId] = $s } }

# ---------------------------------------------------------------------------------------------
# 3. Agent 365 catalog and registry
# ---------------------------------------------------------------------------------------------
Write-Host 'Reading Agent 365 catalog and registry...' -ForegroundColor Cyan
$packages = @(Invoke-Section 'CatalogPackages' 'beta/copilot/admin/catalog/packages')
$packageDetails = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($p in $packages) {
    $i++
    Write-Progress -Activity 'Catalog package details' -Status $p.displayName -PercentComplete (100 * $i / [math]::Max(1, $packages.Count))
    $d = Invoke-Section 'CatalogPackageDetail' "beta/copilot/admin/catalog/packages/$($p.id)" -Single
    $packageDetails.Add(($d ?? $p))
}
Write-Progress -Activity 'Catalog package details' -Completed
$script:Raw.CatalogPackages = $packageDetails

$registrations = @(Invoke-Section 'Agent365Registry' 'beta/copilot/agentRegistrations')
$script:Raw.Agent365Registrations = $registrations
$legacyInstances = @()
if ($registrations.Count -eq 0) {
    $legacyInstances = @(Invoke-Section 'LegacyAgentRegistry' 'beta/agentRegistry/agentInstances')
    $script:Raw.LegacyAgentInstances = $legacyInstances
}

$packageByAgentId = @{}
foreach ($p in $packageDetails) {
    $aid = Get-Prop $p 'agentIdentityId'
    if ($aid) { $packageByAgentId[$aid] = $p }
    $appId = Get-Prop $p 'appId'
    if ($appId) { $packageByAgentId[$appId] = $p }
}

foreach ($p in $packageDetails) {
    $elements = foreach ($ed in @(Get-Prop $p 'elementDetails')) {
        foreach ($e in @(Get-Prop $ed 'elements')) {
            Add-Row 'CatalogElements' ([ordered]@{
                PackageId = $p.id; PackageName = $p.displayName; ElementType = (Get-Prop $ed 'elementType')
                ElementId = (Get-Prop $e 'id'); Definition = (ConvertTo-JsonText (Get-Prop $e 'definition'))
            })
            Get-Prop $ed 'elementType'
        }
    }
    $access = {
        param($list) Join-Values (@($list) | ForEach-Object { if ($_) { Resolve-DirectoryObject $_.resourceId } })
    }
    Add-Row 'Catalog' ([ordered]@{
        PackageId          = $p.id
        DisplayName        = $p.displayName
        Type               = Get-Prop $p 'type'
        Platform           = Get-Prop $p 'platform'
        Publisher          = Get-Prop $p 'publisher'
        Version            = Get-Prop $p 'version'
        IsBlocked          = Get-Prop $p 'isBlocked'
        AvailableTo        = Get-Prop $p 'availableTo'
        DeployedTo         = Get-Prop $p 'deployedTo'
        AllowedUsersGroups = & $access (Get-Prop $p 'allowedUsersAndGroups')
        AcquiredBy         = & $access (Get-Prop $p 'acquireUsersAndGroups')
        SharedWith         = & $access (Get-Prop $p 'sharedWithUsersAndGroups')
        SupportedHosts     = Join-Values (Get-Prop $p 'supportedHosts')
        ElementTypes       = Join-Values ((@(Get-Prop $p 'elementTypes') + @($elements)) | Select-Object -Unique)
        Sensitivity        = Get-Prop $p 'sensitivity'
        Categories         = Join-Values (Get-Prop $p 'categories')
        ActiveUsers        = Get-Prop $p 'activeUsers'
        TotalSessions      = Get-Prop $p 'totalSessions'
        ExceptionRate      = Get-Prop $p 'exceptionRate'
        LastUsed           = Get-Prop $p 'lastUsedDateTime'
        Owner              = Resolve-DirectoryObject (Get-Prop $p 'ownerId')
        AgentIdentityId    = Get-Prop $p 'agentIdentityId'
        AppId              = Get-Prop $p 'appId'
        RequestStatus      = Get-Prop $p 'requestStatus'
        Created            = Get-Prop $p 'createdDateTime'
        LastModified       = Get-Prop $p 'lastModifiedDateTime'
        ShortDescription   = Get-Prop $p 'shortDescription'
        GovernanceMetadata = (ConvertTo-JsonText (Get-Prop $p 'governanceMetadata'))
    })
}

foreach ($r in @($registrations) + @($legacyInstances)) {
    Add-Row 'Registry' ([ordered]@{
        Id                = $r.id
        DisplayName       = Get-Prop $r 'displayName'
        Description       = Get-Prop $r 'description'
        OriginatingStore  = Get-Prop $r 'originatingStore'
        AgentIdentityId   = Get-Prop $r 'agentIdentityId'
        BlueprintId       = Get-Prop $r 'agentIdentityBlueprintId'
        AgentUserId       = Get-Prop $r 'agentUserId'
        Owners            = Join-Values (@(Get-Prop $r 'ownerIds') | ForEach-Object { Resolve-DirectoryObject $_ })
        CreatedBy         = Get-Prop $r 'createdBy'
        LastPublishedBy   = Get-Prop $r 'lastPublishedBy'
        ManagedBy         = (Get-Prop $r 'managedByAppId') ?? (Get-Prop $r 'managedBy')
        SourceAgentId     = Get-Prop $r 'sourceAgentId'
        Created           = (Get-Prop $r 'sourceCreatedDateTime') ?? (Get-Prop $r 'createdDateTime')
        LastModified      = (Get-Prop $r 'sourceLastModifiedDateTime') ?? (Get-Prop $r 'lastModifiedDateTime')
        Source            = if (Get-Prop $r 'agentCard') { 'Agent 365 registry' } else { 'Legacy agentRegistry' }
    })
}

# ---------------------------------------------------------------------------------------------
# 4. Per-agent collection
# ---------------------------------------------------------------------------------------------
$principals = [System.Collections.Generic.List[object]]::new()
foreach ($a in $agentIdentities) { $principals.Add([pscustomobject]@{ Kind = 'AgentIdentity'; Obj = $a; IsSp = $true }) }
foreach ($a in $blueprintPrincs) { $principals.Add([pscustomobject]@{ Kind = 'BlueprintPrincipal'; Obj = $a; IsSp = $true }) }
foreach ($a in $agentUsers)      { $principals.Add([pscustomobject]@{ Kind = 'AgentUser'; Obj = $a; IsSp = $false }) }

function Get-CaMatches {
    # Conditional Access policies that apply to this agent and why.
    param($Kind, $Obj, [string]$BlueprintAppId, [string]$BlueprintObjId)
    $ids = @($Obj.id, (Get-Prop $Obj 'appId'), $BlueprintAppId, $BlueprintObjId) | Where-Object { $_ }
    foreach ($pol in $caPolicies) {
        $c = Get-Prop $pol 'conditions'
        $reason = $null; $excluded = $false
        if ($Kind -eq 'AgentUser') {
            $ag = Get-Prop $c 'agents'
            $inc = @(Get-Prop $ag 'includeAgentUsers'); $exc = @(Get-Prop $ag 'excludeAgentUsers')
            if ($inc -contains 'All') { $reason = 'All agent users' }
            elseif ($inc | Where-Object { $_ -in $ids }) { $reason = 'Targeted directly' }
            $users = Get-Prop $c 'users'
            if (-not $reason -and @(Get-Prop $users 'includeUsers') -contains $Obj.id) { $reason = 'Targeted as user' }
            $rule = Get-Prop (Get-Prop $ag 'agentFilter') 'rule'
            if (-not $reason -and $rule) { $reason = "Filter rule (verify): $rule" }
            if ($exc | Where-Object { $_ -in $ids }) { $excluded = $true }
        }
        else {
            $ca = Get-Prop $c 'clientApplications'
            $inc = @(Get-Prop $ca 'includeAgentIdServicePrincipals'); $exc = @(Get-Prop $ca 'excludeAgentIdServicePrincipals')
            if ($inc -contains 'All') { $reason = 'All agent identities' }
            elseif ($inc | Where-Object { $_ -eq $Obj.id -or $_ -eq (Get-Prop $Obj 'appId') }) { $reason = 'Targeted directly' }
            elseif ($BlueprintAppId -and ($inc | Where-Object { $_ -in @($BlueprintAppId, $BlueprintObjId) })) { $reason = 'Via blueprint' }
            elseif (@(Get-Prop $ca 'includeServicePrincipals') | Where-Object { $_ -in $ids }) { $reason = 'Targeted as service principal' }
            $rule = Get-Prop (Get-Prop $ca 'agentIdServicePrincipalFilter') 'rule'
            if (-not $reason -and $rule) { $reason = "Filter rule (verify): $rule" }
            if (($exc + @(Get-Prop $ca 'excludeServicePrincipals')) | Where-Object { $_ -in $ids }) { $excluded = $true }
        }
        if ($reason) {
            [pscustomobject]@{ Policy = $pol; Reason = $reason; Excluded = $excluded }
        }
    }
}

function Add-AppPermissionRows {
    param($Agent, $Kind, $Assignments, [string]$Source)
    foreach ($ar in @($Assignments)) {
        if (-not $ar) { continue }
        $res = Get-ResourceSp $ar.resourceId
        $roleVal = $null; $roleDesc = $null
        if ($res) {
            $role = @($res.appRoles) | Where-Object { $_.id -eq $ar.appRoleId } | Select-Object -First 1
            if ($role) { $roleVal = $role.value; $roleDesc = $role.displayName }
        }
        if (-not $roleVal) { $roleVal = if ($ar.appRoleId -eq '00000000-0000-0000-0000-000000000000') { '(default access)' } else { $ar.appRoleId } }
        Add-Row 'AppPermissions' ([ordered]@{
            AgentKind = $Kind; AgentName = $Agent.displayName; AgentId = $Agent.id
            Source = $Source
            Resource = (Get-Prop $ar 'resourceDisplayName') ?? (Get-Prop $res 'displayName')
            Permission = $roleVal; Description = $roleDesc
            HighPrivilege = Test-HighPrivilege $roleVal
            GrantedOn = Get-Prop $ar 'createdDateTime'
            AssignmentId = $ar.id; ResourceId = $ar.resourceId
        })
        $roleVal
    }
}

function Add-DelegatedRows {
    param($Agent, $Kind, $Grants, [string]$Source)
    foreach ($g in @($Grants)) {
        if (-not $g) { continue }
        $res = Get-ResourceSp $g.resourceId
        foreach ($scope in (("$($g.scope)").Trim() -split '\s+' | Where-Object { $_ })) {
            Add-Row 'DelegatedPermissions' ([ordered]@{
                AgentKind = $Kind; AgentName = $Agent.displayName; AgentId = $Agent.id
                Source = $Source
                Resource = Get-Prop $res 'displayName'
                Permission = $scope
                HighPrivilege = Test-HighPrivilege $scope
                ConsentType = $g.consentType
                OnBehalfOf = if ($g.consentType -eq 'AllPrincipals') { 'All users (admin consent)' } else { Resolve-DirectoryObject (Get-Prop $g 'principalId') }
                ClientId = $g.clientId; GrantId = $g.id
            })
            $scope
        }
    }
}

$script:Raw.PerAgent = [System.Collections.Generic.List[object]]::new()
$script:Raw.PerBlueprint = [System.Collections.Generic.List[object]]::new()
Write-Host "Collecting permissions and security for $($principals.Count) agent objects..." -ForegroundColor Cyan
$n = 0
foreach ($pr in $principals) {
    $n++
    $a = $pr.Obj; $kind = $pr.Kind; $id = $a.id
    Write-Progress -Activity 'Agents' -Status "$kind : $($a.displayName)" -PercentComplete (100 * $n / [math]::Max(1, $principals.Count))
    $agentRaw = [ordered]@{ Kind = $kind; Object = $a }

    # Blueprint relationship
    $bpAppId = Get-Prop $a 'agentIdentityBlueprintId'
    if (-not $bpAppId -and $kind -eq 'BlueprintPrincipal') { $bpAppId = Get-Prop $a 'appId' }
    if (-not $bpAppId -and $kind -eq 'AgentUser') { $bpAppId = $null }
    $bp = if ($bpAppId) { $blueprintByAppId[$bpAppId] } else { $null }

    $base = if ($pr.IsSp) { "beta/servicePrincipals/$id" } else { "beta/users/$id" }
    $cast = switch ($kind) {
        'AgentIdentity'      { "$base/microsoft.graph.agentIdentity" }
        'BlueprintPrincipal' { "$base/microsoft.graph.agentIdentityBlueprintPrincipal" }
        default              { $base }
    }

    # Owners & sponsors
    $owners   = @(if ($pr.IsSp) { Invoke-Section "Owners:$kind" "$base/owners?`$select=id,displayName,userPrincipalName,appId" })
    $sponsors = @(Invoke-Section "Sponsors:$kind" "$cast/sponsors?`$select=id,displayName,userPrincipalName,appId")
    $manager  = if (-not $pr.IsSp) { Invoke-Section 'Manager' "$base/manager?`$select=id,displayName,userPrincipalName" -Single -AllowNotFound } else { $null }
    $agentRaw.Owners = $owners; $agentRaw.Sponsors = $sponsors; $agentRaw.Manager = $manager
    foreach ($o in $owners)   { Add-Row 'OwnersSponsors' ([ordered]@{ AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; Relationship = 'Owner';   Principal = Format-DirectoryObject $o; PrincipalId = $o.id }) }
    foreach ($o in $sponsors) { Add-Row 'OwnersSponsors' ([ordered]@{ AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; Relationship = 'Sponsor'; Principal = Format-DirectoryObject $o; PrincipalId = $o.id }) }
    if ($manager)             { Add-Row 'OwnersSponsors' ([ordered]@{ AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; Relationship = 'Manager'; Principal = Format-DirectoryObject $manager; PrincipalId = $manager.id }) }

    # Application permissions
    $appAssign = @(Invoke-Section "AppRoleAssignments:$kind" "$base/appRoleAssignments")
    $inhAssign = @(if ($kind -eq 'AgentIdentity') { Invoke-Section 'InheritedAppRoleAssignments' "$cast/inheritedAppRoleAssignments" })
    $agentRaw.AppRoleAssignments = $appAssign; $agentRaw.InheritedAppRoleAssignments = $inhAssign
    $appPerms = @(Add-AppPermissionRows $a $kind $appAssign 'Direct')
    $inhPerms = @(Add-AppPermissionRows $a $kind $inhAssign 'Inherited from blueprint')

    # Delegated permissions
    $grants = @(if ($pr.IsSp) { Invoke-Section "OAuth2Grants:$kind" "v1.0/oauth2PermissionGrants?`$filter=$([uri]::EscapeDataString("clientId eq '$id'"))" }
                else { Invoke-Section 'OAuth2Grants:AgentUser' "$base/oauth2PermissionGrants" })
    $inhGrants = @(if ($kind -eq 'AgentIdentity') { Invoke-Section 'InheritedOAuth2Grants' "$cast/inheritedOauth2PermissionGrants" })
    $agentRaw.OAuth2PermissionGrants = $grants; $agentRaw.InheritedOAuth2PermissionGrants = $inhGrants
    $delPerms = @(Add-DelegatedRows $a $kind $grants $(if ($pr.IsSp) { 'Direct' } else { 'Consented by agent user' }))
    $inhDel   = @(Add-DelegatedRows $a $kind $inhGrants 'Inherited from blueprint')

    # Who can use the agent (users/groups assigned to it)
    $assignedTo = @(if ($pr.IsSp) { Invoke-Section "AppRoleAssignedTo:$kind" "$base/appRoleAssignedTo" })
    $agentRaw.AppRoleAssignedTo = $assignedTo
    foreach ($t in $assignedTo) {
        Add-Row 'AssignedUsersGroups' ([ordered]@{
            AgentKind = $kind; AgentName = $a.displayName; AgentId = $id
            Principal = $t.principalDisplayName; PrincipalType = $t.principalType; PrincipalId = $t.principalId
            AppRoleId = $t.appRoleId; Assigned = Get-Prop $t 'createdDateTime'
        })
    }

    # Group memberships
    $groups = @(Invoke-Section "Groups:$kind" "$base/transitiveMemberOf?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole")
    $agentRaw.TransitiveMemberOf = $groups
    foreach ($g in $groups) {
        Add-Row 'Groups' ([ordered]@{
            AgentKind = $kind; AgentName = $a.displayName; AgentId = $id
            Group = Get-Prop $g 'displayName'; GroupId = $g.id
            Type = ((Get-Prop $g '@odata.type') -replace '#microsoft.graph.', '')
            SecurityEnabled = Get-Prop $g 'securityEnabled'; RoleAssignable = Get-Prop $g 'isAssignableToRole'
        })
    }

    # Directory roles (active + eligible), including roles inherited through role-assignable groups
    $principalIds = @($id) + @($groups | Where-Object { (Get-Prop $_ 'isAssignableToRole') } | ForEach-Object id)
    $activeRoles = @(foreach ($ra in $roleAssigns) {
        if ($ra.principalId -in $principalIds) {
            $rn = (Get-Prop $roleName[$ra.roleDefinitionId] 'displayName') ?? $ra.roleDefinitionId
            Add-Row 'DirectoryRoles' ([ordered]@{
                AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; Role = $rn; Assignment = 'Active'
                Scope = $ra.directoryScopeId; Via = if ($ra.principalId -eq $id) { 'Direct' } else { "Group $($ra.principalId)" }
                Privileged = Get-Prop $roleName[$ra.roleDefinitionId] 'isPrivileged'
            })
            $rn
        }
    })
    $eligRoles = @(foreach ($re in $roleEligible) {
        if ($re.principalId -in $principalIds) {
            $rn = (Get-Prop $roleName[$re.roleDefinitionId] 'displayName') ?? $re.roleDefinitionId
            Add-Row 'DirectoryRoles' ([ordered]@{
                AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; Role = $rn; Assignment = 'Eligible (PIM)'
                Scope = $re.directoryScopeId; Via = if ($re.principalId -eq $id) { 'Direct' } else { "Group $($re.principalId)" }
                Privileged = Get-Prop $roleName[$re.roleDefinitionId] 'isPrivileged'
            })
            $rn
        }
    })

    # Credentials (blueprints hold the credentials agent identities authenticate with)
    $credSources = @()
    if ($pr.IsSp) { $credSources += [pscustomobject]@{ Owner = 'Agent object'; Obj = $a; FicUri = $null } }
    if ($bp) { $credSources += [pscustomobject]@{ Owner = "Blueprint: $($bp.displayName)"; Obj = $bp; FicUri = "beta/applications/$($bp.id)/federatedIdentityCredentials" } }
    $expiries = @()
    foreach ($cs in $credSources) {
        foreach ($k in @(Get-Prop $cs.Obj 'keyCredentials')) {
            if (-not $k) { continue }
            if (Get-Prop $k 'endDateTime') { $expiries += [datetime](Get-Prop $k 'endDateTime') }
            Add-Row 'Credentials' ([ordered]@{ AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; HeldBy = $cs.Owner; Type = "Certificate ($($k.usage))"; Name = Get-Prop $k 'displayName'; Start = Get-Prop $k 'startDateTime'; Expires = Get-Prop $k 'endDateTime'; Expired = ((Get-Prop $k 'endDateTime') -and [datetime](Get-Prop $k 'endDateTime') -lt (Get-Date)); KeyId = $k.keyId })
        }
        foreach ($k in @(Get-Prop $cs.Obj 'passwordCredentials')) {
            if (-not $k) { continue }
            if (Get-Prop $k 'endDateTime') { $expiries += [datetime](Get-Prop $k 'endDateTime') }
            Add-Row 'Credentials' ([ordered]@{ AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; HeldBy = $cs.Owner; Type = 'Client secret'; Name = Get-Prop $k 'displayName'; Start = Get-Prop $k 'startDateTime'; Expires = Get-Prop $k 'endDateTime'; Expired = ((Get-Prop $k 'endDateTime') -and [datetime](Get-Prop $k 'endDateTime') -lt (Get-Date)); KeyId = $k.keyId })
        }
        if ($cs.FicUri) {
            if (-not $script:FicCache.ContainsKey($cs.FicUri)) { $script:FicCache[$cs.FicUri] = @(Invoke-Section 'FederatedCredentials' $cs.FicUri) }
            foreach ($f in $script:FicCache[$cs.FicUri]) {
                Add-Row 'Credentials' ([ordered]@{ AgentKind = $kind; AgentName = $a.displayName; AgentId = $id; HeldBy = $cs.Owner; Type = 'Federated credential'; Name = $f.name; Start = ''; Expires = ''; Expired = $false; KeyId = "$($f.issuer) | $($f.subject)" })
            }
        }
    }

    # Conditional Access
    $caMatches = @(Get-CaMatches -Kind $kind -Obj $a -BlueprintAppId $bpAppId -BlueprintObjId (Get-Prop $bp 'id'))
    foreach ($m in $caMatches) {
        $p = $m.Policy
        Add-Row 'ConditionalAccess' ([ordered]@{
            AgentKind = $kind; AgentName = $a.displayName; AgentId = $id
            Policy = $p.displayName; State = $p.state; MatchReason = $m.Reason; Excluded = $m.Excluded
            GrantControls = Join-Values (@(Get-Prop (Get-Prop $p 'grantControls') 'builtInControls'))
            AgentRiskLevels = Join-Values (@(Get-Prop (Get-Prop $p 'conditions') 'agentIdRiskLevels'))
            Applications = Join-Values (@(Get-Prop (Get-Prop (Get-Prop $p 'conditions') 'applications') 'includeApplications'))
            PolicyId = $p.id
        })
    }
    $caEffective = @($caMatches | Where-Object { -not $_.Excluded -and $_.Policy.state -eq 'enabled' })

    # Risk
    $risk = $riskById[$id]
    $dets = @(if ($detectionsById.ContainsKey($id)) { $detectionsById[$id] })
    if ($risk) {
        Add-Row 'Risk' ([ordered]@{
            AgentKind = $kind; AgentName = $a.displayName; AgentId = $id
            RiskLevel = $risk.riskLevel; RiskState = $risk.riskState; RiskDetail = $risk.riskDetail
            LastUpdated = Get-Prop $risk 'riskLastModifiedDateTime'; Platform = Get-Prop $risk 'agentPlatform'
            BlastRadiusRisk = (ConvertTo-JsonText (Get-Prop $risk 'blastRadiusRisk'))
            ExposureRisk = (ConvertTo-JsonText (Get-Prop $risk 'exposureRisk'))
            RuntimeRisk = (ConvertTo-JsonText (Get-Prop $risk 'runtimeRisk'))
        })
    }
    foreach ($d in $dets) {
        Add-Row 'RiskDetections' ([ordered]@{
            AgentKind = $kind; AgentName = $a.displayName; AgentId = $id
            Detected = $d.detectedDateTime; RiskEventType = $d.riskEventType; RiskLevel = $d.riskLevel; RiskState = $d.riskState
            Detail = $d.riskDetail; Source = Get-Prop $d 'source'; Evidence = Get-Prop $d 'riskEvidence'; DetectionId = $d.id
        })
    }

    # Last sign-in
    $lastSignIn = $null
    if ($pr.IsSp) {
        # Agent identities have no app registration of their own, so appId can be empty.
        $spAppId = Get-Prop $a 'appId'
        $act = if ($spAppId) { $signInActByAppId[$spAppId] } else { $null }
        if ($act) { $lastSignIn = Get-Prop (Get-Prop $act 'lastSignInActivity') 'lastSignInDateTime' }
    }
    else {
        $lastSignIn = Get-Prop (Get-Prop $a 'signInActivity') 'lastSignInDateTime'
    }

    # Catalog link
    $pkg = $packageByAgentId[$id] ?? $packageByAgentId[(Get-Prop $a 'appId') ?? '-']

    $allApp = @($appPerms + $inhPerms | Select-Object -Unique)
    $allDel = @($delPerms + $inhDel | Select-Object -Unique)
    Add-Row 'Agents' ([ordered]@{
        Kind                 = $kind
        DisplayName          = $a.displayName
        Id                   = $id
        AppId                = Get-Prop $a 'appId'
        UserPrincipalName    = Get-Prop $a 'userPrincipalName'
        Enabled              = Get-Prop $a 'accountEnabled'
        Created              = Get-Prop $a 'createdDateTime'
        Blueprint            = Get-Prop $bp 'displayName'
        BlueprintAppId       = $bpAppId
        Publisher            = (Get-Prop $a 'publisherName') ?? (Get-Prop $a 'appOwnerOrganizationId')
        Tags                 = Join-Values (Get-Prop $a 'tags')
        Owners               = Join-Values ($owners | ForEach-Object { Format-DirectoryObject $_ })
        Sponsors             = Join-Values ($sponsors | ForEach-Object { Format-DirectoryObject $_ })
        NoOwnerOrSponsor     = ($owners.Count + $sponsors.Count) -eq 0
        AppPermissionCount   = $allApp.Count
        AppPermissions       = Join-Values $allApp
        DelegatedPermCount   = $allDel.Count
        DelegatedPermissions = Join-Values $allDel
        HighPrivilegePerms   = Join-Values (@($allApp + $allDel) | Where-Object { Test-HighPrivilege $_ } | Select-Object -Unique)
        DirectoryRoles       = Join-Values ($activeRoles | Select-Object -Unique)
        EligibleRoles        = Join-Values ($eligRoles | Select-Object -Unique)
        GroupCount           = $groups.Count
        AssignedToCount      = $assignedTo.Count
        CAPoliciesApplied    = Join-Values ($caEffective | ForEach-Object { $_.Policy.displayName })
        CAPolicyCount        = $caEffective.Count
        RiskLevel            = Get-Prop $risk 'riskLevel'
        RiskState            = Get-Prop $risk 'riskState'
        RiskDetections       = @($dets).Count
        NextCredentialExpiry = if ($expiries) { ($expiries | Where-Object { $_ -gt (Get-Date) } | Sort-Object | Select-Object -First 1) } else { $null }
        LastSignIn           = $lastSignIn
        CatalogPackage       = Get-Prop $pkg 'displayName'
        CatalogBlocked       = Get-Prop $pkg 'isBlocked'
        Description          = Get-Prop $a 'description'
    })
    $script:Raw.PerAgent.Add($agentRaw)
}
Write-Progress -Activity 'Agents' -Completed

# Blueprints (permissions they hand down to their agent identities)
foreach ($b in $blueprints) {
    $bSponsors = @(Invoke-Section 'BlueprintSponsors' "beta/applications/$($b.id)/microsoft.graph.agentIdentityBlueprint/sponsors?`$select=id,displayName,userPrincipalName")
    $bOwners   = @(Invoke-Section 'BlueprintOwners' "beta/applications/$($b.id)/owners?`$select=id,displayName,userPrincipalName")
    $inheritable = @(Invoke-Section 'InheritablePermissions' "beta/applications/$($b.id)/microsoft.graph.agentIdentityBlueprint/inheritablePermissions")
    $script:Raw.PerBlueprint.Add([ordered]@{ Object = $b; Sponsors = $bSponsors; Owners = $bOwners; InheritablePermissions = $inheritable })
    foreach ($ip in $inheritable) {
        $scopes = Get-Prop $ip 'inheritableScopes'
        Add-Row 'BlueprintInheritable' ([ordered]@{
            Blueprint = $b.displayName; BlueprintAppId = $b.appId
            ResourceAppId = Get-Prop $ip 'resourceAppId'
            ScopeKind = ((Get-Prop $scopes '@odata.type') -replace '#microsoft.graph.', '')
            Scopes = Join-Values (Get-Prop $scopes 'scopes')
        })
    }
    $children = @($agentIdentities | Where-Object { (Get-Prop $_ 'agentIdentityBlueprintId') -eq $b.appId })
    Add-Row 'Blueprints' ([ordered]@{
        DisplayName = $b.displayName; AppId = $b.appId; ObjectId = $b.id
        Created = Get-Prop $b 'createdDateTime'; Publisher = Get-Prop $b 'publisherDomain'
        AgentIdentities = $children.Count
        Owners = Join-Values ($bOwners | ForEach-Object { Format-DirectoryObject $_ })
        Sponsors = Join-Values ($bSponsors | ForEach-Object { Format-DirectoryObject $_ })
        Secrets = @(Get-Prop $b 'passwordCredentials').Where({ $_ }).Count
        Certificates = @(Get-Prop $b 'keyCredentials').Where({ $_ }).Count
        RequiredResourceAccess = Join-Values (@(Get-Prop $b 'requiredResourceAccess') | ForEach-Object { "$($_.resourceAppId): $(@($_.resourceAccess).Count) perms" })
    })
}

# ---------------------------------------------------------------------------------------------
# 5. Optional sign-in logs
# ---------------------------------------------------------------------------------------------
if ($IncludeSignInLogs) {
    Write-Host "Reading agent sign-in logs for the last $SignInDays days..." -ForegroundColor Cyan
    $since = (Get-Date).ToUniversalTime().AddDays(-$SignInDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $hdr = @{ Prefer = 'include-unknown-enum-members' }
    $signIns = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($t in 'agenticAppInstance', 'agenticApp', 'agentIdentityBlueprintPrincipal', 'agentIDuser') {
        $filter = "createdDateTime ge $since and signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser' or t eq 'servicePrincipal') and agent/agentType eq '$t'"
        $uri = "beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($filter))&`$top=999"
        try { $rows = @(Get-GraphAll -Uri $uri -Headers $hdr -Max $MaxSignIns) }
        catch {
            # Fall back to a simpler filter (interactive sign-ins only) if the event-type filter is rejected.
            $filter = "createdDateTime ge $since and agent/agentType eq '$t'"
            $rows = @(Invoke-Section "SignIns:$t" "beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($filter))&`$top=999" -Headers $hdr -Max $MaxSignIns)
        }
        foreach ($r in $rows) {
            $sid = Get-Prop $r 'id'
            if ($sid -and $seen.Contains($sid)) { continue }
            if ($sid) { [void]$seen.Add($sid) }
            $signIns.Add($r)
        }
    }
    $script:Raw.SignIns = $signIns
    foreach ($s in $signIns) {
        $agentInfo = Get-Prop $s 'agent'
        $err = Get-Prop (Get-Prop $s 'status') 'errorCode'
        Add-Row 'SignIns' ([ordered]@{
            Time = $s.createdDateTime
            Agent = (Get-Prop $s 'servicePrincipalName') ?? (Get-Prop $s 'appDisplayName') ?? (Get-Prop $s 'userDisplayName')
            AgentType = Get-Prop $agentInfo 'agentType'; SubjectType = Get-Prop $agentInfo 'agentSubjectType'
            AgentObjectId = (Get-Prop $s 'servicePrincipalId') ?? (Get-Prop $s 'userId')
            ParentId = Get-Prop $agentInfo 'agentSubjectParentId'
            Resource = Get-Prop $s 'resourceDisplayName'
            Result = if ($err -eq 0) { 'Success' } else { "Failure $err" }
            FailureReason = Get-Prop (Get-Prop $s 'status') 'failureReason'
            ConditionalAccess = Get-Prop $s 'conditionalAccessStatus'
            IPAddress = Get-Prop $s 'ipAddress'
            Location = "$(Get-Prop (Get-Prop $s 'location') 'city'), $(Get-Prop (Get-Prop $s 'location') 'countryOrRegion')"
            EventTypes = Join-Values (Get-Prop $s 'signInEventTypes')
            CorrelationId = Get-Prop $s 'correlationId'
        })
    }
    # Per-agent summary, joined back onto the Agents tab
    $byAgent = @{}
    foreach ($row in @($script:Tables['SignIns'])) {
        if (-not $row) { continue }
        foreach ($k in @($row.AgentObjectId, $row.ParentId) | Where-Object { $_ } | Select-Object -Unique) {
            if (-not $byAgent.ContainsKey($k)) { $byAgent[$k] = [System.Collections.Generic.List[object]]::new() }
            $byAgent[$k].Add($row)
        }
    }
    foreach ($ag in @($script:Tables['Agents'])) {
        $rows = if ($byAgent.ContainsKey($ag.Id)) { $byAgent[$ag.Id] } else { @() }
        $ag | Add-Member -NotePropertyName "SignIns_${SignInDays}d" -NotePropertyValue @($rows).Count
        $ag | Add-Member -NotePropertyName 'SignInFailures' -NotePropertyValue @($rows | Where-Object Result -ne 'Success').Count
        $ag | Add-Member -NotePropertyName 'ResourcesAccessed' -NotePropertyValue (Join-Values ($rows | ForEach-Object Resource | Select-Object -Unique))
        $ag | Add-Member -NotePropertyName 'DistinctIPs' -NotePropertyValue @($rows | ForEach-Object IPAddress | Select-Object -Unique).Count
    }
}

# ---------------------------------------------------------------------------------------------
# 6. Summary + output
# ---------------------------------------------------------------------------------------------
foreach ($k in $script:ErrCount.Keys) {
    if ($script:ErrCount[$k] -gt 3) {
        Add-Row 'Errors' ([ordered]@{ Section = $k; Uri = ''; Error = "...and $($script:ErrCount[$k] - 3) more failures of this kind"; Time = (Get-Date).ToString('s') })
    }
}
$agentsTab = @($script:Tables['Agents'] | Where-Object { $_ })
$summary = [ordered]@{
    'Tenant'                               = $tenantLabel
    'Run by'                               = $ctx.Account ?? $ctx.AppName
    'Run at'                               = $script:Started.ToString('s')
    'Duration (s)'                         = [int]((Get-Date) - $script:Started).TotalSeconds
    'Agent identities'                     = $agentIdentities.Count
    'Agent identity blueprints'            = $blueprints.Count
    'Blueprint principals'                 = $blueprintPrincs.Count
    'Agent users'                          = $agentUsers.Count
    'Catalog packages (Agent 365)'         = $packageDetails.Count
    'Agent 365 registry entries'           = @($registrations).Count + @($legacyInstances).Count
    'Agents with no owner or sponsor'      = @($agentsTab | Where-Object NoOwnerOrSponsor).Count
    'Agents with high-privilege perms'     = @($agentsTab | Where-Object HighPrivilegePerms).Count
    'Agents with directory roles'          = @($agentsTab | Where-Object { $_.DirectoryRoles -or $_.EligibleRoles }).Count
    'Agents not covered by any CA policy'  = @($agentsTab | Where-Object { $_.CAPolicyCount -eq 0 }).Count
    'Agents with risk (not none)'          = @($agentsTab | Where-Object { $_.RiskLevel -and $_.RiskLevel -ne 'none' }).Count
    'Expired credentials'                  = @($script:Tables['Credentials'] | Where-Object { $_ -and $_.Expired } | ForEach-Object { "$($_.HeldBy)|$($_.KeyId)" } | Select-Object -Unique).Count
    'Blocked catalog packages'             = @($script:Tables['Catalog'] | Where-Object { $_ -and $_.IsBlocked }).Count
    'Failed Graph calls (see Errors)'      = ($script:ErrCount.Values | Measure-Object -Sum).Sum
}
$summaryRows = foreach ($k in $summary.Keys) { [pscustomobject]@{ Item = $k; Value = $summary[$k] } }

# Tab order
$order = 'Agents', 'AppPermissions', 'DelegatedPermissions', 'DirectoryRoles', 'ConditionalAccess', 'OwnersSponsors',
         'Groups', 'AssignedUsersGroups', 'Credentials', 'Risk', 'RiskDetections', 'Blueprints', 'BlueprintInheritable',
         'Catalog', 'CatalogElements', 'Registry', 'SignIns', 'Errors'

function ConvertTo-CellSafe {
    # Excel cells max out at 32,767 characters (full values stay in raw JSON). -IsoDates writes
    # dates as yyyy-MM-dd HH:mm:ss (UTC) so CSVs read the same in every locale.
    param($Rows, [switch]$IsoDates)
    foreach ($r in $Rows) {
        $o = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) {
            $v = $p.Value
            if ($IsoDates -and $v -is [datetime]) { $v = $v.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') }
            if ($v -is [string] -and $v.Length -gt $ExcelCellLimit) { $v = $v.Substring(0, $ExcelCellLimit) + '...[truncated - see raw JSON]' }
            $o[$p.Name] = $v
        }
        [pscustomobject]$o
    }
}

Write-Host 'Writing output...' -ForegroundColor Cyan
$summaryRows | Export-Csv (Join-Path $outDir 'csv/Summary.csv') -NoTypeInformation -Encoding utf8
foreach ($t in $order) {
    $rows = @($script:Tables[$t] | Where-Object { $_ })
    if ($rows.Count -gt 0) { ConvertTo-CellSafe $rows -IsoDates | Export-Csv (Join-Path $outDir "csv/$t.csv") -NoTypeInformation -Encoding utf8 }
}
foreach ($k in $script:Raw.Keys) {
    $file = Join-Path $outDir ("raw/{0}.json" -f ($k -replace '[^\w\.-]', '_'))
    $script:Raw[$k] | ConvertTo-Json -Depth 50 | Set-Content -Path $file -Encoding utf8
}

if ($haveExcel) {
    Import-Module ImportExcel
    $xlsx = Join-Path $outDir 'AgentSecurity.xlsx'
    $summaryRows | Export-Excel -Path $xlsx -WorksheetName 'Summary' -AutoSize -BoldTopRow
    foreach ($t in $order) {
        $rows = @($script:Tables[$t] | Where-Object { $_ })
        if ($rows.Count -eq 0) { continue }
        ConvertTo-CellSafe $rows | Export-Excel -Path $xlsx -WorksheetName $t -AutoSize `
            -FreezeTopRow -BoldTopRow -TableName "t_$t" -TableStyle Medium2
    }
    Write-Host "Excel workbook: $xlsx" -ForegroundColor Green
}

Write-Host ''
foreach ($row in $summaryRows) { Write-Host ('  {0,-40} {1}' -f $row.Item, $row.Value) }
Write-Host ''
Write-Host "Export complete: $outDir" -ForegroundColor Green
if (@($script:Tables['Errors'] | Where-Object { $_ }).Count -gt 0) {
    Write-Host 'Some endpoints were unavailable - see the Errors tab / csv\Errors.csv (usually licence, preview or permission).' -ForegroundColor Yellow
}
