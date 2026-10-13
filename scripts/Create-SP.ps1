<#
.SYNOPSIS
    Create or Delete an Azure Application needed for goose usage

.PARAMETER AppName
 The name of the application to create or delete

.PARAMETER Create
 Boolean flag on whether to create. Will prompt if not defined. If both Create and Delete are defined then will prompt

.PARAMETER Delete
 Boolean flag on whether to delete. Will prompt if not defined. If both Create and Delete are defined then will prompt

.PARAMETER Force
 Boolean flag on whether to Force deletion or creation without prompting for confirmation

.PARAMETER NoSubscriptions
 Boolean flag on whether to not apply subscription level roles

.PARAMETER GccHigh
 Boolean flag on whether to set it up for a Gcc High Environment

.DESCRIPTION
    Create or Delete an Azure Application needed for goose usage
 Utilizes Microsoft Graph Powershell SDK, Azure SDK, and ExchangeManagementOnline

.EXAMPLE
 Write-Host "Creating a new Goose Application"
 PS > ./Create_SP.ps1 -AppName GooseApp -Create

 This will create a new Entra Application and Service Principal with the name "GooseApp". It will also apply the necessary API permissions and subscription roles for Goose to function properly.

.EXAMPLE
 Write-Host "Deleting a previously created Goose Application"
 PS > ./Create_SP.ps1 -AppName GooseApp -Delete

 This will delete the Entra Application and Service Principal with the name "GooseApp". It will also remove any associated API permissions and subscription roles.
 The user will be prompted to confirm the deletion before it proceeds.

.EXAMPLE
 Write-Host "Force Deleting a previously created Goose Application without confirmation"
 PS > ./Create_SP.ps1 -AppName GooseApp -Delete -Force

 This will delete the Entra Application and Service Principal with the name "GooseApp" without prompting for confirmation. It will also remove any associated API permissions and subscription roles.

.NOTES
 Version: 3.0 20260528

#>

[cmdletbinding()]Param(
 [string] $AppName # Display Name for the Application
 ,[switch] $Create=$False # Boolean flag on whether to create. Will prompt if not defined. If both Create and Delete are defined then will prompt
 ,[switch] $Delete=$False # Boolean flag on whether to delete. Will prompt if not defined. If both Create and Delete are defined then will prompt
 ,[switch] $Force=$False # Boolean flag on whether to Force deletion or creation without prompting
 ,[switch] $NoSubscriptions=$False # Boolean flag on whether to not apply subscription level roles
 ,[switch] $GccHigh=$False # Boolean flag on whether to set it up for a Gcc High Environment
)

$script:UserNames = @()
$script:UserSecrets = @()
$script:OutputSubscriptionId = @()

$permissions = @{
 "Log Analytics API" = @(
  "Data.Read"
 )
 "Microsoft Threat Protection" = @(
  "AdvancedHunting.Read.All"
 )
 "WindowsDefenderATP" = @(
  "AdvancedQuery.Read.All",
  "Alert.Read.All",
  "Library.Manage",
  "Machine.Read.All",
  "SecurityRecommendation.Read.All",
  "Software.Read.All",
  "Ti.ReadWrite",
  "Vulnerability.Read.All"
 )
 "Office 365 Exchange Online" = @(
  "Exchange.ManageAsApp"
 )
 "Microsoft Graph" = @(
  "AdministrativeUnit.Read.All",
  "APIConnectors.Read.All",
  "AuditLog.Read.All",
  "ConsentRequest.Read.All",
  "Directory.Read.All",
  "Domain.Read.All",
  "ExternalUserProfile.Read.All",
  "Group.Read.All",
  "IdentityProvider.Read.All",
  "IdentityRiskEvent.Read.All",
  "IdentityRiskyServicePrincipal.Read.All",
  "IdentityRiskyUser.Read.All",
  "MailboxSettings.Read",
  "PendingExternalUserProfile.Read.All",
  "Policy.Read.All",
  "Policy.Read.PermissionGrant",
  "Reports.Read.All",
  "ResourceSpecificPermissionGrant.ReadForUser.All",
  "RoleManagement.Read.All",
  "SecurityActions.Read.All",
  "SecurityAlert.Read.All",
  "SecurityEvents.Read.All",
  "SecurityIncident.Read.All",
  "Team.ReadBasic.All",
  "TeamsAppInstallation.ReadForUser.All",
  "ThreatHunting.Read.All",
  "User.Read.All",
  "UserAuthenticationMethod.Read.All"
 )
 "Microsoft Cloud App Security" = @(
  "investigation.read"
 )
}

$app_roles = @(
 "Reader",
 "Storage Blob Data Reader",
 "Storage Queue Data Reader"
)

$exchange_roles = @(
 "View-Only Audit Logs",
 "View-Only Configuration",
 "View-Only Recipients",
 "User Options"
)

Function Install-RequiredModule {
 # Install (if missing) and import a single pinned module version. Unloads any other
 # version first so Import-Module -RequiredVersion can take effect.
 [CmdletBinding()]
 param(
  [Parameter(Mandatory)] [string] $ModuleName,
  [Parameter(Mandatory)] [string] $RequiredVersion
 )
 $pinned = [version] $RequiredVersion
 $installed = Get-Module -Name $ModuleName -ListAvailable |
  Where-Object { [version]$_.Version -eq $pinned } |
  Select-Object -First 1

 if (-not $installed) {
  Write-Host "Installing $ModuleName $RequiredVersion (pinned) from PSGallery for current user"
  try {
   Install-Module -Name $ModuleName -RequiredVersion $RequiredVersion -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
  }
  catch {
   throw "Failed to install required module '$ModuleName' $RequiredVersion from PSGallery. Error: $($_.Exception.Message). Resolve the issue (network, PSGallery trust, or permissions) and re-run the script."
  }
  $installed = Get-Module -Name $ModuleName -ListAvailable |
   Where-Object { [version]$_.Version -eq $pinned } |
   Select-Object -First 1
  if (-not $installed) {
   throw "Module '$ModuleName' $RequiredVersion is still not present after Install-Module reported success. Check your PSModulePath and try again."
  }
 }

 # If a different version is already loaded, unload it so we can import the pin.
 # Import-Module -RequiredVersion cannot swap out an already-loaded different version.
 $loaded = Get-Module -Name $ModuleName
 if ($loaded -and ($loaded.Version -ne $pinned)) {
  Write-Host "Unloading $ModuleName $($loaded.Version) to import pinned version $RequiredVersion"
  try {
   Remove-Module -Name $ModuleName -Force -ErrorAction Stop
   $loaded = $null
  }
  catch {
   throw "Module '$ModuleName' is already loaded at version $($loaded.Version) and could not be unloaded ($($_.Exception.Message)). Start a fresh PowerShell session and re-run the script."
  }
 }

 if (-not $loaded) {
  Write-Host "Importing $ModuleName $RequiredVersion"
  try {
   Import-Module -Name $ModuleName -RequiredVersion $RequiredVersion -Force -ErrorAction Stop
  }
  catch {
   throw "Failed to import '$ModuleName' $RequiredVersion. Error: $($_.Exception.Message). A conflicting version of '$ModuleName' (or one of its dependencies) may be loaded; start a fresh PowerShell session and re-run the script."
  }
 }
}

# Install the required modules if not already installed
Function Install-Modules {
 Write-Host "Starting module installation checks. This part can take a few minutes"

 # Unload any currently-loaded copies of these modules so a different version
 # already in memory can't override the pinned versions below.
 # This only affects the current session. Module files on disk are not removed.
 $unloadModules = @(
  'Az.Accounts',
  'Az.Resources',
  'Microsoft.Graph.Authentication',
  'ExchangeOnlineManagement'
 )
 foreach ($name in $unloadModules) {
  Get-Module -Name $name | Remove-Module -Force -ErrorAction SilentlyContinue
 }

 # Pinned module versions. Bumping these should be an explicit, reviewed change.
 # Set differently for PowerShell 7+ vs Windows PowerShell 5.1 where necessary based on compatibility testing.
 # Install-RequiredModule will install the pinned version if missing, and throw a clear error if it can't be installed or imported.
 $pinned = [ordered]@{
  'Az.Accounts'                    = if ($PSVersionTable.PSVersion.Major -ge 7) { '5.3.4'  } else { '5.3.1' }
  'Az.Resources'                   = if ($PSVersionTable.PSVersion.Major -ge 7) { '9.0.3'  } else { '9.0.0' }
  'Microsoft.Graph.Authentication' = '2.36.1'
  'ExchangeOnlineManagement'       = if ($PSVersionTable.PSVersion.Major -ge 7) { '3.9.2'  } else { '3.7.1' }
 }
 foreach ($name in $pinned.Keys) {
  Install-RequiredModule -ModuleName $name -RequiredVersion $pinned[$name]
 }
}

# --- Microsoft Graph REST helpers (replaced Microsoft.Graph.Applications cmdlets) ---
# Default Invoke-MgGraphRequest to PSObject output so dot-access (.id / .appId / .value) works.
$PSDefaultParameterValues['Invoke-MgGraphRequest:OutputType'] = 'PSObject'

Function Write-Section {
 # Print a labeled section divider in cyan.
 param([Parameter(Mandatory)][string] $Title)
 $pad = [Math]::Max(3, 55 - $Title.Length)
 $line = ('-' * 3) + ' ' + $Title + ' ' + ('-' * $pad)
 Write-Host ""
 Write-Host $line -ForegroundColor Cyan
}

Function Write-KeyValue {
 # Print a two-column key/value line for the section panels.
 param(
  [Parameter(Mandatory)][string] $Key,
  [Parameter(Mandatory)][AllowEmptyString()][string] $Value
 )
 # Format string: 18-char left-aligned key, then a space, then the value.
 # {0,-18} = arg 0 padded to 18 chars, left-aligned (negative width = left).
 Write-Host ("  {0,-18} {1}" -f $Key, $Value)
}

Function Get-GraphApplicationByName {
 # Look up an Entra application by display name. Returns the value array from Graph.
 param([Parameter(Mandatory)] [string] $DisplayName)
 $escaped = $DisplayName.Replace("'", "''")
 (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications?`$filter=displayName eq '$escaped'").value
}

Function Get-GraphServicePrincipalByName {
 # Look up a service principal by display name. Returns the value array from Graph.
 param([Parameter(Mandatory)] [string] $DisplayName)
 $escaped = $DisplayName.Replace("'", "''")
 (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/servicePrincipals?`$filter=displayName eq '$escaped'").value
}

Function Delete-GooseApp {
 param(
        [string] $AppName,
  [bool] $Force=$false
    )

 # Query Microsoft Graph to find the service principal by display name
 $ServicePrincipals = @(Get-GraphServicePrincipalByName -DisplayName $AppName)

 if ($Force -eq $false) {
  $Confirm = Read-Host "Are you sure you want to delete the application '$AppName'? Y/N"
  $Delete = $false
  Switch ($Confirm){
   Y {$Delete = $true}
   N {$Delete = $false}
  }
  if ($Delete -eq $false) {
   Write-Host "Stopping Deletion"
   Return
  }
 }
 If ($ServicePrincipals.Count -gt 0) {
  foreach ($ServicePrincipal in $ServicePrincipals)
  {
   # Role assignments need to be removed. Otherwise will leave empty role assignments on the subscriptions
   Write-Host "Removing Roles $app_roles"
   $Subscriptions = Get-AzSubscription
   foreach ($Subscription in $Subscriptions) {
    $SubscriptionName = ($Subscription | Select-Object -ExpandProperty Name)
    Write-Host "Removing Roles from Subscription '$SubscriptionName'"
    foreach ($role in $app_roles) {
     $SubscriptionId = ($Subscription | Select-Object -ExpandProperty Id)
     Remove-AzRoleAssignment -ObjectId $ServicePrincipal.id -Scope "/subscriptions/$SubscriptionId" -RoleDefinitionName $role
     Write-Host "Removed role $role from service principal."
    }
   }
   # Delete the service principal
   Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/servicePrincipals/$($ServicePrincipal.id)" | Out-Null
   Write-Host "Service Principal '$AppName' Deleted"
  }
 } Else {
  Write-Host "Service Principal with the name '$AppName' not found."
 }

 $Applications = @(Get-GraphApplicationByName -DisplayName $AppName)
 If ($Applications.Count -gt 0) {
  foreach ($Application in $Applications)
  {
   # Delete the Application
   Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/applications/$($Application.id)" | Out-Null
   Write-Host "Application '$AppName' Deleted"
  }
 } Else {
  Write-Host "Application with the name '$AppName' not found."
 }
}

Function Create-GooseApp{
 param(
        [string] $AppName,
  [array] $SubscriptionsUsed
    )

 $displayName = $AppName

 # --- App Registration ---
 Write-Section 'App Registration'
 # Reuse an existing app with this display name if one is found.
 $newAppRegistration = Get-GraphApplicationByName -DisplayName $AppName
 if ($newAppRegistration -is [array]) { $newAppRegistration = $newAppRegistration[0] }
 $appCreated = $false
 if (-not $newAppRegistration) {
  $newAppRegistration = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications" -Body @{ displayName = $displayName }
  $appCreated = $true
 }
 $appStatus = if ($appCreated) { 'created' } else { 'reused existing' }
 Write-KeyValue 'Application' ("{0}  ({1})" -f $AppName, $appStatus)
 Write-KeyValue 'AppId'       $newAppRegistration.appId
 Write-KeyValue 'Object Id'   $newAppRegistration.id

 # Build requiredResourceAccess (Configured permissions in the manifest)
 $requiredResourceAccess = @()
 $manifestWarnings = @()
 foreach ($scope in $permissions.Keys) {
  $ResourceApplication = Get-GraphServicePrincipalByName -DisplayName $scope
  if ($ResourceApplication -is [array]) { $ResourceApplication = $ResourceApplication[0] }
  if (-not $ResourceApplication) {
   $manifestWarnings += "Could not find resource application '$scope'"
   continue
  }
  $resourceAccess = @()
  foreach ($permission in $permissions[$scope]) {
   $AppRole = $ResourceApplication.appRoles | Where-Object { $_.value -eq $permission }
   if ($AppRole) { $resourceAccess += @{ id = $AppRole.id; type = "Role" } }
   else { $manifestWarnings += "Could not find app role '$permission' on '$scope'" }
  }
  if ($resourceAccess.Count -gt 0) {
   $requiredResourceAccess += @{ resourceAppId = $ResourceApplication.appId; resourceAccess = $resourceAccess }
  }
 }
 Invoke-MgGraphRequest -Method PATCH -Uri "/v1.0/applications/$($newAppRegistration.id)" -Body @{ requiredResourceAccess = $requiredResourceAccess } | Out-Null
 Write-KeyValue 'Manifest' 'Configured permissions updated'

 # Service principal. Reuse if one already exists for this app.
 $ServicePrincipal = Get-GraphServicePrincipalByName -DisplayName $displayName
 if ($ServicePrincipal -is [array]) { $ServicePrincipal = $ServicePrincipal[0] }
 $spCreated = $false
 if (-not $ServicePrincipal) {
  $ServicePrincipal = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/servicePrincipals" -Body @{ appId = $newAppRegistration.appId }
  $spCreated = $true
 }
 $ServicePrincipalId = $ServicePrincipal.id
 $spStatus = if ($spCreated) { 'created' } else { 'reused existing' }
 Write-KeyValue 'Service Principal' ("{0}  ({1})" -f $ServicePrincipalId, $spStatus)
 foreach ($w in $manifestWarnings) { Write-Host "  ! $w" -ForegroundColor Yellow }

 # --- API Permissions ---
 Write-Section 'API Permissions'
 # Grant each app role; skip ones already assigned. Tally per-resource counts for the table below.
 $permRows = @()
 foreach ($scope in $permissions.Keys) {
  $ResourceApplication = Get-GraphServicePrincipalByName -DisplayName $scope
  if ($ResourceApplication -is [array]) { $ResourceApplication = $ResourceApplication[0] }
  if (-not $ResourceApplication) {
   $permRows += [pscustomobject]@{ Resource = $scope; Granted = 0; Skipped = 0; Failed = $permissions[$scope].Count }
   continue
  }
  $existingAssignments = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments").value
  $granted = 0; $skipped = 0; $failed = 0
  foreach ($permission in $permissions[$scope]) {
   $AppRoleId = ($ResourceApplication.appRoles | Where-Object { $_.value -eq $permission }).id
   if (-not $AppRoleId) { $failed++; continue }
   $exists = $existingAssignments | Where-Object { $_.appRoleId -eq $AppRoleId }
   if ($exists) { $skipped++; continue }
   try {
    $body = @{ principalId = $ServicePrincipalId; resourceId = $ResourceApplication.id; appRoleId = $AppRoleId }
    Invoke-MgGraphRequest -Method POST -Uri "/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments" -Body $body | Out-Null
    $granted++
   } catch { $failed++ }
  }
  $permRows += [pscustomobject]@{ Resource = $scope; Granted = $granted; Skipped = $skipped; Failed = $failed }
 }
 # Table layout for the API Permissions summary.
 # {0,-34} = Resource column, 34 chars wide, left-aligned.
 # {1,7} {2,7} {3,6} = Granted/Skipped/Failed columns, right-aligned numeric widths.
 $fmt = "  {0,-34}  {1,7}   {2,7}   {3,6}"
 # Header row, then a divider made of dashes sized to each column.
 Write-Host ($fmt -f 'Resource', 'Granted', 'Skipped', 'Failed')
 Write-Host ($fmt -f ('-' * 34), ('-' * 7), ('-' * 7), ('-' * 6))
 $totG=0; $totS=0; $totF=0
 foreach ($r in $permRows) {
  $color = if ($r.Failed -gt 0) { 'Red' } elseif ($r.Granted -eq 0 -and $r.Skipped -gt 0) { 'DarkGray' } else { 'Green' }
  Write-Host ($fmt -f $r.Resource, $r.Granted, $r.Skipped, $r.Failed) -ForegroundColor $color
  $totG += $r.Granted; $totS += $r.Skipped; $totF += $r.Failed
 }
 # Footer divider and TOTAL row using the same format string.
 Write-Host ($fmt -f ('-' * 34), ('-' * 7), ('-' * 7), ('-' * 6))
 Write-Host ($fmt -f 'TOTAL', $totG, $totS, $totF)

 # --- Subscription Roles ---
 Write-Section 'Subscription Roles'
 # Assign $app_roles on each selected subscription. 'Already exists' counts as success.
 $subRows = @()
 $Subscriptions = Get-AzSubscription
 foreach ($Subscription in $Subscriptions) {
  $SubscriptionId = $Subscription.Id
  $SubscriptionName = $Subscription.Name
  if ($SubscriptionsUsed -contains "all" -or $SubscriptionsUsed -contains $SubscriptionId) {
   $assigned = 0
   foreach ($role in $app_roles) {
    if ($null -ne $ServicePrincipal) {
     try {
      New-AzRoleAssignment -ApplicationId $ServicePrincipal.appId -Scope "/subscriptions/$SubscriptionId" -RoleDefinitionName $role -ErrorAction Stop | Out-Null
      $assigned++
     } catch {
      if ($_.Exception.Message -match 'already exists|RoleAssignmentExists') { $assigned++ }
     }
    }
   }
   $subRows += [pscustomobject]@{ Subscription = $SubscriptionName; Assigned = ("{0} of {1}" -f $assigned, $app_roles.Count) }
  }
 }
 if ($subRows.Count -eq 0) {
  Write-Host '  (no subscriptions selected)' -ForegroundColor DarkGray
 } else {
  # Table layout for the Subscription Roles summary.
  # {0,-42} = Subscription column, 42 chars wide, left-aligned.
  # {1,14}  = 'Roles assigned' column, 14 chars wide, right-aligned.
  $sfmt = "  {0,-42}  {1,14}"
  Write-Host ($sfmt -f 'Subscription', 'Roles assigned')
  Write-Host ($sfmt -f ('-' * 42), ('-' * 14))
  foreach ($r in $subRows) { Write-Host ($sfmt -f $r.Subscription, $r.Assigned) -ForegroundColor Green }
  Write-Host ("  Roles: {0}" -f ($app_roles -join ', ')) -ForegroundColor DarkGray
 }

 $AppId = $newAppRegistration.appId
 Return $AppId, $ServicePrincipalId
}
Function Delete-ExchangeServicePrincipal {
 param(
        [string] $AppName,
        [bool] $Force=$false
    )

 # Get the AppId
 $App = Get-GraphApplicationByName -DisplayName $AppName
 if ($App -is [array]) { $App = $App[0] }
 $AppId = $App.appId

 # Get the Service Principal Id
 $Sp = Get-GraphServicePrincipalByName -DisplayName $AppName
 if ($Sp -is [array]) { $Sp = $Sp[0] }
 $ObjectId = $Sp.id

 # Remove the role group and service principal created for goose
 if ($Force) {
  Remove-RoleGroupMember -Identity "$AppName" -Member $ObjectId -Confirm:$false
  Remove-ServicePrincipal -Identity $ObjectId -Confirm:$false
  Remove-RoleGroup "$AppName" -Confirm:$false
 }
 Else {
  Remove-RoleGroupMember -Identity "$AppName" -Member $ObjectId
  Remove-ServicePrincipal -Identity $ObjectId
  Remove-RoleGroup "$AppName"
 }
}

Function Create-ExchangeServicePrincipal {
 param(
        [string] $AppName,
  [guid] $AppId,
  [guid] $ObjectId
    )
 Write-Section 'Exchange Online'
 # Create or reuse the Exchange role group, link the service principal,
 # and add the SP as a role group member.

 $RoleGroup = Get-RoleGroup $AppName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
 $rgCreated = $false
 if (-not $RoleGroup) {
  $RoleGroup = New-RoleGroup -Name $AppName -Roles $exchange_roles -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
  $rgCreated = $true
 }
 if (-not $RoleGroup) {
  Write-Host ("  !!  Role group '{0}' could not be created" -f $AppName) -ForegroundColor Red
  return
 }
 $rgStatus = if ($rgCreated) { 'created' } else { 'reused existing' }
 Write-Host ("  OK  Role group '{0}'  ({1})" -f $AppName, $rgStatus) -ForegroundColor Green

 $ServicePrincipal = New-ServicePrincipal -AppId $AppId -ObjectId $ObjectId -DisplayName $AppName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
 if ($ServicePrincipal) {
  Write-Host '  OK  Service principal linked' -ForegroundColor Green
  $RoleGroupMember = Add-RoleGroupMember -Identity $AppName -Member $ObjectId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
  if ($RoleGroupMember) { Write-Host '  OK  Role group membership added' -ForegroundColor Green }
 }
}
Function Choose-Subscriptions {
 param(
  [bool] $Force=$false
  ,[bool] $NoSubscriptions=$false
 )
 $Subscriptions = Get-AzSubscription
 $SubscriptionIds = @()
 $AllSubscriptions = $true
 $SubscriptionsUsed = ""
 if ($NoSubscriptions) {
  return $SubscriptionsUsed
 }
 foreach ($Subscription in $Subscriptions) {
  $SubscriptionName = ($Subscription | Select-Object -ExpandProperty Name)
  If ($Force -eq $true) {
   $CreateRoles = "Y"
  }
  Else {
   $CreateRoles = Read-Host "Assign user/app roles for subscription '$SubscriptionName'? Y/N"
  }
  Switch ($CreateRoles){
   Y {$CreateRoles = $true}
   N {$CreateRoles = $false}
  }
  if ($CreateRoles) {
   $SubscriptionsUsed += ($Subscription | Select-Object -ExpandProperty Id)
  }
  else {
   $AllSubscriptions = $false
  }
 }
 if ($AllSubscriptions) {
  $SubscriptionsUsed = @("all")
 }
 else {
  $SubscriptionsUsed = $SubscriptionIds
 }
 return $SubscriptionsUsed
}

Function Output-Results {
 param(
  [string]   $AppId,
  [string]   $TenantId,
  [string]   $ClientSecret,
  [datetime] $ClientSecretExpires,
  [string]   $SubscriptionsUsed
 )
 $SubscriptionIds = $SubscriptionsUsed -join ","

 Write-Section 'Setup Complete - UGT Configuration'
 Write-Host '  Run the following command to configure goosey:' -ForegroundColor Green
 Write-Host ""
 Write-Host "  goosey conf --config_tenant=$TenantId --config_subscriptionid=$SubscriptionIds --auth_appid=$AppId" -ForegroundColor Yellow
 Write-Host ""
 Write-Host '  Enter the following client secret when prompted:' -ForegroundColor Green
 Write-Host ""
 Write-Host "  Client Secret: $ClientSecret" -ForegroundColor Yellow
 # Show the secret's expiration in the user's local time.
 Write-Host "  Expires on: $($ClientSecretExpires.ToLocalTime().ToLongDateString())" -ForegroundColor DarkGray
 Write-Host ""
}

if (-not $AppName) {
    $AppName = Read-Host "Enter the application name"
}
if (($Create -eq $false -and $Delete -eq $false) -or ($Create -eq $true -and $Delete -eq $true)) {
 $Create_read = Read-Host 'Do you want to create or delete a goose app and users? C/D'
 Switch ($Create_read){
  C {$Create = $true}
  D {$Create = $false}
 }
}

Install-Modules

$AzEnvironment = "AzureCloud"
$GraphEnvironment = "Global"
$ExchangeEnvironment = "O365Default"
if ($GccHigh) {
 $AzEnvironment = "AzureUSGovernment"
 $GraphEnvironment = "USGov"
 $ExchangeEnvironment = "O365USGovGCCHigh"
}

Connect-AzAccount -WarningVariable ConnectAzOutput -Environment $AzEnvironment
Write-Host $ConnectAzOutput
if ($ConnectAzOutput -Match "Interactive authentication is not supported") {
 Write-Host "Interactive Authentication Failed. Attempting Device Authentication"
 Connect-AzAccount -UseDeviceAuthentication -Environment $AzEnvironment
}
Connect-MgGraph -Scope 'Application.ReadWrite.All,AppRoleAssignment.ReadWrite.All,Directory.ReadWrite.All' -NoWelcome -Environment $GraphEnvironment
Connect-ExchangeOnline -ShowBanner:$false -ExchangeEnvironmentName $ExchangeEnvironment
If ($Create) {
 $SubscriptionsUsed = Choose-Subscriptions -Force $Force -NoSubscriptions $NoSubscriptions
 $AppId, $ObjectId = Create-GooseApp -AppName $AppName -SubscriptionsUsed $SubscriptionsUsed
 Create-ExchangeServicePrincipal -AppId $AppId -AppName $AppName -ObjectId $ObjectId

 # Generate secret (180 day expiration) and grab details needed for goosey conf
 $TenantId = (Get-AzTenant).Id
 $App = Get-GraphApplicationByName -DisplayName $AppName
 if ($App -is [array]) { $App = $App[0] }
 $AppId = $App.appId
 $AppObjectId = $App.id
 $params = @{
  passwordCredential = @{
   displayName = "$AppName secret"
   endDateTime = (Get-Date).AddDays(180).ToUniversalTime().ToString("o")
  }
 }
 # addPassword must target the application object, not the service principal.
 # Read the secret value and expiration from the response so we don't recompute the date later.
 $pwResp = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications/$AppObjectId/addPassword" -Body $params
 $ClientSecret = $pwResp.secretText
 $ClientSecretExpires = [datetime]$pwResp.endDateTime

 #Disconnect-AzAccount | Out-Null
 #Disconnect-ExchangeOnline -Confirm:$false | Out-Null
 #Disconnect-MgGraph | Out-Null
 Output-Results -TenantId $TenantId -AppId $AppId -SubscriptionsUsed $SubscriptionsUsed `
  -ClientSecret $ClientSecret -ClientSecretExpires $ClientSecretExpires
}
Else {
 Delete-ExchangeServicePrincipal -AppName $AppName -Force $Force
 Delete-GooseApp -AppName $AppName -Force $Force
 #Disconnect-AzAccount | Out-Null
 #Disconnect-ExchangeOnline -Confirm:$false | Out-Null
 #Disconnect-MgGraph | Out-Null
}
 