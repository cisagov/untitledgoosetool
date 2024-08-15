<#
.SYNOPSIS
    Generate or Delete an Azure Application needed for goose usage
.DESCRIPTION
    Generate or Delete an Azure Application needed for goose usage
	Utilizes Microsoft Graph Powershell SDK, Azure SDK, and ExchangeManagementOnline
.EXAMPLE
	Write-Host "Creating a new Goose Application"
	PS > ./Create_SP.ps1 -AppName GooseApp -Create
.EXAMPLE
	Write-Host "Deleting a previously created Goose Application"
	PS > ./Create_SP.ps1 -AppName GooseApp -Delete
#>

[cmdletbinding()]Param(
	[string] $AppName # Display Name for the Application
	,[switch] $Create=$False # Boolean flag on whether to create. Will prompt if not defined. If both Create and Delete are defined then will prompt
	,[switch] $Delete=$False # Boolean flag on whether to delete. Will prompt if not defined. If both Create and Delete are defined then will prompt
	,[switch] $Force=$False # Boolean flag on whether to Force deletion or creation without prompting
	,[switch] $CloudShell=$False # Boolean if you are running in cloudshell or somewhere else you need to perform DeviceLogins
)

$script:UserNames = @()
$script:UserSecrets = @()
$script:OutputSubscriptionId = @()

$permissions = @{
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
		"Team.ReadBasic.All",
		"TeamsAppInstallation.ReadForUser.All",
		"User.Read.All",
		"UserAuthenticationMethod.Read.All"
	)
}

$app_roles = @(
	"Reader",
	"Storage Blob Data Reader",
	"Storage Queue Data Reader"
)

$user_roles = @(
	"Reader"
)

$exchange_roles = @(
	"View-Only Audit Logs",
	"View-Only Configuration",
	"View-Only Recipients",
	"User Options"
)

# Install the required modules if not already installed
Function Install-Modules {
	Write-Host "Starting package installation. This part can take up to 20 minutes"
	$GraphVersion = 2.15.0
	$AzVersion = 6.16.0
	If ((-not (Get-Module -Name Az.Resources -ListAvailable)) -or ($null -eq (Get-InstalledModule Az.Resources -RequiredVersion $AzVersion))) {
		Write-Host "Installing Az from default repository"
		Install-Module -Name Az.Resources -RequiredVersion $AzVersion -Force -AllowClobber
	}
	Write-Host "Importing Az"
	Import-Module -Name Az.Resources -RequiredVersion $AzVersion -Force
	If ((-not (Get-Module -Name Microsoft.Graph.Applications -ListAvailable)) -or ($null -eq (Get-InstalledModule Microsoft.Graph.Applications -RequiredVersion $GraphVersion))) {
		Write-Host "Installing Microsoft.Graph from default repository"
		Install-Module -Name Microsoft.Graph.Applications -RequiredVersion $GraphVersion -Force
	}
	Write-Host "Importing Microsoft.Graph"
	Import-Module -Name Microsoft.Graph.Applications -RequiredVersion $GraphVersion -Force
	If (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
        Write-Host "Required module, ExchangeOnlineManagement, is not installed on the system."
        Write-Host "Installing ExchangeOnlineManagement from default repository"
        Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.1.0  -Force -AllowClobber
    } ElseIf ($null -eq (Get-InstalledModule ExchangeOnlineManagement -RequiredVersion 3.1.0)) {
        Write-Host "Incorrect version of ExchangeOnlineManagement module is installed on the system."
        Write-Host "Installing ExchangeOnlineManagement from default repository"
        Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.1.0 -Force -AllowClobber
    }
    Write-Host "Importing ExchangeOnlineManagement"
    Import-Module -Name ExchangeOnlineManagement -RequiredVersion 3.1.0 -Force
}

Function Delete-GooseApp {
	param(
        [string] $AppName,
		[bool] $Force=$false
    )

	# Query Microsoft Graph to find the service principal by display name
	$ServicePrincipals = Get-MgServicePrincipal -Filter "displayName eq '$AppName'"
	
	
	if ($Force -eq $false) {
		$Delete = Read-Host "Are you sure you want to delete the application '$AppName'? Y/N"
		Switch ($Create){
			Y {$Delete = $true}
			N {$Delete = $false}
		}
		if ($Delete -eq $false) {
			Write-Host "Stopping Deletion"
			Return
		}
	}
	If ($ServicePrincipals) {
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
					Remove-AzRoleAssignment -ObjectId $ServicePrincipal.Id -Scope "/subscriptions/$SubscriptionId" -RoleDefinitionName $role
					Write-Host "Removed role $role from service principal."
				}
			}
			# Delete the service principal
			Remove-MgServicePrincipal -ServicePrincipalId $ServicePrincipal.Id
			Write-Host "Service Principal '$AppName' Deleted"
		}
	} Else {
		Write-Host "Service Principal with the name '$AppName' not found."
	}
	
	$Applications = Get-MgApplication -Filter "displayName eq '$AppName'"
	If ($Applications) {
		foreach ($Application in $Applications)
		{
			# Delete the Application
			Remove-MgApplication -ApplicationId $Application.Id
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

	# Define the required permissions

	$displayName = $AppName
	
	# Create a new Entra ID App Registration for the service principal
	$newAppRegistration = Get-MgApplication -Filter "displayName eq '$AppName'"
	if (-not $newAppRegistration) {
		Write-Host "Application '$AppName' does not exist. Creating now"
		New-MgApplication -DisplayName $displayName
	}
	$newAppRegistration = Get-MgApplication -Filter "displayName eq '$AppName'"

	# Create a service principal for the new app registration
	$ServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq '$displayName'"
	if (-not $ServicePrincipal) {
		Write-Host "Service Principal for '$AppName' does not exist. Creating now"
		New-MgServicePrincipal -AppId $newAppRegistration.AppId
	}
	$ServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq '$displayName'"

	# Get the object ID of the new service principal
	$ServicePrincipalId = $ServicePrincipal.Id

	# Iterate through the permissions and add them to the service principal
	foreach ($scope in $permissions.Keys) {
		Write-Host "Adding permissions for scope $scope"
		$ResourceApplication = Get-MgServicePrincipal -Filter "displayName eq '$scope'"
		foreach ($permission in $permissions[$scope]) {
			Write-Host "Assigning permission $permission from $scope to $AppName"
			
			$AppRoleId = ($ResourceApplication.appRoles | where value -eq $permission).Id
			$ResourceId = $ResourceApplication.Id
			
			$exists = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId | where appRoleId -eq $AppRoleId
			If ($exists) {
				Write-Host "Permission $permission already in service principal"
			}
			Else {
				$params = @{
					principalId = $ServicePrincipalId
					resourceId = $ResourceId
					appRoleId = $AppRoleId
				}
				New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -BodyParameter $params
				Write-Host "Permission $permission added to service principal"
			}	
		}
	}

	# Subscription IAM Roles
	Write-Host "Assigning Roles $app_roles"
	# Assign the roles to the service principal
	$Subscriptions = Get-AzSubscription
	foreach ($Subscription in $Subscriptions) {
		$SubscriptionId = ($Subscription | Select-Object -ExpandProperty Id)
		if ($SubscriptionsUsed -contains "all" -or $SubscriptionsUsed -contains $SubscriptionId) {
			foreach ($role in $app_roles) {
				if ($ServicePrincipal -ne $null) {
					New-AzRoleAssignment -ApplicationId $ServicePrincipal.AppId -Scope "/subscriptions/$SubscriptionId" -RoleDefinitionName $role
					Write-Host "Assigned role $role to service principal."
				}
			}
		}
	}

	$AppId = $newAppRegistration.AppId
	Return $AppId, $ServicePrincipalId
}
Function Delete-ExchangeServicePrincipal {
	param(
        [string] $AppName,
        [bool] $Force=$false
    )
	
	# Get the AppId
	$AppId = (Get-MgApplication -Filter "displayName eq '$AppName'").AppId

	# Get the Service Principal Id
	$ObjectId = (Get-MgServicePrincipal -Filter "displayName eq '$AppName'").Id

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
        [string] $AppName
    )
	# Create the Exchange Online group and add permissions needed
	$RoleGroup = $false
	$ServicePrincipal = $false
	$RoleGroupMember = $false
	
	# Get the AppId
	$AppId = (Get-MgApplication -Filter "displayName eq '$AppName'").AppId

	# Get the Service Principal Id
	$ObjectId = (Get-MgServicePrincipal -Filter "displayName eq '$AppName'").Id

	$RoleGroup = New-RoleGroup -Name $AppName -Roles $exchange_roles
	if ($RoleGroup) {
		Write-Host "Role Group '$AppName' created"
		# Associate the Exchange Online service principal with the new service principal
		$ServicePrincipal = New-ServicePrincipal -AppId $AppId -ObjectId $ObjectId -DisplayName $AppName
	}
	if ($ServicePrincipal) {
		Write-Host "Exchange Service Principal '$AppName' created"
		$RoleGroupMember = Add-RoleGroupMember -Identity $AppName -Member $ObjectId
	}
	if ($RoleGroupMember) {
		Write-Host "Role Group '$AppName' created"
	}	
}
Function Choose-Subscriptions {
	param(
		[bool] $Force=$false
	)
	$Subscriptions = Get-AzSubscription
	$SubscriptionIds = @()
	$AllSubscriptions = $true
	$SubscriptionsUsed = ""
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
		[string] $AppId,
		[string] $TenantId,
		[string] $ClientSecret,
		[string] $SubscriptionsUsed
	)
	$SubscriptionIds = $SubscriptionsUsed -join ","

	# Make sure this part contrasts
	Write-Host -ForegroundColor Green -BackgroundColor Black "Use the below output to generate the UGT configuration"
	Write-Host -ForegroundColor DarkGreen -BackgroundColor Black "goosey conf --config_tenant=$TenantId --config_subscriptionid=$SubscriptionIds --auth_appid=$AppId --auth_clientsecret=$ClientSecret"
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
Connect-MgGraph -Scope 'Application.ReadWrite.All,AppRoleAssignment.ReadWrite.All,Directory.ReadWrite.All' -NoWelcome
Connect-ExchangeOnline -ShowBanner:$false
if ($CloudShell) {
	Connect-AzAccount -UseDeviceAuthentication
}
else {
	Connect-AzAccount
}
If ($Create) {
	$SubscriptionsUsed = Choose-Subscriptions -Force $Force
	$AppId, $ObjectId = Create-GooseApp -AppName $AppName -SubscriptionsUsed $SubscriptionsUsed
	Create-ExchangeServicePrincipal -AppId $AppId -AppName $AppName -ObjectId $ObjectId

	# Generate secret and grab details needed for goosey conf
	$TenantId = (Get-AzTenant).Id
	$AppId = (Get-MgApplication -Filter "displayName eq '$AppName'").AppId	
	$ServicePrincipalId = (Get-MgServicePrincipal -Filter "displayName eq '$AppName'").Id
	$params = @{
		passwordCredential = @{
			displayName = "$AppName secret"
		}
	}
	$ClientSecret = (Add-MgServicePrincipalPassword -ServicePrincipalId $ServicePrincipalId -BodyParameter $params).SecretText
	
	Disconnect-AzAccount
	Disconnect-ExchangeOnline -Confirm:$false
	Disconnect-MgGraph
	Output-Results -TenantId $TenantId -AppId $AppId -SubscriptionsUsed $SubscriptionsUsed -ClientSecret $ClientSecret
}
Else {
	Delete-ExchangeServicePrincipal -AppName $AppName -Force $Force
	Delete-GooseApp -AppName $AppName -Force $Force
	Disconnect-AzAccount
	Disconnect-ExchangeOnline -Confirm:$false
	Disconnect-MgGraph
}
