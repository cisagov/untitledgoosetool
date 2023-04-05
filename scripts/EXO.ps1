[cmdletbinding()]Param(
    [Parameter()]
    [string] $ExchangeEnvironment,
    [Parameter()]
    [string] $ExportDir,
    [Parameter()]
    [string] $UserId,
    [Parameter()]
    [string] $ReportDir,    
    [Parameter()]
    [string] $OSEnvironment = [System.Environment]::OSVersion.Platform
)
Function Import-PSModules {

    [cmdletbinding()]Param(
        [Parameter(Mandatory=$true)]
        [string] $ExportDir
        )

    If ($null -eq (Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue)){
        Write-Host "Required module, ExchangeOnlineManagement, is not installed on the system."
        Write-Host "Installing ExchangeOnlineManagement from default repository"
        Install-Module -Name ExchangeOnlineManagement -MinimumVersion 3.1.0 -Force -AllowClobber
        Write-Host "Importing ExchangeOnlineManagement"
        Import-Module -Name ExchangeOnlineManagement -MinimumVersion 3.1.0 -Force
    } ElseIf ($null -eq (Get-InstalledModule ExchangeOnlineManagement -MinimumVersion 2.0.5)) {
        Write-Host "Outdated ExchangeOnlineManagement module is installed on the system."
        Write-Host "Installing ExchangeOnlineManagement from default repository"
        Install-Module -Name ExchangeOnlineManagement -MinimumVersion 3.1.0 -Force -AllowClobber
        Write-Host "Importing ExchangeOnlineManagement"
        Import-Module -Name ExchangeOnlineManagement -MinimumVersion 3.1.0 -Force
    } Else {
        Write-Host "Importing ExchangeOnlineManagement"
        Import-Module -Name ExchangeOnlineManagement -MinimumVersion 3.1.0 -Force
    }

    #If you want to change the default export directory, please change the $ExportDir value.
    #Otherwise, the default export is the user's home directory, Desktop folder, and ExportDir folder.
    If (!(Test-Path $ExportDir)){
        New-Item -Path $ExportDir -ItemType "Directory" -Force
    }
}

Function Get-EXOEnvironment {

    [cmdletbinding()]Param(
        [Parameter()]
        [string] $ExchangeEnvironment
    )

    $ExchangeEnvironments = [System.Enum]::GetNames([Microsoft.Exchange.Management.RestApiClient.ExchangeEnvironment])
    While ($ExchangeEnvironments -cnotcontains $ExchangeEnvironment -or [string]::IsNullOrWhiteSpace($ExchangeEnvironment) -and $ExchangeEnvironment -ne "None") {
        Write-Host 'Exchange Environments'
        Write-Host '---------------------'
        $ExchangeEnvironments | ForEach-Object { Write-Host $_ }
        Write-Host 'None'
        $ExchangeEnvironment = Read-Host 'Choose your Exchange Environment [O365Default]'
        If ([string]::IsNullOrWhiteSpace($ExchangeEnvironment)) { $ExchangeEnvironment = 'O365Default' }
    }

    Return ($ExchangeEnvironment)
}

Function Get-EXORoleGrpInformation() {

    Write-Host "Initializing Exchange role groups export..."

    If ((Test-Path -Path $ExportDir\EXO_RoleGroups_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_RoleGroupMembers_PowerShell.json) -and (-not (Test-Path -Path $ExportDir\.EXO_RoleGroupMembers_savestate))) {
        Write-Host "Exchange role group information already exported. Skipping this call."
    } 
    
    If (-Not (Test-Path -Path $ExportDir\EXO_RoleGroups_PowerShell.json)) {
        Write-Host "Exchange role groups not found. Exporting Exchange role groups..."

        [array]$RoleGrps = Get-RoleGroup -ResultSize Unlimited -ShowPartnerLinked

        $RoleGrps | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_RoleGroups_PowerShell.json -Encoding Ascii

        Write-Host "Exchange role groups export completed."
    }
    
    If (-Not (Test-Path -Path $ExportDir\EXO_RoleGroupMembers_PowerShell.json)) {
        Write-Host "Exchange role group members not found. Exporting Exchange role group members..."

        If (Test-Path -Path $ExportDir\EXO_RoleGroups_PowerShell.json) {
            $RoleGrps = Get-Content $ExportDir\EXO_RoleGroups_PowerShell.json | ConvertFrom-Json
            $RoleGrps = $RoleGrps.DisplayName

            If (-not (Test-Path -Path $ExportDir\.EXO_RoleGroupMembers_savestate)) {
                ForEach ($grp in $RoleGrps) {
                    $RoleGrpMembers = Get-RoleGroupMember -Identity $grp -ResultSize Unlimited
                    $RoleGrpMembers | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_RoleGroupMembers_PowerShell.json -Encoding Ascii -Append
                    $grp | Out-File $ExportDir\.EXO_RoleGroupMembers_savestate -Encoding Ascii
                }
            } Else {
                $EXO_RGM_save = Get-Content $ExportDir\.EXO_RoleGroupMembers_savestate -Encoding Ascii
                $index = $RoleGrps.IndexOf($EXO_RGM_save)
                Write-Host "Exchange role group members save state found. Picking up from last entry..."
                For ($i=$index; $i -le $RoleGrps.Length; $i++) {
                    $grp = $RoleGrps[$i]
                    $RoleGrpMembers = Get-RoleGroupMember -Identity $grp -ResultSize Unlimited
                    $RoleGrpMembers | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_RoleGroupMembers_PowerShell.json -Encoding Ascii -Append
                    $grp | Out-File $ExportDir\.EXO_RoleGroupMembers_savestate -Encoding Ascii
                }
            }

            If (Test-Path -Path $ExportDir\.EXO_RoleGroupMembers_savestate) {
                $EXO_RGM_save_final = Get-Content $ExportDir\.EXO_RoleGroupMembers_savestate -Encoding Ascii
                If ($EXO_RGM_save_final -eq $RoleGrps[-1]) {
                    Write-Host "Exchange role group members completed. Removing save state file."
                    Remove-Item -Path $ExportDir\.EXO_RoleGroupMembers_savestate -Force
                }
                If ($RoleGrps.count -eq 1) {
                    If ($EXO_RGM_save_final -eq $RoleGrps) {
                        Write-Host "Exchange role group members completed. Removing save state file."
                        Remove-Item -Path $ExportDir\.EXO_RoleGroupMembers_savestate -Force
                    }
                }
            }

        }

        Write-Host "Exchange role group members export completed."
    }

    Write-Host "Completed exporting Exchange role group information."
}

Function Get-EDiscoveryInformation() {

    Write-Host "Initializing E-Discovery export..."

    If ((Test-Path -Path $ExportDir\EXO_EDiscovery_Roles_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_EDiscovery_RoleCmdlets_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_EDiscovery_RoleAssignments_PowerShell.json) -and (-not (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate)) -and (-not (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate))) {
        Write-Host "E-Discovery information already exported. Skipping this call."
    }
    
    If (-not (Test-Path -Path $ExportDir\EXO_EDiscovery_Roles_PowerShell.json)) {

        $EDiscoveryCmdlets = "New-MailboxSearch", "Search-Mailbox"

        ForEach ($cmdlet in $EDiscoveryCmdlets) {
            [array]$Roles = $Roles + (Get-ManagementRoleEntry ("*\" + $cmdlet))
        }
    
        $Roles = $Roles | Sort-Object -Unique -Property Role | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_EDiscovery_Roles_PowerShell.json  -Encoding Ascii

        $Roles = Get-Content $ExportDir\EXO_EDiscovery_Roles_PowerShell.json | ConvertFrom-Json
        $Roles = $Roles.role
    }

    If ((-not (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate)) -and (-not (Test-Path -Path $ExportDir\EXO_EDiscovery_RoleCmdlets_PowerShell.json))) {
        Write-Host "Exchange E-Discovery Role cmdlets not found. Exporting E-Discovery Role cmdlets..."
        ForEach ($Role in $Roles) {
            $RoleCmdlets = $RoleCmdlets + (Get-ManagementRoleEntry ($Role + "\*"))
            $RoleCmdlets | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_EDiscovery_RoleCmdlets_PowerShell.json -Encoding Ascii -Append
            $Role | Out-File $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate -Encoding Ascii
        }
    } ElseIf (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate) {
        $EXO_ED_RC_save = Get-Content $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate -Encoding Ascii
        $index = $Roles.IndexOf($EXO_ED_RC_save)
        Write-Host "Exchange E-Discovery Role cmdlets save state found. Picking up from last entry..."
        For ($i=$index; $i -le $Roles.Length; $i++) {
            $Role = $Roles[$i]
            $RoleCmdlets = $RoleCmdlets + (Get-ManagementRoleEntry ($Role + "\*"))
            $RoleCmdlets | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_EDiscovery_RoleCmdlets_PowerShell.json -Encoding Ascii -Append
            $Role | Out-File $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate -Encoding Ascii
        }
    }

    If (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate) {
        $EXO_ED_RC_save_final = Get-Content $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate -Encoding Ascii
        If ($EXO_ED_RC_save_final -eq $Roles[-1]) {
            Write-Host "Exchange E-Discovery Role cmdlets export completed. Removing save state file."
            Remove-Item -Path $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate -Force
        }
        If ($Roles -eq 1) {
            If ($EXO_ED_RC_save_final -eq $Roles) {
                Write-Host "Exchange E-Discovery Role cmdlets export completed. Removing save state file."
                Remove-Item -Path $ExportDir\.EXO_EDiscovery_RoleCmdlets_savestate -Force
            }
        }
    }

    If ((-not (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate)) -and (-not (Test-Path -Path $ExportDir\EXO_EDiscovery_RoleAssignments.json))) {
        Write-Host "Exchange E-Discovery Role assignments not found. Exporting E-Discovery Role assignments..."
        ForEach ($Role in $Roles) {
            $RoleAssignments = $RoleAssignments + (Get-ManagementRoleAssignment -Role $Role -Delegating $false)
            $RoleAssignments | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_EDiscovery_RoleAssignments_PowerShell.json  -Encoding Ascii -Append
            $Role | Out-File $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate -Encoding Ascii
        }
    } ElseIf (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate) {
        $EXO_ED_RA_save = Get-Content $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate -Encoding Ascii
        $index = $Roles.IndexOf($EXO_ED_RA_save)
        Write-Host "Exchange E-Discovery Role assignments save state found. Picking up from last entry..."
        For ($i=$index; $i -le $Roles.Length; $i++) {
            $Role = $Roles[$i]
            $RoleAssignments = $RoleAssignments + (Get-ManagementRoleAssignment -Role $Role -Delegating $false)
            $RoleAssignments | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_EDiscovery_RoleAssignments_PowerShell.json  -Encoding Ascii -Append
            $Role | Out-File $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate -Encoding Ascii
        }
    }

    If (Test-Path -Path $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate){
        $EXO_ED_RA_save_final = Get-Content $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate -Encoding Ascii
        If ($EXO_ED_RA_save_final -eq $Roles[-1]) {
            Write-Host "Exchange E-Discovery Role assignments completed. Removing save state file."
            Remove-Item -Path $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate -Force
        }
        If ($Roles.count -eq 1) {
            If ($EXO_ED_RA_save_final -eq $Roles) {
                Write-Host "Exchange E-Discovery Role assignments completed. Removing save state file."
                Remove-Item -Path $ExportDir\.EXO_EDiscovery_RoleAssignments_savestate -Force
            }
        }
    }

    Write-Host "Completed exporting EDiscovery information."
}

Function Get-M365MobileDevices() {

    Write-Host "Initializing M365 mobile devices export..."

    If ((Test-Path -Path $ExportDir\EXO_MobileDevices_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_MobileDeviceMailboxPolicy_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_MobileDeviceStats_PowerShell.json) -and (-not (Test-Path -Path $ExportDir\.EXO_MobileDeviceStats_savestate))) {
        Write-Host "M365 mobile devices information already exported. Skipping this call."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_MobileDevices_PowerShell.json)) {
        Write-Host "M365 mobile devices not found. Exporting M365 mobile devices..."
        Get-MobileDevice -ResultSize Unlimited | Select-Object -Property @{Name='FirstSyncTime_UTC'; Expression={$_.FirstSyncTime.ToString()}}, @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty FirstSyncTime, WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MobileDevices_PowerShell.json -Encoding Ascii
        Write-Host "M365 mobile devices export completed."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_MobileDeviceMailboxPolicy_PowerShell.json)) {
        Write-Host "M365 mobile device mailbox policies not found. Exporting M365 mobile device mailbox policies..."
        Get-MobileDeviceMailboxPolicy | Select-Object -Property @{Name='WhenChanged_UTC'; Expression={$_.WhenChangedUTC.ToString()}}, @{Name='WhenCreated_UTC'; Expression={$_.WhenCreatedUTC.ToString()}}, * -ExcludeProperty WhenChangedUTC, WhenCreatedUTC, WhenChanged, WhenCreated | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MobileDeviceMailboxPolicy_PowerShell.json -Encoding Ascii
        Write-Host "M365 mobile device mailbox policies export completed."
    }

    If (Test-Path -Path $ExportDir\EXO_MobileDevices_PowerShell.json) {
        $Devices = Get-Content $ExportDir\EXO_MobileDevices_PowerShell.json | ConvertFrom-Json
        $DeviceGUIDs = $Devices.Guid 
    }

    If ((-not (Test-Path -Path $ExportDir\.EXO_MobileDeviceStats_savestate)) -and (-not (Test-Path -Path $ExportDir\EXO_MobileDeviceStats_PowerShell.json))) {
        Write-Host "M365 mobile device stats not found. Exporting M365 mobile device stats..."
        Foreach ($DeviceGUID in $DeviceGUIDs) {
            $DeviceStats = Get-MobileDeviceStatistics -Identity $DeviceGUID -ErrorAction SilentlyContinue
            $DeviceStats | Select-Object -Property @{Name='FirstSyncTime_UTC'; Expression={$_.FirstSyncTime.ToString()}}, @{Name='LastPolicyUpdateTime_UTC'; Expression={$_.LastPolicyUpdateTime.ToString()}}, @{Name='LastSuccessSync_UTC'; Expression={$_.LastSuccessSync.ToString()}}, @{Name='LastSyncAttemptTime_UTC'; Expression={$_.LastSyncAttemptTime.ToString()}}, * -ExcludeProperty FirstSyncTime, LastPolicyUpdateTime, LastSuccessSync, LastSyncAttemptTime | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MobileDeviceStats_PowerShell.json -Encoding Ascii -Append
            $DeviceGUID | Out-File $ExportDir\.EXO_MobileDeviceStats_savestate -Encoding Ascii
        }
    } ElseIf (Test-Path -Path $ExportDir\.EXO_MobileDeviceStats_savestate) {
        $EXO_MDS_save = Get-Content $ExportDir\.EXO_MobileDeviceStats_savestate -Encoding Ascii
        $index = $DeviceGUIDs.IndexOf($EXO_MDS_save)
        Write-Host "M365 mobile device stats save state found. Picking up from last entry..."
        For ($i=$index; $i -le $DeviceGUIDs.Length; $i++) {
            $DeviceGUID = $DeviceGUIDs[$i]
            $DeviceStats = Get-MobileDeviceStatistics -Identity $DeviceGUID -ErrorAction SilentlyContinue
            $DeviceStats | Select-Object -Property @{Name='FirstSyncTime_UTC'; Expression={$_.FirstSyncTime.ToString()}}, @{Name='LastPolicyUpdateTime_UTC'; Expression={$_.LastPolicyUpdateTime.ToString()}}, @{Name='LastSuccessSync_UTC'; Expression={$_.LastSuccessSync.ToString()}}, @{Name='LastSyncAttemptTime_UTC'; Expression={$_.LastSyncAttemptTime.ToString()}}, * -ExcludeProperty FirstSyncTime, LastPolicyUpdateTime, LastSuccessSync, LastSyncAttemptTime | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MobileDeviceStats_PowerShell.json -Encoding Ascii -Append
            $DeviceGUID | Out-File $ExportDir\.EXO_MobileDeviceStats_savestate -Encoding Ascii
        }
    }

    If (Test-Path -Path $ExportDir\.EXO_MobileDeviceStats_savestate) {
        $EXO_MDS_save_final = Get-Content $ExportDir\.EXO_MobileDeviceStats_savestate -Encoding Ascii
        If ($EXO_MDS_save_final -eq $DeviceGUIDs[-1]) {
            Write-Host "M365 mobile device stats completed. Removing save state file."
            Remove-Item -Path $ExportDir\.EXO_MobileDeviceStats_savestate -Force
        }
        If ($DeviceGUIDs.count -eq 1) {
            If ($EXO_MDS_save_final -eq $DeviceGUIDs) {
                Write-Host "M365 mobile device stats completed. Removing save state file."
                Remove-Item -Path $ExportDir\.EXO_MobileDeviceStats_savestate -Force
            }
        }
    }

    Write-Host "Completed exporting M365 mobile devices information." 
}

Function Get-EXOMailboxInformation() {

    Write-Host "Initializing EXO mailbox export..."
    
    If ((Test-Path -Path $ExportDir\EXO_Mailboxes_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_MailboxCAS_Settings_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_Tenant_CAS_Plan_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_MailboxPermissions_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_InboxRules_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_TopLevelFolderPermissions_PowerShell.json) -and (-not (Test-Path -Path $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate)) -and (-not (Test-Path -Path $ExportDir\.EXO_InboxRules_PowerShell_savestate)) -and (-not (Test-Path -Path $ExportDir\.EXO_TopLevelFolderPermissions_savestate))) {
        Write-Host "Exchange Online mailbox information already exported. Skipping this call."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_Mailboxes_PowerShell.json)) {
        Write-Host "Exchange mailboxes not found. Exporting Exchange mailboxes..."
        Get-EXOMailbox -ResultSize unlimited | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_Mailboxes_PowerShell.json -Encoding Ascii
        Write-Host "Exchange mailboxes export completed."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_MailboxCAS_Settings_PowerShell.json)) {
        Write-Host "Exchange mailbox CAS settings not found. Exporting Exchange mailbox CAS settings..."
        Get-EXOCASMailbox -ResultSize unlimited | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MailboxCAS_Settings_PowerShell.json -Encoding Ascii
        Write-Host "Exchange mailbox CAS settings completed."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_Tenant_CAS_Plan_PowerShell.json)) {
        Write-Host "Exchange tenant CAS plan not found. Exporting Exchange tenant CAS plan..."
        Get-CASMailboxPlan -ResultSize unlimited | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_Tenant_CAS_Plan_PowerShell.json -Encoding Ascii
        Write-Host "Exchange tenant CAS plan completed."
    }

    If (Test-Path -Path $ExportDir\EXO_Mailboxes_PowerShell.json) {
        $Mailboxes = Get-Content $ExportDir\EXO_Mailboxes_PowerShell.json | ConvertFrom-Json
        $Usernames = $Mailboxes.UserPrincipalName
    }   

    If ((-not (Test-Path -Path $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate)) -and (-not (Test-Path -Path $ExportDir\EXO_MailboxPermissions_PowerShell.json))) {
        Write-Host "Exchange mailbox permissions not found. Exporting Exchange mailbox permissions..."
        Foreach ($Username in $Usernames) {
            $UserMailBoxPerms = Get-EXOMailboxPermission -Identity $Username -ResultSize unlimited
            $UserMailBoxPerms | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MailboxPermissions_PowerShell.json -Encoding Ascii -Append
            $Username | Out-File $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate -Encoding Ascii
        }
    } ElseIf (Test-Path -Path $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate) {
        $EXO_MP_PS_save = Get-Content $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate -Encoding Ascii
        $index = $Usernames.IndexOf($EXO_MP_PS_save)
        Write-Host "Exchange mailbox permissions save state found. Picking up from last entry..."
        For ($i=$index; $i -le $Usernames.Length; $i++) {
            $Username = $Usernames[$i]
            $UserMailBoxPerms = Get-EXOMailboxPermission -Identity $Username -ResultSize unlimited
            $UserMailBoxPerms | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MailboxPermissions_PowerShell.json -Encoding Ascii -Append
            $Username | Out-File $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate -Encoding Ascii
        }
    }

    If (Test-Path -Path $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate) {
        $EXO_MP_PS_save_final = Get-Content $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate -Encoding Ascii
        If ( $EXO_MP_PS_save_final -eq $Usernames[-1]) {
            Write-Host "Exchange mailbox permissions completed. Removing save state file."
            Remove-Item -Path $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate -Force
        }
        If ($Usernames.count -eq 1) {
            If ($EXO_MP_PS_save_final -eq $Usernames) {
                Write-Host "Exchange mailbox permissions completed. Removing save state file."
                Remove-Item -Path $ExportDir\.EXO_MailboxPermissions_PowerShell_savestate -Force
            }
        }
    }

    If ((-not (Test-Path -Path $ExportDir\.EXO_InboxRules_PowerShell_savestate)) -and (-not (Test-Path -Path $ExportDir\EXO_InboxRules_PowerShell.json))) {
        Write-Host "Exchange inbox rules not found. Exporting Exchange inbox rules..."
        Foreach ($Username in $Usernames) {
            $UserInboxRules = Get-InboxRule -Mailbox $Username -IncludeHidden
            $UserInboxRules | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_InboxRules_PowerShell.json -Encoding Ascii -Append
            $Username | Out-File $ExportDir\.EXO_InboxRules_PowerShell_savestate -Encoding Ascii
        }
    } ElseIf (Test-Path -Path $ExportDir\.EXO_InboxRules_PowerShell_savestate) {
        $EXO_IR_PS_save = Get-Content $ExportDir\.EXO_InboxRules_PowerShell_savestate -Encoding Ascii
        $index = $Usernames.IndexOf($EXO_IR_PS_save)
        Write-Host "Exchange inbox rules save state found. Picking up from last entry..."
        For ($i=$index; $i -le $Usernames.Length; $i++) {
            $Username = $Usernames[$i]
            $UserInboxRules = Get-InboxRule -Mailbox $Username -IncludeHidden
            $UserInboxRules | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_InboxRules_PowerShell.json -Encoding Ascii -Append
            $Username | Out-File $ExportDir\.EXO_InboxRules_PowerShell_savestate -Encoding Ascii
        }
    }

    If (Test-Path -Path $ExportDir\.EXO_InboxRules_PowerShell_savestate) {
        $EXO_IR_PS_save_final = Get-Content $ExportDir\.EXO_InboxRules_PowerShell_savestate -Encoding Ascii
        If ($EXO_IR_PS_save_final -eq $Usernames[-1]) {
            Write-Host "Exchange inbox rules completed. Removing save state file."
            Remove-Item -Path $ExportDir\.EXO_InboxRules_PowerShell_savestate -Force
        }
        If ($Usernames.count -eq 1) {
            If ($EXO_IR_PS_save_final -eq $Usernames) {
                Write-Host "Exchange inbox rules completed. Removing save state file."
                Remove-Item -Path $ExportDir\.EXO_InboxRules_PowerShell_savestate -Force
            }
        }
    }

    If ((-not (Test-Path -Path $ExportDir\.EXO_TopLevelFolderPermissions_savestate)) -and (-not (Test-Path -Path $ExportDir\EXO_TopLevelFolderPermissions_PowerShell.json))) {
        Write-Host "Exchange top level folder permissions not found. Exporting Exchange top level folder permissions..."
        Foreach ($Username in $Usernames) {
            $UserTopLevelFolderPerms += Get-EXOMailboxFolderPermission -UserPrincipalName $Username
            $UserTopLevelFolderPerms | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_TopLevelFolderPermissions_PowerShell.json -Encoding Ascii -Append
            $Username | Out-File $ExportDir\.EXO_TopLevelFolderPermissions_savestate -Encoding Ascii
        }
    } ElseIf (Test-Path -Path $ExportDir\.EXO_TopLevelFolderPermissions_savestate) {
        $EXO_TLFP_save = Get-Content $ExportDir\.EXO_TopLevelFolderPermissions_savestate -Encoding Ascii
        $index = $Usernames.IndexOf($EXO_TLFP_save)
        Write-Host "Exchange top level folder permissions save state found. Picking up from last entry..."
        For ($i=$index; $i -le $Usernames.Length; $i++) {
            $Username = $Usernames[$i]
            $UserTopLevelFolderPerms += Get-EXOMailboxFolderPermission -UserPrincipalName $Username
            $UserTopLevelFolderPerms | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_TopLevelFolderPermissions_PowerShell.json -Encoding Ascii -Append
            $Username | Out-File $ExportDir\.EXO_TopLevelFolderPermissions_savestate -Encoding Ascii
        }
    }

    If (Test-Path -Path $ExportDir\.EXO_TopLevelFolderPermissions_savestate) {
        $EXO_TLFP_save_final = Get-Content $ExportDir\.EXO_TopLevelFolderPermissions_savestate -Encoding Ascii
        If ($EXO_TLFP_save_final -eq $Usernames[-1]) {
            Write-Host "Exchange top level folder permissions completed. Removing save state file."
            Remove-Item -Path $ExportDir\.EXO_TopLevelFolderPermissions_savestate -Force
        }
        If ($Usernames.count -eq 1) {
            If ($EXO_TLFP_save_final -eq $Usernames) {
                Write-Host "Exchange top level folder permissions completed. Removing save state file."
                Remove-Item -Path $ExportDir\.EXO_TopLevelFolderPermissions_savestate -Force
            }
        }
    }

    Write-Host "Completed exporting EXO mailbox information..."
}

Function Get-EXOConfigInformation() {

    Write-Host "Initializing EXO configuration export..."

    If ((Test-Path -Path $ExportDir\EXO_MailboxAuditStatus_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_AdminAuditLogConfig_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_UALRetentionPolicy_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_OrganizationConfig_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_PerimeterConfig_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_TransportRules_PowerShell.json) -and (Test-Path -Path $ExportDir\EXO_TransportConfig_PowerShell.json)) {
        Write-Host "Exchange Online mailbox information already exported. Skipping this call."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_MailboxAuditStatus_PowerShell.json)) {
        Write-Host "Exchange mailbox audit status not found. Exporting Exchange mailbox audit status..."
        [array]$MailboxAuditStatus = Get-MailboxAuditBypassAssociation -ResultSize unlimited | Where-Object {$_.AuditBypassEnabled -eq $true}
        $MailboxAuditStatus | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_MailboxAuditStatus_PowerShell.json -Encoding Ascii
        Write-Host "Exchange mailbox audit status export completed."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_AdminAuditLogConfig_PowerShell.json)) {
        Write-Host "Exchange admin audit log configuration not found. Exporting Exchange admin audit log configuration..."
        Get-AdminAuditLogConfig | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_AdminAuditLogConfig_PowerShell.json -Encoding Ascii
        Write-Host "Exchange admin audit log configuration export completed."
    }
    
    If (-not (Test-Path -Path $ExportDir\EXO_UALRetentionPolicy_PowerShell.json)) {
        Write-Host "Unified Audit Log retention policy not found. Exporting Unified Audit Log retention policy..."
        Get-UnifiedAuditLogRetentionPolicy | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_UALRetentionPolicy_PowerShell.json -Encoding Ascii
        Write-Host "Unified Audit Log retention policy export completed."
    }
    
    If (-not (Test-Path -Path $ExportDir\EXO_OrganizationConfig_PowerShell.json)) {
        Write-Host "Exchange organization configuration not found. Exporting Exchange organization configuration..."
        Get-OrganizationConfig | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_OrganizationConfig_PowerShell.json -Encoding Ascii
        Write-Host "Exchange organization configuration export completed."
    }

    If (-not (Test-Path -Path $ExportDir\EXO_PerimeterConfig_PowerShell.json)) {
        Write-Host "Exchange perimeter configuration not found. Exporting Exchange perimeter configuration..."
        Get-PerimeterConfig | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_PerimeterConfig_PowerShell.json -Encoding Ascii
        Write-Host "Exchange perimeter configuration export completed."
    }    
    
    If (-not (Test-Path -Path $ExportDir\EXO_TransportRules_PowerShell.json)) {
        Write-Host "Exchange perimeter configuration not found. Exporting Exchange perimeter configuration..."
        Get-TransportRule | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_TransportRules_PowerShell.json -Encoding Ascii
        Write-Host "Exchange perimeter configuration export completed."
    }    

    If (-not (Test-Path -Path $ExportDir\EXO_TransportConfig_PowerShell.json)) {
        Write-Host "Exchange transport configuration not found. Exporting Exchange transport configuration..."
        Get-TransportConfig | ConvertTo-Json -Compress | Out-File $ExportDir\EXO_TransportConfig_PowerShell.json -Encoding Ascii
        Write-Host "Exchange transport configuration export completed."
    } 

    Write-Host "Completed exporting EXO configuration information..."
}

If ($OSEnvironment -match "Unix") {
    $MinimumPSVersion = "7.0.3"
    $OSPSVersion = $PSVersionTable.PSVersion.toString()
    If ([System.Version]$OSPSVersion -le [System.Version]$MinimumPSVersion) {
        Write-Host "Your PowerShell version must be at least 7.0.3. Please upgrade PowerShell and retry the script."
        Pause
        Exit
    }
}

Start-Transcript -OutputDirectory $ReportDir
Import-PSModules -ExportDir $ExportDir -Verbose
($ExchangeEnvironment) = Get-EXOEnvironment -ExchangeEnvironment $ExchangeEnvironment
$UserId = Read-Host "Please enter your username"


If ($OSEnvironment -match "Win") {
    If ($ExchangeEnvironment -ne "O365USGovGCCHigh") {
        Write-Host "EXO environment is NOT US Government."
        Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironment
        Connect-IPPSSession -UserPrincipalName $UserId
    } ElseIf ($ExchangeEnvironment -eq "O365USGovGCCHigh") {
        Write-Host "EXO environment is US Government"
        Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironment
        Connect-IPPSSession -UserPrincipalName $UserId -ConnectionUri https://ps.compliance.protection.office365.us/powershell-liveid/ -AzureADAuthorizationEndpointUri https://login.microsoftonline.us/common
    }

} ElseIf ($OSEnvironment -match "Unix") {
    If ($ExchangeEnvironment -ne "O365USGovGCCHigh") {
        Write-Host "EXO environment is NOT US Government."
        Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironment -Device
        Connect-IPPSSession
    } ElseIf ($ExchangeEnvironment -eq "O365USGovGCCHigh") {
        Write-Host "EXO environment is US Government"
        Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironment
        Connect-IPPSSession -UserPrincipalName $UserId -ConnectionUri https://ps.compliance.protection.office365.us/powershell-liveid/ -AzureADAuthorizationEndpointUri https://login.microsoftonline.us/common
    }
}

Get-EXORoleGrpInformation
Get-EDiscoveryInformation
Get-M365MobileDevices
Get-EXOMailboxInformation
Get-EXOConfigInformation

Write-Host "EXO script is complete! Exiting script now."
Disconnect-ExchangeOnline -Confirm:$false

Stop-Transcript
