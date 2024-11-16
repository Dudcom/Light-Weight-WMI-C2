Function Write-Results {
    Param (
            [Parameter(Position=0,Mandatory=$true)]
            [string]$Path,

            [Parameter(Position=1,Mandatory=$true)]
            [string]$Domain
        )

    $Acl = Get-Acl -Path $Path
    Write-Host $Domain -ForegroundColor DarkRed -BackgroundColor White
    Write-Host ($Path.Substring($Path.IndexOf(":") + 1)) -ForegroundColor DarkRed -BackgroundColor White
    Write-Output -InputObject $Acl.Access
}
Function Set-Auditing {
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Domain,

        [Parameter(Position=1,Mandatory=$true)]
        [AllowEmptyString()]
        [String]$ObjectCN,

        [Parameter(Position=2,Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectoryAuditRule[]]$Rules
    )

    $DN = (Get-ADDomain -Identity $Domain).DistinguishedName
    [String[]]$Drives = Get-PSDrive | Select-Object -ExpandProperty Name

    $TempDrive = "tempdrive"

    if ($Drives.Contains($TempDrive)) {
        Write-Host "An existing PSDrive exists with name $TempDrive, temporarily removing" -ForegroundColor Yellow
        $OldDrive = Get-PSDrive -Name $TempDrive
        Remove-PSDrive -Name $TempDrive
    }

    $Drive = New-PSDrive -Name $TempDrive -Root "" -PSProvider ActiveDirectory -Server $Domain
    Push-Location -Path "$Drive`:\"

    if ($ObjectCN -eq "") {
        $ObjectDN = $DN
    } else {
        $ObjectDN = $ObjectCN + "," + $DN
    }

    $ObjectToChange = Get-ADObject -Identity $ObjectDN -Server $Domain
    $Path = $ObjectToChange.DistinguishedName

    try {
        $Acl = Get-Acl -Path $Path -Audit

        if ($Acl -ne $null) {
            foreach ($Rule in $Rules) {
                $Acl.AddAuditRule($Rule)
            }
            Set-Acl -Path $Path -AclObject $Acl
            # Write-Results -Path $Path -Domain $Domain
        } else {
            Write-Warning "Could not retrieve the ACL for $Path"
        }
    } catch [System.Exception] {
        Write-Warning $_.ToString()
    }
    Pop-Location

    Remove-PSDrive $Drive

    if ($OldDrive -ne $null) {
        Write-Host "Recreating original PSDrive" -ForegroundColor Yellow
        New-PSDrive -Name $OldDrive.Name -PSProvider $OldDrive.Provider -Root $OldDrive.Root | Out-Null
        $OldDrive = $null
    }
}
Function New-EveryoneAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-DomainControllersAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneWriteDaclSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneWritePropertySuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneWriteDaclSuccess, $EveryoneWritePropertySuccess)

    Write-Output -InputObject $Rules
}
Function New-InfrastructureObjectAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    #$objectguid = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd" #Guid for change infrastructure master extended right if it was needed
    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-PolicyContainerAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-DomainAuditRuleSet {
    Param (
        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
        [System.Security.Principal.SecurityIdentifier]$DomainSID
    )

    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    $DomainUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)
    $Administrators = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $DomainUsersSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($DomainUsers,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $AdministratorsSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Administrators,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $DomainUsersSuccess, $AdministratorsSuccess, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}

Function New-RIDManagerAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Mitigate Zerologon (CVE-2020-1472)" -ForegroundColor white

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v vulnerablechannelallowlist /f | Out-Null
nltest /DBFlag:2080FFFF | Out-Null

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Mitigate NoPac (CVE-2021-42287/CVE-2021-42278)" -ForegroundColor white

Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enable enforcement of signing for LDAP server" -ForegroundColor white

reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f | Out-Null

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enable extended protection for LDAP authentication" -ForegroundColor white

reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f | Out-Null

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured DSRM administator account usage" -ForegroundColor white

reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 1 /f | Out-Null

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disable unauthenticated LDAP" -ForegroundColor white

$RootDSE = Get-ADRootDSE
$ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1'}

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configure maximum time for LDAP connections" -ForegroundColor white

[string]$DomainDN = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser -Server $env:COMPUTERNAME).RootDomain -Server $env:COMPUTERNAME | Select-Object -ExpandProperty DistinguishedName
[System.Int32]$MaxConnIdleTime = 180
[string]$SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + $DomainDN
[Microsoft.ActiveDirectory.Management.ADEntity]$Policies = get-adobject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties *
$AdminLimits = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$Policies.lDAPAdminLimits

for ($i = 0; $i -lt $AdminLimits.Count; $i++) {
    if ($AdminLimits[$i] -match "MaxConnIdleTime=*") {
        break
    }
}
if ($i -lt $AdminLimits.Count) {
    $AdminLimits[$i] = "MaxConnIdleTime=$MaxConnIdleTime"
} else {
    $AdminLimits.Add("MaxConnIdleTime=$MaxConnIdleTime")
}
Set-ADObject -Identity $Policies -Clear lDAPAdminLimits
foreach ($Limit in $AdminLimits) {
    Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit}
}
Write-Output -InputObject (Get-ADObject -Identity $Policies -Properties * | Select-Object -ExpandProperty lDAPAdminLimits | Where-Object {$_ -match "MaxConnIdleTime=*"})

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disable anonymous LDAP" -ForegroundColor white

$DN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain -Identity (Get-ADForest -Current LocalComputer).RootDomain).DistinguishedName)
$DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = "00000000"}

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "INFO" -ForegroundColor yellow -NoNewLine; Write-Host "] Set ACLs" -ForegroundColor white

$BuiltinAdministrators = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$CreatorOwner = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)
$LocalService = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalServiceSid, $null)

$AdministratorAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$CreatorOwnerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$LocalServiceAce = New-Object System.Security.AccessControl.FileSystemAccessRule($LocalService,
    @([System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateDirectories),
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$NTDS = Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
$DSA = $NTDS.'DSA Database File'
$Logs = $NTDS.'Database log files path'
$DSA = $DSA.Substring(0, $DSA.LastIndexOf("\"))

$ACL1 = Get-Acl -Path $DSA

foreach($Rule in $ACL1.Access) {
    $ACL1.RemoveAccessRule($Rule) | Out-Null
}

$ACL1.AddAccessRule($AdministratorAce)
$ACL1.AddAccessRule($SystemAce)

Set-Acl -Path $DSA -AclObject $ACL1
Get-ChildItem -Path $DSA | ForEach-Object {
    $Acl = Get-Acl -Path $_.FullName
    foreach($Rule in $Acl.Access) {
        if(-not $Rule.IsInherited) {
            $Acl.RemoveAccessRule($Rule) | Out-Null
        }
    }
    Set-Acl -Path $_.FullName -AclObject $Acl
}

$ACL2 = Get-Acl -Path $Logs

foreach($Rule in $ACL2.Access) {
    $ACL2.RemoveAccessRule($Rule) | Out-Null
}

$ACL2.AddAccessRule($AdministratorAce)
$ACL2.AddAccessRule($SystemAce)
$ACL2.AddAccessRule($LocalServiceAce)
$ACL2.AddAccessRule($CreatorOwnerAce)
    
Set-Acl -Path $Logs -AclObject $ACL2
Get-ChildItem -Path $Logs | ForEach-Object {
    $Acl = Get-Acl -Path $_.FullName
    foreach($Rule in $Acl.Access) {
        if(-not $Rule.IsInherited) {
            $Acl.RemoveAccessRule($Rule) | Out-Null
        }
    }
    Set-Acl -Path $_.FullName -AclObject $Acl
}

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enable auditing on several objects" -ForegroundColor white

$Domain = (Get-ADDomain -Current LocalComputer).DNSRoot

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-RIDManagerAuditRuleSet
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=RID Manager$,CN=System"

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-PolicyContainerAuditRuleSet
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Policies,CN=System"

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainAuditRuleSet -DomainSID (Get-ADDomain -Identity $Domain | Select-Object -ExpandProperty DomainSID)
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN ""

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-InfrastructureObjectAuditRuleSet
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Infrastructure"

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainControllersAuditRuleSet
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "OU=Domain Controllers"

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-EveryoneAuditRuleSet
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=AdminSDHolder,CN=System"