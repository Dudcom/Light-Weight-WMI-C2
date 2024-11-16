Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configure SMB" -ForegroundColor white

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "MinimumPIN" /t REG_DWORD /d "0x00000006" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v "MaxSize" /t REG_DWORD /d "0x00008000" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisableIpSourceRouting" /t REG_DWORD /d "2" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "2" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" /v "UseLogonCredential" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\batfile\shell\runasuser\" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\cmdfile\shell\runasusers" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\exefile\shell\runasuser" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\exefile\shell\runasusers" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fMinimizeConnections" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fBlockNonDomain" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "0x00000001" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v "DriverLoadPolicy" /t REG_DWORD /d "8" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoGPOListChanges" /t REG_DWORD /d "0" /f | Out-Null
reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SYSTEM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\Systemh" /v "EnumerateLocalUsers" /t REG_DWORD /d "0" /f | Out-Null
reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "DCSettingIndex" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "ACSettingIndex" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "3" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0x00000001" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "DevicePKInitEnabled" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v "RestrictRemoteClients" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "MSAOptional" /t REG_DWORD /d "0x00000001" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "0x00000001" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v "EnumerateAdministrators" /t REG_DWORD /d "0" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0x00000001" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "0x000000ff" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0x00000001" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "v1607 LTSB:" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0x00000002" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d "0" /f | Out-Null
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d "0x00000000" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "PreXPSP2ShellProtocolBehavior" /t REG_DWORD /d "0" /f | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force | Out-Null
Set-SmbServerConfiguration -EncryptData $true -Force | Out-Null