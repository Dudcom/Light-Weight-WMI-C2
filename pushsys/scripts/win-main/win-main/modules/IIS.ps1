Import-Module WebAdministration
Import-Module IISAdministration

if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {
    # Set application pool identity type to LocalSystem (4) for all app pools
    foreach($item in (Get-ChildItem IIS:\AppPools)) {
        $tempPath = "IIS:\AppPools\" + $item.name
        Set-ItemProperty -Path $tempPath -Name processModel.identityType -Value 4
    }

    # Disable directory browsing for all sites
    foreach($item in (Get-ChildItem IIS:\Sites)) {
        $tempPath = "IIS:\Sites\" + $item.name
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $tempPath -Value False
    }

    # Allow PowerShell to modify anonymousAuthentication settings
    Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -Metadata overrideMode -Value Allow -PSPath IIS:/

    # Disable anonymous authentication for all sites
    foreach($item in (Get-ChildItem IIS:\Sites)) {
        $tempPath = "IIS:\Sites\" + $item.name
        Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication $tempPath -Value 0
    }

    # Deny PowerShell the ability to modify anonymousAuthentication settings
    Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -Metadata overrideMode -Value Deny -PSPath IIS:/

    # Delete custom error pages
    $sysDrive = $Env:Path.Substring(0, 3)
    $tempPath = (Get-WebConfiguration "//httperrors/error").prefixLanguageFilePath | Select-Object -First 1
    $sysDrive += $tempPath.Substring($tempPath.IndexOf('\') + 1)
    Get-ChildItem -Path $sysDrive -Include *.* -File -Recurse | ForEach-Object { $_.Delete() }
}

# Set various web application and site security settings
# Ensure forms authentication requires SSL
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "requireSSL" -Value $true

# Ensure forms authentication is set to use cookies
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "cookieless" -Value "UseCookies"

# Ensure cookie protection mode is configured for forms authentication
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "protection" -Value "All"

# Ensure passwordFormat is not set to clear
Add-WebConfigurationProperty -Filter "/system.web/membership/providers/add[@name='ProviderName']" -Name "passwordFormat" -Value "Hashed"

# Ensure credentials are not stored in configuration files
$webapps = Get-WebApplication
foreach ($webapp in $webapps) {
    $physicalPath = $webapp.physicalPath
    $webConfigPath = "$physicalPath\web.config"
    if (Test-Path $webConfigPath) {
        $webConfig = [xml](Get-Content $webConfigPath)
        $credentialsElement = $webConfig.SelectSingleNode("/configuration/system.web/httpRuntime/@enablePasswordRetrieval")
        if ($credentialsElement -ne $null) {
            $credentialsElement.ParentNode.RemoveChild($credentialsElement)
            $webConfig.Save($webConfigPath)
            Write-Host "Removed 'credentials' element from $webConfigPath"
        }
    }
}

# Additional security configurations
Add-WebConfigurationProperty -Filter "/system.webServer/deployment" -Name "Retail" -Value "True"
Set-WebConfigurationProperty -Filter "/system.web/compilation" -Name "debug" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/httpErrors" -Name "errorMode" -Value "DetailedLocalOnly"
Set-WebConfigurationProperty -Filter "/system.web/trace" -Name "enabled" -Value "false"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "mode" -Value "InProc"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieName" -Value "MyAppSession"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieless" -Value "UseCookies"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "timeout" -Value "20"
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "3DES"
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "SHA1"
Add-WebConfigurationProperty -Filter "/configuration/system.web/trust" -Name "level" -Value "Full"
Set-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" -PSPath "IIS:\Sites\Default Web Site" -Name "." -Value $null
Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "remove" -Value @{name="X-Powered-By";}
Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "add" -Value @{name="Server";value="";}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 104857600
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -Value 8192
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -Value 2048
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/allowDoubleEscaping" -Name "enabled" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/denyUrlSequences" -Name "add" -Value @{sequence="%2525"}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering" -Name "allowVerb" -Value @{verb="TRACE"; allowed="False"}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/fileExtensions" -Name "allowUnlisted" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/handlers/*" -Name "permissions" -Value "Read,Script"
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedIsapisAllowed" -Value "False"
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedCgisAllowed" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/security/dynamicIpSecurity" -Name "enabled" -Value "True"

Add-Item -ItemType Directory -Path "C:\NewIISLogLocation"
Add-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile" -Name "directory" -Value "C:\NewIISLogLocation"

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/Logfile" -Name "logExtFileFlags" -Value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/tracing/traceFailedRequestsLogging" -Name "enabled" -Value "True"

Restart-Service W3SVC