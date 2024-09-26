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
            PushPull-System-PSRemoting -target $target -user $user -password $password

            Execute-InteractivePSRemoting -ComputerName $target -User $user -Password $password
        }
    }
}

Start-C2Session
