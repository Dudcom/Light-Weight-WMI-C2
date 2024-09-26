# Check and seed credentials and targets from seed.txt
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
                Write-Host "Password: ********"  # Masking password output
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

# Function to use PS Remoting to copy files and execute commands on the target machine
function PushPull-System-PSRemoting {
    param (
        [string]$target,
        [string]$user,
        [string]$password,
        [string]$localDir = "$(Get-Location)\pushsys",  # Local pushsys directory on the attacker
        [string]$remoteDir = "C:\pushsys"  # Target pushsys directory on the host
    )

    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)

        # Create a PS Session to the target
        $session = New-PSSession -ComputerName $target -Credential $credential

        # Ensure the local 'pushsys' folder exists
        if (-not (Test-Path $localDir)) {
            Write-Host "The directory $localDir does not exist. Please check the path."
            return
        }

        # Ensure the remote pushsys directory exists
        Invoke-Command -Session $session -ScriptBlock {
            param ($remoteDir)
            if (-not (Test-Path $remoteDir)) {
                New-Item -ItemType Directory -Path $remoteDir -Force
            }
        } -ArgumentList $remoteDir

        # Copy local pushsys files to the remote machine
        Copy-Item -Path "$localDir\*" -Destination $remoteDir -Recurse -ToSession $session -Force

        Write-Host "Push-Pull system synced from $localDir to ${target}:$remoteDir"

        # Close the PS session
        Remove-PSSession -Session $session
    }
    catch {
        Write-Host "An error occurred during the push-pull operation: $_"
    }
}

# Interactive PowerShell Remoting Command Execution for a remote system
function Execute-InteractivePSRemoting {
    param (
        [string]$ComputerName,
        [string]$User,
        [string]$Password
    )

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($User, $securePassword)

    # Create a PS Session to the target
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

    # Close the PS session
    Remove-PSSession -Session $session
}

# Main script logic for seeding and starting interactive PS Remoting
function Start-C2Session {
    $seedData = Seed-System
    if ($seedData) {
        $user = $seedData.user
        $password = $seedData.password
        $targets = $seedData.targets

        foreach ($target in $targets) {
            Write-Host "`nStarting interactive session with $target..."

            # Sync the pushsys folder before starting the interactive session
            PushPull-System-PSRemoting -target $target -user $user -password $password

            Execute-InteractivePSRemoting -ComputerName $target -User $user -Password $password
        }
    }
}

# Run the C2 session
Start-C2Session
