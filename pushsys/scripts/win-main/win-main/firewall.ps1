<#
.SYNOPSIS
    Configures Windows Firewall to block all network traffic except HTTPS, LDAP, IMAP, DNS, and SMB.

.DESCRIPTION
    This script sets the default inbound and outbound firewall policies to block all traffic.
    It then creates specific allow rules for HTTPS, LDAP, IMAP, DNS, and SMB traffic on all IP addresses.

.NOTES
    - Run this script with administrative privileges.
    - Backup your current firewall settings before running this script.
    - Test the script in a non-production environment before deploying it widely.

.EXAMPLE
    .\Configure-Firewall-Allow-Specific-Services.ps1
#>

# Ensure the script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
    Write-Warning "You need to run this script as an Administrator!"
    exit 1
}

# Function to backup current firewall settings
function Backup-FirewallSettings {
    param (
        [string]$BackupDirectory = "$env:USERPROFILE\FirewallBackup"
    )

    if (-not (Test-Path -Path $BackupDirectory)) {
        New-Item -Path $BackupDirectory -ItemType Directory | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = Join-Path -Path $BackupDirectory -ChildPath "FirewallBackup_$timestamp.wfw"

    try {
        netsh advfirewall export "$backupPath"
        Write-Output "✅ Firewall settings backed up to $backupPath"
    } catch {
        Write-Error "❌ Failed to backup firewall settings. $_"
        exit 1
    }
}

# Function to set default firewall policies to block all traffic
function Set-DefaultFirewallPolicies {
    Write-Output "🔒 Setting default firewall policies to block all inbound and outbound traffic..."
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
    Write-Output "✅ Default firewall policies set to Block."
}

# Function to create allow rules for specified services
function Create-AllowRules {
    Write-Output "🚧 Creating allow rules for specified services..."

    # Define the rules to allow
    $allowRules = @(
        # HTTPS
        @{
            Name = "Allow-HTTPS-Inbound"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = 443
            Action = "Allow"
        },
        @{
            Name = "Allow-HTTPS-Outbound"
            Direction = "Outbound"
            Protocol = "TCP"
            RemotePort = 443
            Action = "Allow"
        },
        # LDAP
        @{
            Name = "Allow-LDAP-Inbound-TCP"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = 389
            Action = "Allow"
        },
        @{
            Name = "Allow-LDAP-Inbound-UDP"
            Direction = "Inbound"
            Protocol = "UDP"
            LocalPort = 389
            Action = "Allow"
        },
        @{
            Name = "Allow-LDAP-Outbound-TCP"
            Direction = "Outbound"
            Protocol = "TCP"
            RemotePort = 389
            Action = "Allow"
        },
        @{
            Name = "Allow-LDAP-Outbound-UDP"
            Direction = "Outbound"
            Protocol = "UDP"
            RemotePort = 389
            Action = "Allow"
        },
        # LDAPS (Secure LDAP)
        @{
            Name = "Allow-LDAPS-Inbound"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = 636
            Action = "Allow"
        },
        @{
            Name = "Allow-LDAPS-Outbound"
            Direction = "Outbound"
            Protocol = "TCP"
            RemotePort = 636
            Action = "Allow"
        },
        # IMAP
        @{
            Name = "Allow-IMAP-Inbound"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = 143
            Action = "Allow"
        },
        @{
            Name = "Allow-IMAP-Outbound"
            Direction = "Outbound"
            Protocol = "TCP"
            RemotePort = 143
            Action = "Allow"
        },
        # IMAPS (Secure IMAP)
        @{
            Name = "Allow-IMAPS-Inbound"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = 993
            Action = "Allow"
        },
        @{
            Name = "Allow-IMAPS-Outbound"
            Direction = "Outbound"
            Protocol = "TCP"
            RemotePort = 993
            Action = "Allow"
        },
        # DNS
        @{
            Name = "Allow-DNS-Inbound-TCP"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = 53
            Action = "Allow"
        },
        @{
            Name = "Allow-DNS-Inbound-UDP"
            Direction = "Inbound"
            Protocol = "UDP"
            LocalPort = 53
            Action = "Allow"
        },
        @{
            Name = "Allow-DNS-Outbound-TCP"
            Direction = "Outbound"
            Protocol = "TCP"
            RemotePort = 53
            Action = "Allow"
        },
        @{
            Name = "Allow-DNS-Outbound-UDP"
            Direction = "Outbound"
            Protocol = "UDP"
            RemotePort = 53
            Action = "Allow"
        },
        # SMB
        @{
            Name = "Allow-SMB-Inbound"
            Direction = "Inbound"
            Protocol = "TCP"
            LocalPort = 445
            Action = "Allow"
        },
        @{
            Name = "Allow-SMB-Outbound"
            Direction = "Outbound"
            Protocol = "TCP"
            RemotePort = 445
            Action = "Allow"
        }
    )

    # Optional: Include SMB legacy ports 137-139 if needed
    $includeLegacySMB = $false  # Set to $true if you need to include legacy SMB ports

    if ($includeLegacySMB) {
        $legacyPorts = 137, 138, 139
        foreach ($port in $legacyPorts) {
            $allowRules += @{
                Name = "Allow-SMB-Legacy-Inbound-TCP-$port"
                Direction = "Inbound"
                Protocol = "TCP"
                LocalPort = $port
                Action = "Allow"
            },
            @{
                Name = "Allow-SMB-Legacy-Inbound-UDP-$port"
                Direction = "Inbound"
                Protocol = "UDP"
                LocalPort = $port
                Action = "Allow"
            },
            @{
                Name = "Allow-SMB-Legacy-Outbound-TCP-$port"
                Direction = "Outbound"
                Protocol = "TCP"
                RemotePort = $port
                Action = "Allow"
            },
            @{
                Name = "Allow-SMB-Legacy-Outbound-UDP-$port"
                Direction = "Outbound"
                Protocol = "UDP"
                RemotePort = $port
                Action = "Allow"
            }
        }
    }

    # Create the firewall rules
    foreach ($rule in $allowRules) {
        try {
            $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
            if ($existingRule) {
                Write-Output "ℹ️  Rule already exists: $($rule.Name). Updating the rule."
                Remove-NetFirewallRule -DisplayName $rule.Name
            }
            New-NetFirewallRule -DisplayName $rule.Name `
                                -Direction $rule.Direction `
                                -Protocol $rule.Protocol `
                                -LocalPort $rule.LocalPort `
                                -RemotePort $rule.RemotePort `
                                -Action $rule.Action `
                                -Profile Domain,Private,Public `
                                -Enabled True `
                                -EdgeTraversalPolicy Block
            Write-Output "✅ Created firewall rule: $($rule.Name)"
        } catch {
            Write-Warning "⚠️  Failed to create firewall rule: $($rule.Name). $_"
        }
    }
}

# Function to enable the firewall if it's not enabled
function Ensure-FirewallEnabled {
    $profiles = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }

    if ($profiles) {
        foreach ($profile in $profiles) {
            try {
                Set-NetFirewallProfile -Name $profile.Name -Enabled True
                Write-Output "✅ Enabled Firewall for profile: $($profile.Name)"
            } catch {
                Write-Warning "⚠️  Failed to enable Firewall for profile: $($profile.Name). $_"
            }
        }
    } else {
        Write-Output "✅ Firewall is already enabled for all profiles."
    }
}

# Function to verify firewall rules
function Verify-FirewallRules {
    Write-Output "🔍 Verifying firewall rules..."

    # Collect the names of required rules
    $requiredRuleNames = $allowRules | Select-Object -ExpandProperty Name

    foreach ($ruleName in $requiredRuleNames) {
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            Write-Output "✅ Rule exists: $ruleName"
        } else {
            Write-Warning "❌ Rule missing: $ruleName"
        }
    }

    Write-Output "🔍 Verification complete."
}

# Backup current firewall settings
Backup-FirewallSettings

# Set default firewall policies to block all
Set-DefaultFirewallPolicies

# Create allow rules for specified services
Create-AllowRules

# Ensure firewall is enabled
Ensure-FirewallEnabled

# Verify the created firewall rules
Verify-FirewallRules

Write-Output "🎉 Firewall configuration completed successfully."
