<#
.SYNOPSIS
    Automates the installation of Active Directory Domain Services (AD DS) and promotes server to a Domain Controller.

.DESCRIPTION
    Prompts for server name, IP settings, domain name, and Safe Mode password.
    Renames the computer, sets static IP, installs AD DS + DNS, and promotes server as Domain Controller.

.NOTES
    Run this script as Administrator on a fresh Windows Server.
    Server will reboot automatically after promotion.
#>

# ----------------------------
# Ensure script is run as Administrator
# ----------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'. Exiting..."
    Start-Sleep -Seconds 5
    exit
}

# ----------------------------
# Prompt for Input
# ----------------------------
$NewName       = Read-Host "Enter new computer name"
$IPAddress     = Read-Host "Enter static IP address (e.g., 192.168.1.10)"
$PrefixLength  = Read-Host "Enter prefix length (e.g., 24 for /24)"
$Gateway       = Read-Host "Enter default gateway (e.g., 192.168.1.1)"
$DNSServer     = Read-Host "Enter DNS server (use same as this DC, e.g., $IPAddress)"
$DomainName    = Read-Host "Enter new domain name (e.g., corp.local)"
$SafeModePass  = Read-Host "Enter DSRM Safe Mode password" -AsSecureString

Write-Host "`n--- Starting Configuration ---`n"

# ----------------------------
# Rename Computer
# ----------------------------
Rename-Computer -NewName $NewName -Force
Write-Host "Computer renamed to $NewName (changes apply after reboot)."

# ----------------------------
# Configure Static IP
# ----------------------------
$NIC = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

# Remove existing IP addresses
Get-NetIPAddress -InterfaceIndex $NIC.ifIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

# Assign new static IP
New-NetIPAddress -InterfaceIndex $NIC.ifIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -DefaultGateway $Gateway

# Set DNS server
Set-DnsClientServerAddress -InterfaceIndex $NIC.ifIndex -ServerAddresses $DNSServer

Write-Host "Static IP and DNS configured."

# ----------------------------
# Install AD DS Role
# ----------------------------
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Write-Host "AD DS role installed."

# ----------------------------
# Promote to Domain Controller
# ----------------------------
Install-ADDSForest `
    -DomainName $DomainName `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "WinThreshold" `
    -ForestMode "WinThreshold" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword $SafeModePass `
    -Force

# ----------------------------
# Script End
# ----------------------------
Write-Host "`nSetup complete! Server will reboot automatically to apply Domain Controller role.`n"
