<#
.SYNOPSIS
    Automates installation of Active Directory Domain Services and promotes server to Domain Controller.
.DESCRIPTION
    - Renames computer
    - Sets static IP and DNS
    - Installs AD DS + DNS
    - Promotes server to Domain Controller
    - Includes error handling and keeps window open for review
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
$NewName      = Read-Host "Enter new computer name"
$IPAddress    = Read-Host "Enter static IP address (e.g., 192.168.1.10)"
$PrefixLength = Read-Host "Enter prefix length (e.g., 24 for /24)"
$Gateway      = Read-Host "Enter default gateway (e.g., 192.168.1.1)"
$DNSServer    = Read-Host "Enter DNS server (use same as this DC, e.g., $IPAddress)"
$DomainName   = Read-Host "Enter new domain name (e.g., corp.local)"
$SafeModePass = Read-Host "Enter DSRM Safe Mode password" -AsSecureString

Write-Host "`n--- Starting Configuration ---`n"

# ----------------------------
# Rename Computer
# ----------------------------
try {
    Rename-Computer -NewName $NewName -Force -ErrorAction Stop
    Write-Host "Computer renamed to $NewName (changes apply after reboot)."
}
catch {
    Write-Error "Failed to rename computer: $_"
}

# ----------------------------
# Configure Static IP
# ----------------------------
try {
    $NIC = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $NIC) { throw "No active network adapter found." }

    # Remove existing IPs
    Get-NetIPAddress -InterfaceIndex $NIC.ifIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    # Assign new IP
    New-NetIPAddress -InterfaceIndex $NIC.ifIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -DefaultGateway $Gateway -ErrorAction Stop

    # Set DNS
    Set-DnsClientServerAddress -InterfaceIndex $NIC.ifIndex -ServerAddresses $DNSServer -ErrorAction Stop

    Write-Host "Static IP and DNS configured."
}
catch {
    Write-Error "Failed to configure network settings: $_"
}

# ----------------------------
# Install AD DS Role
# ----------------------------
try {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
    Write-Host "AD DS role installed."
}
catch {
    Write-Error "Failed to install AD DS role: $_"
}

# ----------------------------
# Promote to Domain Controller
# ----------------------------
try {
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
        -Force -ErrorAction Stop

    Write-Host "`nDomain Controller promotion initiated successfully."
}
catch {
    Write-Error "Failed to promote server to Domain Controller: $_"
}

# ----------------------------
# End of Script
# ----------------------------
Write-Host "`nSetup script finished. Review any errors above before rebooting."

# Pause before exiting so you can read the output
Write-Host "`nPress any key to exit..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
