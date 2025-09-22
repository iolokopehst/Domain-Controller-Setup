<#
.SYNOPSIS
Automates installing Active Directory Domain Services (AD DS) and promoting
the server to a Domain Controller for a new forest.

.DESCRIPTION
- Checks for admin rights and self-elevates if needed.
- Installs AD DS role if missing.
- Ensures Administrator account has a non-blank password.
- Promotes server to a Domain Controller in a new forest.
- Handles errors gracefully and pauses at the end so messages are visible.
#>

# ----------------------------
# Ensure script runs as admin
# ----------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrative privileges. Restarting as administrator..."
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "`n=== Active Directory Domain Controller Setup ===`n"

# ----------------------------
# Install AD DS role if not present
# ----------------------------
try {
    $ADDS = Get-WindowsFeature AD-Domain-Services
    if (-not $ADDS.Installed) {
        Write-Host "Installing Active Directory Domain Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        Write-Host "AD DS role installed successfully.`n"
    } else {
        Write-Host "AD DS role already installed. Skipping installation.`n"
    }
} catch {
    Write-Error "Failed to install AD DS role: $_"
    Read-Host "Press Enter to exit"
    exit 1
}

# ----------------------------
# Check if already a Domain Controller
# ----------------------------
try {
    $DC = Get-ADDomain -ErrorAction SilentlyContinue
    if ($DC) {
        Write-Host "This server is already a Domain Controller in domain $($DC.DNSRoot). Exiting."
        Read-Host "Press Enter to exit"
        exit 0
    }
} catch {
    # Not a DC yet, continue
}

# ----------------------------
# Ensure Administrator has a usable password
# ----------------------------
$AdminUser = "Administrator"
$HasBlankPassword = $false

# Test authentication with blank password
$TestPassword = ConvertTo-SecureString "" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($AdminUser, $TestPassword)
try {
    $null = Start-Process powershell.exe -Credential $Cred -ArgumentList "-Command exit" -ErrorAction Stop
    $HasBlankPassword = $true
} catch {
    $HasBlankPassword = $false
}

if ($HasBlankPassword) {
    Write-Warning "Administrator account currently has a BLANK password. This must be changed before promotion."
    $NewPassword = Read-Host "Enter a new password for Administrator" -AsSecureString
    try {
        Set-LocalUser -Name $AdminUser -Password $NewPassword -ErrorAction Stop
        Write-Host "Administrator password updated successfully.`n"
    } catch {
        Write-Error "Failed to set Administrator password: $_"
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# ----------------------------
# Prompt for domain details
# ----------------------------
$DomainName = Read-Host "Enter the new domain name (e.g., corp.local)"
$SafeModePass = Read-Host "Enter Directory Services Restore Mode (DSRM) password" -AsSecureString

# ----------------------------
# Promote server to DC
# ----------------------------
try {
    Write-Host "Promoting server to Domain Controller for domain $DomainName..."
    Install-ADDSForest `
        -DomainName $DomainName `
        -SafeModeAdministratorPassword $SafeModePass `
        -InstallDNS:$true `
        -Force:$true -ErrorAction Stop

    Write-Host "`nDomain Controller promotion started. The server will reboot automatically."
} catch {
    Write-Error "Failed to promote server to Domain Controller: $_"
    Read-Host "Press Enter to exit"
    exit 1
}

# ----------------------------
# Keep window open at the end
# ----------------------------
Read-Host "`nSetup completed. Press Enter to close this window"
