<#
.SYNOPSIS
Automates installing Active Directory Domain Services (AD DS) and promoting
the server to a Domain Controller for a new forest.

.DESCRIPTION
- Self-elevates if not run as admin.
- Installs AD DS role if missing.
- Always prompts for Administrator password if not a DC.
- Promotes server to Domain Controller in a new forest.
- Handles errors gracefully, logs all actions, and pauses at the end.
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
# Logging
# ----------------------------
$LogDir = "C:\Setup-DC"
$LogFile = "$LogDir\setup-dc.log"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Start-Transcript -Path $LogFile -Force

try {
    # ----------------------------
    # Check if already a Domain Controller
    # ----------------------------
    try {
        $DCCheck = Get-ADDomain -ErrorAction SilentlyContinue
        if ($DCCheck) {
            Write-Host "This server is already a Domain Controller in domain $($DCCheck.DNSRoot). Exiting."
            Stop-Transcript
            Read-Host "Press Enter to exit"
            exit 0
        }
    } catch {
        # Not a DC yet, continue
    }

    # ----------------------------
    # Install AD DS role if missing
    # ----------------------------
    $ADDS = Get-WindowsFeature AD-Domain-Services
    if (-not $ADDS.Installed) {
        Write-Host "Installing Active Directory Domain Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        Write-Host "AD DS role installed successfully.`n"
    } else {
        Write-Host "AD DS role already installed. Skipping installation.`n"
    }

    # ----------------------------
    # Prompt to set Administrator password (required for AD promotion)
    # ----------------------------
    Write-Host "You must set a secure password for the local Administrator account before promotion."
    $AdminPassword = Read-Host "Enter a new password for Administrator" -AsSecureString
    try {
        Set-LocalUser -Name "Administrator" -Password $AdminPassword -ErrorAction Stop
        Write-Host "Administrator password updated successfully.`n"
    } catch {
        Write-Error "Failed to set Administrator password: $_"
        Read-Host "Press Enter to exit"
        exit 1
    }

    # ----------------------------
    # Prompt for domain details
    # ----------------------------
    $DomainName = Read-Host "Enter the new domain name (e.g., corp.local)"
    $DSRMPassword = Read-Host "Enter Directory Services Restore Mode (DSRM) password" -AsSecureString

    # ----------------------------
    # Promote server to Domain Controller
    # ----------------------------
    Write-Host "Promoting server to Domain Controller for domain $DomainName..."
    Install-ADDSForest `
        -DomainName $DomainName `
        -SafeModeAdministratorPassword $DSRMPassword `
        -InstallDNS:$true `
        -Force:$true -ErrorAction Stop

    Write-Host "`nDomain Controller promotion started. The server will reboot automatically."

} catch {
    Write-Error "A fatal error occurred: $_"
} finally {
    Stop-Transcript
    Write-Host "`nScript finished. Review log at: $LogFile"
    Read-Host "Press Enter to exit"
}
