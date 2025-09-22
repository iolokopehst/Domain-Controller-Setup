<#
.SYNOPSIS
    Automated setup of a Domain Controller with Active Directory.
.DESCRIPTION
    - Verifies admin rights
    - Installs AD DS role
    - Promotes server to Domain Controller for a new forest
    - Handles errors gracefully and logs everything
.NOTES
    Run this as Administrator on a fresh Windows Server.
    After promotion, the server will reboot automatically.
#>

# ----------------------------
# Start Pause (prevents instant exit if double-clicked)
# ----------------------------
Write-Host "Domain Controller setup script starting. Press any key to continue..."
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# ----------------------------
# Variables
# ----------------------------
$LogFile = "C:\Setup-DC\setup-dc.log"
New-Item -ItemType Directory -Force -Path "C:\Setup-DC" | Out-Null
Start-Transcript -Path $LogFile -Force

try {
    # ----------------------------
    # Check Admin Rights
    # ----------------------------
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator."
        Pause
        exit 1
    }

    # ----------------------------
    # Gather User Input
    # ----------------------------
    $DomainName = Read-Host "Enter the desired domain name (e.g., corp.local)"
    $DSRMPasswordPlain = Read-Host "Enter the DSRM password (used for recovery mode)" -AsSecureString
    $DSRMPassword = $DSRMPasswordPlain

    # ----------------------------
    # Install AD DS Role
    # ----------------------------
    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-Host "Installing Active Directory Domain Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        Write-Host "AD DS role installed successfully."
    } else {
        Write-Host "AD DS role already installed. Skipping..."
    }

    # ----------------------------
    # Promote to Domain Controller
    # ----------------------------
    Write-Host "Promoting server to Domain Controller for new forest: $DomainName"
    Install-ADDSForest `
        -DomainName $DomainName `
        -SafeModeAdministratorPassword $DSRMPassword `
        -InstallDns `
        -Force `
        -ErrorAction Stop

    Write-Host "Domain Controller promotion started successfully."
    Write-Host "The server will reboot automatically when ready."
}
catch {
    Write-Error "A fatal error occurred: $_"
}
finally {
    Stop-Transcript
    Write-Host "`nScript finished. Review log at: $LogFile"
    Write-Host "Press any key to exit..."
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
