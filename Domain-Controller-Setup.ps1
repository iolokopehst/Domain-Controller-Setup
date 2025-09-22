<#
.SYNOPSIS
    Automated setup of a Domain Controller with Active Directory.
.DESCRIPTION
    - Self-elevates if not run as admin
    - Installs AD DS role if missing
    - Checks if server is already a DC
    - Ensures Administrator account has a secure password
    - Promotes server to Domain Controller for a new forest
    - Logs all actions
.NOTES
    Run this on a fresh Windows Server VM. It will reboot after promotion.
#>

# ----------------------------
# Self-Elevation
# ----------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "Not running as Administrator. Restarting with elevation..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Error "User declined UAC elevation. Exiting..."
    }
    exit
}

# ----------------------------
# Setup Logging
# ----------------------------
$LogFile = "C:\Setup-DC\setup-dc.log"
New-Item -ItemType Directory -Force -Path "C:\Setup-DC" | Out-Null
Start-Transcript -Path $LogFile -Force

try {
    # ----------------------------
    # Check if already a Domain Controller
    # ----------------------------
    if ((Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4) {
        Write-Host "This server is already a Domain Controller. Skipping promotion."
        Stop-Transcript
        Write-Host "`nPress Enter to exit..."
        [void][System.Console]::ReadLine()
        exit
    }

    # ----------------------------
    # Install AD DS Role if missing
    # ----------------------------
    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-Host "Installing Active Directory Domain Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        Write-Host "AD DS role installed successfully."
    } else {
        Write-Host "AD DS role already installed. Skipping installation."
    }

    # ----------------------------
    # Ensure Administrator has a password
    # ----------------------------
    $AdminUser = "Administrator"
    $Admin = Get-LocalUser -Name $AdminUser

    if ($null -eq $Admin) {
        Write-Error "Local Administrator account not found. Exiting..."
        exit 1
    }

    if (-not $Admin.PasswordRequired -or $Admin.PasswordExpires -eq $false) {
        Write-Host "Local Administrator account does not have a secure password."
        $NewPassword = Read-Host "Enter a new password for Administrator" -AsSecureString
        try {
            Set-LocalUser -Name $AdminUser -Password $NewPassword -ErrorAction Stop
            Write-Host "Administrator password updated successfully."
        } catch {
            Write-Error "Failed to set Administrator password: $_"
            exit 1
        }
    }

    # ----------------------------
    # Gather Domain Info
    # ----------------------------
    $DomainName = Read-Host "Enter the desired domain name (e.g., corp.local)"
    $DSRMPassword = Read-Host "Enter the DSRM password (used for recovery mode)" -AsSecureString

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

    Write-Host "Domain Controller promotion started. The server will reboot automatically."
}
catch {
    Write-Error "A fatal error occurred: $_"
}
finally {
    Stop-Transcript
    Write-Host "`nScript finished. Review log at: $LogFile"
    Write-Host "Press Enter to exit..."
    [void][System.Console]::ReadLine()
}
