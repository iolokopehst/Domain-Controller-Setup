<#
.SYNOPSIS
    Automated setup of a Domain Controller with Active Directory.
.DESCRIPTION
    - Automatically relaunches with Administrator rights if needed
    - Installs AD DS role
    - Promotes server to Domain Controller for a new forest
    - Logs everything
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
# Start Transcript Logging
# ----------------------------
$LogFile = "C:\Setup-DC\setup-dc.log"
New-Item -ItemType Directory -Force -Path "C:\Setup-DC" | Out-Null
Start-Transcript -Path $LogFile -Force

try {
    # ----------------------------
    # Gather User Input
    # ----------------------------
    $DomainName = Read-Host "Enter the desired domain name (e.g., corp.local)"
    $DSRMPassword = Read-Host "Enter the DSRM password (used for recovery mode)" -AsSecureString

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
