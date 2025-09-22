<#
.SYNOPSIS
    Automated setup of a Domain Controller with Active Directory.
#>

Write-Host "Domain Controller setup script starting. Press any key to continue..."
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

$LogFile = "C:\Setup-DC\setup-dc.log"
New-Item -ItemType Directory -Force -Path "C:\Setup-DC" | Out-Null
Start-Transcript -Path $LogFile -Force

try {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }

    $DomainName = Read-Host "Enter the desired domain name (e.g., corp.local)"
    $DSRMPassword = Read-Host "Enter the DSRM password (used for recovery mode)" -AsSecureString

    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-Host "Installing Active Directory Domain Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
    }

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
}

# --- hard pause so window never closes immediately ---
Write-Host "`nPress Enter to close this window..."
[void][System.Console]::ReadLine()
