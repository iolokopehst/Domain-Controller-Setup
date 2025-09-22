<#
.SYNOPSIS
    All-in-one Active Directory installer that can enable built-in Administrator,
    optionally auto-logon as Administrator, and resume to perform Install-ADDSForest.
.DESCRIPTION
    WARNING: enabling AutoAdminLogon stores the Administrator password in the registry
    temporarily (DefaultPassword). This is insecure and only for lab/demo use.
    The script will remove the AutoAdminLogon/DefaultPassword entries after finishing.
.PARAMETER Resume
    Use -Resume when the script is being run after auto-logon to continue AD promotion.
.NOTES
    Run elevated (Administrator). Tested conceptually for Server 2019/2022.
#>

param(
    [switch]$Resume
)

# --- helper to convert SecureString to plaintext (used only when user confirms autologon) ---
function ConvertTo-PlainText([System.Security.SecureString]$ss) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

# --- simple logging helper ---
$LogFile = "C:\Setup-DC\setup-dc.log"
function Log {
    param($msg)
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$t - $msg"
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
}

# Top-level pause so double-click doesn't immediately close
Write-Host "Setup-DC.ps1 — Active Directory automation"
Write-Host "Press any key to continue (or Ctrl-C to cancel)..."
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Top-level error handling so we never close the window before user sees messages
try {
    # -------------------------
    # Ensure C:\Setup-DC exists (for temp data & logs)
    # -------------------------
    if (-not (Test-Path "C:\Setup-DC")) {
        New-Item -Path "C:\Setup-DC" -ItemType Directory -Force | Out-Null
    }

    # -------------------------
    # Admin / DC checks
    # -------------------------
    $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isElevated) {
        Write-Warning "This script must be run with Administrator privileges. Right-click PowerShell -> Run as Administrator and run the script again."
        Log "Script aborted: not elevated."
        exit 1
    }

    # Do not continue if already a domain controller
    $ntdsService = Get-Service -Name ntds -ErrorAction SilentlyContinue
    if ($ntdsService) {
        Write-Warning "This machine already appears to be a Domain Controller (NTDS service found). Aborting."
        Log "Aborted: machine already a domain controller."
        exit 1
    }

    # If running in resume mode, continue promotion steps
    if ($Resume) {
        Log "Resume mode started."

        # Read saved state
        $infoFile = "C:\Setup-DC\setup-info.json"
        if (-not (Test-Path $infoFile)) {
            Write-Error "Cannot find saved state file $infoFile. Ensure you used the script previously to prepare auto-logon or run the script manually as Administrator and choose options again."
            exit 1
        }

        $info = Get-Content $infoFile -Raw | ConvertFrom-Json
        $DomainName = $info.DomainName
        Log "Loaded DomainName: $DomainName"

        # Prompt for DSRM (Safe Mode) password (will be passed as SecureString)
        $SafeModePass = Read-Host "Enter DSRM (Directory Services Restore Mode) password (will not be shown)" -AsSecureString

        try {
            # Install AD DS role if missing
            $adFeature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue
            if (-not $adFeature -or -not $adFeature.Installed) {
                Log "Installing AD-Domain-Services role..."
                Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
                Log "AD-Domain-Services installed."
            } else {
                Log "AD-Domain-Services already installed."
            }

            Log "Starting Install-ADDSForest for domain '$DomainName'..."
            Install-ADDSForest `
                -DomainName $DomainName `
                -CreateDnsDelegation:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -LogPath "C:\Windows\NTDS" `
                -SysvolPath "C:\Windows\SYSVOL" `
                -InstallDns:$true `
                -SafeModeAdministratorPassword $SafeModePass `
                -Force -ErrorAction Stop

            Log "Install-ADDSForest completed (if the command finished without error)."

            # Cleanup: remove AutoAdminLogon and stored password (if present)
            $wlPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            try {
                Set-ItemProperty -Path $wlPath -Name "AutoAdminLogon" -Value "0" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $wlPath -Name "DefaultPassword" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $wlPath -Name "DefaultUserName" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $wlPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue
                Log "AutoAdminLogon keys removed from registry."
            } catch {
                Log "Warning: failed to fully clean autologon registry keys: $_"
            }

            # Remove RunOnce entry if exists
            try {
                $runOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                if (Get-ItemProperty -Path $runOncePath -Name "Setup-DC-Resume" -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $runOncePath -Name "Setup-DC-Resume" -ErrorAction SilentlyContinue
                    Log "Removed RunOnce entry."
                }
            } catch {
                Log "Warning: failed to remove RunOnce entry: $_"
            }

            # Remove temporary state file
            try { Remove-Item -Path $infoFile -Force -ErrorAction SilentlyContinue } catch {}

            Log "Resume flow complete. If Install-ADDSForest triggered a reboot, server will reboot automatically as part of the promotion."
        }
        catch {
            Write-Error "Error during resume AD DS promotion: $_"
            Log "Error during resume: $_"
            exit 1
        }

        exit 0
    }

    # -------------------------
    # Normal initial run
    # -------------------------
    Log "Initial run."

    # Ask for domain name up-front (store for resume)
    $DomainName = Read-Host "Enter the new domain name to create (example: corp.local)"
    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        Write-Error "Domain name is required. Exiting."
        exit 1
    }

    # Option: Enable built-in Administrator and set its password
    $enableAdmin = Read-Host "Do you want to ENABLE the built-in Administrator account (Y/N)?"
    $enableAdmin = $enableAdmin.Trim().ToUpper()
    $useAutoLogon = $false

    if ($enableAdmin -eq 'Y' -or $enableAdmin -eq 'YES') {
        # Prompt password for the built-in Administrator
        $AdminPass = Read-Host "Enter the new password for the local Administrator account (will not be shown)" -AsSecureString
        $AdminPlain = ConvertTo-PlainText $AdminPass

        try {
            Log "Enabling built-in Administrator..."
            & net user Administrator /active:yes | Out-Null
            # Set the password
            & net user Administrator $AdminPlain | Out-Null
            Log "Built-in Administrator enabled and password set."
        }
        catch {
            Write-Error "Failed to enable/set built-in Administrator: $_"
            Log "Failed enabling Administrator: $_"
            exit 1
        }

        # Ask if the user wants fully automated sign-in (AutoAdminLogon)
        $auto = Read-Host "Do you want the script to automatically sign in as the Administrator (AutoAdminLogon) to finish AD installation? THIS STORES THE ADMIN PASSWORD IN THE REGISTRY TEMPORARILY. Type Y to proceed or N to skip."
        if ($auto.Trim().ToUpper() -in @('Y','YES')) {
            $useAutoLogon = $true
            # Warn again and require confirmation
            Write-Warning "You chose to enable AutoAdminLogon. The Administrator password will be written into the registry (DefaultPassword) temporarily. This is insecure. Only use for lab/demo. Continue? (Y/N)"
            $confirm = Read-Host
            if ($confirm.Trim().ToUpper() -notin @('Y','YES')) {
                Write-Warning "Auto-logon aborted by user. The script will not perform the automated sign-in flow. You will need to sign in as an Administrator and run this script again with -Resume to continue AD installation."
                $useAutoLogon = $false
                # Clear plain var
                $AdminPlain = $null
            }
        } else {
            # Clear plain var
            $AdminPlain = $null
        }
    }

    # Save state to file for resume
    $state = @{ DomainName = $DomainName }
    $state | ConvertTo-Json | Out-File -FilePath "C:\Setup-DC\setup-info.json" -Encoding UTF8

    # Copy script itself to C:\Setup-DC so RunOnce can execute it after auto-login
    $scriptSource = $MyInvocation.MyCommand.Definition
    $scriptDest = "C:\Setup-DC\Setup-DC.ps1"
    try {
        Copy-Item -Path $scriptSource -Destination $scriptDest -Force
        Log "Copied script to $scriptDest"
    } catch {
        Write-Error "Failed to copy script to C:\Setup-DC: $_"
        Log "Failed to copy script: $_"
        exit 1
    }

    # If user chose AutoAdminLogon, set registry keys and create RunOnce to resume
    if ($useAutoLogon) {
        try {
            $wlPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $computerName = $env:COMPUTERNAME

            Set-ItemProperty -Path $wlPath -Name "DefaultUserName" -Value "Administrator" -Force
            Set-ItemProperty -Path $wlPath -Name "DefaultDomainName" -Value $computerName -Force
            Set-ItemProperty -Path $wlPath -Name "DefaultPassword" -Value $AdminPlain -Force
            Set-ItemProperty -Path $wlPath -Name "AutoAdminLogon" -Value "1" -Force
            Log "AutoAdminLogon registry keys set (temporary)."

            # Create RunOnce entry to run the script at next logon with -Resume
            $runOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptDest`" -Resume"
            Set-ItemProperty -Path $runOncePath -Name "Setup-DC-Resume" -Value $cmd -Force
            Log "RunOnce entry created to resume script after auto-logon."
        }
        catch {
            Write-Error "Failed to setup AutoAdminLogon/RunOnce: $_"
            Log "Failed to setup autologon/RunOnce: $_"
            # clear admin plaintext
            $AdminPlain = $null
            exit 1
        }

        # Clear AdminPlain variable as best-effort
        $AdminPlain = $null

        Write-Host "`nThe system will sign out now. When the machine signs in automatically as Administrator, the script will resume and complete AD installation."
        Write-Host "If you prefer to sign in manually instead, DO NOT proceed; run the script again after you sign in as Administrator using: powershell -ExecutionPolicy Bypass -File `"$scriptDest`" -Resume"
        Start-Sleep -Seconds 5

        # Sign out (logoff) to trigger auto-login
        try {
            Log "Signing out current user to allow auto-logon of Administrator..."
            shutdown.exe /l /f
        }
        catch {
            Write-Error "Failed to log off: $_"
            Log "Failed to log off: $_"
        }

        # script will exit now because machine will log off
        exit 0
    }
    else {
        # AutoLogon not chosen: instruct user to sign in as Administrator and run with -Resume
        Write-Host ""
        Write-Host "Auto-logon was not configured. To continue AD installation:"
        Write-Host "  1) Sign out and sign in as an Administrator account (built-in Administrator or another admin)."
        Write-Host "  2) Run this script copied to C:\Setup-DC\Setup-DC.ps1 with the -Resume switch:"
        Write-Host "       powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Setup-DC\Setup-DC.ps1 -Resume"
        Write-Host ""
        Log "Auto-logon not enabled. Awaiting manual admin login and resume."
    }

    # end initial run
}
catch {
    Write-Error "A fatal error occurred: $_"
    try { Add-Content -Path $LogFile -Value ("ERROR: " + $_.ToString()) -ErrorAction SilentlyContinue } catch {}
}
finally {
    Write-Host "`nScript finished. Press any key to exit..."
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
