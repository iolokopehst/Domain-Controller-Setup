<#
.SYNOPSIS
    Fully automated Windows Server AD DS setup script.
.DESCRIPTION
    - Adaptive static IP configuration
    - Computer rename with automatic reboot handling
    - AD DS role check and installation
    - Domain Controller promotion
    - Full error handling
.NOTES
    Run as Administrator on a fresh or partially configured Windows Server.
#>

try {
    # ----------------------------
    # Admin Check
    # ----------------------------
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'. Exiting..."
        Start-Sleep -Seconds 5
        exit
    }

    # ----------------------------
    # Marker file for reboot/resume
    # ----------------------------
    $MarkerPath = "C:\Temp\DC-Promotion-Phase2.txt"

    # ----------------------------
    # Resume after reboot
    # ----------------------------
    if (Test-Path $MarkerPath) {
        Write-Host "`nResuming Domain Controller promotion after reboot..."
        Remove-Item $MarkerPath -Force

        try {
            # Install AD DS if not already installed
            if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
                Write-Host "Installing AD DS role..."
                Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
            }

            Write-Host "Promoting server to Domain Controller..."
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

            Write-Host "`nDomain Controller promotion completed successfully!"
        }
        catch {
            Write-Error "Error during DC promotion: $_"
        }

        exit
    }

    # ----------------------------
    # Phase 1: Prompt for Input
    # ----------------------------
    $NewName      = Read-Host "Enter new computer name"
    $DomainName   = Read-Host "Enter new domain name (e.g., corp.local)"
    $SafeModePass = Read-Host "Enter DSRM Safe Mode password" -AsSecureString

    # ----------------------------
    # Phase 1: Rename Computer (if needed)
    # ----------------------------
    $currentName = $env:COMPUTERNAME
    if ($currentName -ne $NewName) {
        try {
            Rename-Computer -NewName $NewName -Force -ErrorAction Stop
            Write-Host "Computer renamed to $NewName."
            $RenameRebootRequired = $true
        }
        catch {
            Write-Error "Failed to rename computer: $_"
        }
    } else {
        Write-Host "Computer name is already $NewName. Skipping rename."
        $RenameRebootRequired = $false
    }

    # ----------------------------
    # Phase 1: Configure Static IP if missing
    # ----------------------------
    $NIC = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    $HasStaticIP = (Get-NetIPAddress -InterfaceIndex $NIC.ifIndex -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -eq "Manual" })

    if (-not $HasStaticIP) {
        Write-Host "`nNo static IP found. Please enter static IP details."
        $IPAddress    = Read-Host "Enter static IP address (e.g., 192.168.1.10)"
        $PrefixLength = Read-Host "Enter prefix length (e.g., 24 for /24)"
        $Gateway      = Read-Host "Enter default gateway (e.g., 192.168.1.1)"
        $DNSServer    = Read-Host "Enter DNS server (use same as this DC, e.g., $IPAddress)"

        try {
            # Remove existing IPv4 addresses
            Get-NetIPAddress -InterfaceIndex $NIC.ifIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

            # Assign static IP
            New-NetIPAddress -InterfaceIndex $NIC.ifIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -DefaultGateway $Gateway -ErrorAction Stop

            # Set DNS
            Set-DnsClientServerAddress -InterfaceIndex $NIC.ifIndex -ServerAddresses $DNSServer -ErrorAction Stop

            Write-Host "Static IP and DNS configured."
        }
        catch {
            Write-Error "Failed to configure network settings: $_"
        }
    } else {
        Write-Host "Static IP already exists. Skipping IP configuration."
    }

    # ----------------------------
    # Prepare for reboot if rename occurred
    # ----------------------------
    if ($RenameRebootRequired) {
        try {
            if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" | Out-Null }
            New-Item -ItemType File -Path $MarkerPath -Force | Out-Null

            Write-Host "`nRebooting server to apply computer rename and continue DC promotion..."
            Start-Sleep -Seconds 5
            Restart-Computer
        }
        catch {
            Write-Error "Failed to reboot server: $_"
        }
    }
    else {
        # Rename not needed, proceed directly
        try {
            if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
                Write-Host "Installing AD DS role..."
                Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
            }

            Write-Host "Promoting server to Domain Controller..."
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

            Write-Host "`nDomain Controller promotion completed successfully!"
        }
        catch {
            Write-Error "Error during DC promotion: $_"
        }
    }
}
catch {
    Write-Error "A fatal error occurred in the script: $_"
}
finally {
    Write-Host "`nScript finished. Press any key to exit..."
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
