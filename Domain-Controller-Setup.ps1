```powershell
# Simple script to turn a Windows Server into a Domain Controller
# Run as Administrator on a fresh install

# Ask for details
$NewName = Read-Host "New computer name"
$IPAddress = Read-Host "Static IP address"
$PrefixLength = Read-Host "Prefix length (e.g. 24)"
$Gateway = Read-Host "Default gateway"
$DNSServer = Read-Host "DNS server (use same as IP if this is the DC)"
$DomainName = Read-Host "New domain name (example: corp.local)"
$SafeModePass = Read-Host "DSRM Safe Mode password" -AsSecureString

Write-Host "Renaming computer to $NewName..."
Rename-Computer -NewName $NewName -Force

Write-Host "Setting static IP..."
$nic = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -DefaultGateway $Gateway
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $DNSServer

Write-Host "Installing AD DS role..."
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Write-Host "Promoting server to Domain Controller..."
Install-ADDSForest `
    -DomainName $DomainName `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $SafeModePass `
    -Force

Write-Host "Done. The server will reboot automatically."
```
