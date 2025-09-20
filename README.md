# Setup-DC.ps1

This script automates turning a fresh Windows Server into a **Domain Controller** with **Active Directory Domain Services (AD DS)** and **DNS**.

## 🚀 Quick Start

1. Go to this repository and download **`Domain-Controler-Setup.ps1`**.
2. On your Windows Server, right-click the file → **Run with PowerShell (as Administrator)**.
3. Enter the prompts (computer name, IP details, domain name, Safe Mode password).
4. The server will reboot automatically as a **Domain Controller**.

## ✨ What It Does

* Renames the computer
* Sets static IP and DNS
* Installs AD DS + DNS roles
* Promotes the server as a new forest root Domain Controller
