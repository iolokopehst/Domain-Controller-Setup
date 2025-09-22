# Windows Server Domain Controller Setup Script

## Overview

This PowerShell script automates the installation of **Active Directory Domain Services (AD DS)** and promotes a Windows Server to a **Domain Controller** for a new forest.  

It is designed to handle common scenarios and ensures the server meets all prerequisites, including:

- Installing the AD DS role if it is not already installed.  
- Ensuring the local Administrator account has a secure password.  
- Skipping promotion if the server is already a Domain Controller.  
- Logging all actions and errors for later review.  

---

## Features

- **Self-Elevating:** Automatically requests administrative privileges if not run as admin.  
- **Automatic AD DS Role Installation:** Installs the AD DS role and management tools if missing.  
- **Administrator Password Check:** Prompts for a secure password if the local Administrator account does not have one.  
- **Domain Controller Promotion:** Promotes the server to a Domain Controller for a new forest.  
- **Error Handling:** Catches and logs errors for troubleshooting.  
- **Logging:** All output is logged to `C:\Setup-DC\setup-dc.log`.  
- **Safe Pauses:** Pauses at key steps so users can read messages and errors.  

---

## Requirements

- **Windows Server 2016/2019/2022** (or newer).  
- **PowerShell 5.1** or higher.  
- Must be run with **administrative privileges**.  
- Recommended to run on a **fresh server** to avoid conflicts.  

---

## Usage

1. Download the `Setup-DC.ps1` script from this repository.  
2. Right-click the script and select **Run with PowerShell** **OR** run from an elevated PowerShell session:  

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\Setup-DC.ps1
