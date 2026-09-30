# Security Project

The public repository for my security project. Originally created as a personal project, this repository focuses on building tools to help scan and protect personal computers.

## Current Tool

The project currently includes PowerShell verification scripts for running processes and Windows services. They collect system information and highlight activity that may require further investigation.

The script can:

- Capture process metadata, parent processes, owners, services, and network connections
- Prioritize known LOLBins and processes running from user-writable locations
- Detect encoded PowerShell-style command lines
- Identify suspicious processes launched by Microsoft Office applications
- Check executable digital signatures and calculate SHA-256 hashes
- Optionally collect loaded modules
- Export results in both JSON and CSV formats

The service-verification script can:

- Capture service configuration, startup mode, account, dependencies, and state
- Link services to their running processes and network connections
- Flag services using writable paths, unquoted paths, missing executables, or command interpreters
- Check service executable digital signatures and calculate SHA-256 hashes
- Export results in both JSON and CSV formats

## Requirements

- Windows
- PowerShell 5.1 or later
- Administrator privileges are recommended for the most complete results

## Usage

Run the script from PowerShell:

```powershell
.\ps_scripts\processVerificationScript.ps1 -OutputDir .\results
```

To skip module collection:

```powershell
.\ps_scripts\processVerificationScript.ps1 -OutputDir .\results -SkipModules
```

To inspect Windows services:

```powershell
.\ps_scripts\serviceVerificationScript.ps1 -OutputDir .\results
```

To skip service network-connection collection:

```powershell
.\ps_scripts\serviceVerificationScript.ps1 -OutputDir .\results -SkipNetworkConnections
```

The process script creates timestamped `ProcessSnapshot_*.json` and `ProcessSnapshot_*.csv` files. The service script creates `ServiceSnapshot_*.json` and `ServiceSnapshot_*.csv` files in the selected output directory.

## Project Structure

```text
.
├── documentation/
│   └── useCase.drawio
└── ps_scripts/
    ├── processVerificationScript.ps1
    └── serviceVerificationScript.ps1
```

## Disclaimer

This project is intended for defensive security research, system inspection, and educational use on computers you own or are authorized to assess. The results are indicators for investigation, not proof that a process or service is malicious.
