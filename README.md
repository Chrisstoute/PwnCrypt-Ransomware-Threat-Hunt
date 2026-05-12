# Zero-Day PwnCrypt Ransomware Threat Hunt

## Overview

This project documents a threat hunt performed in Microsoft Defender for Endpoint during a simulated zero-day ransomware scenario involving PwnCrypt.

The investigation focused on identifying ransomware-style file activity, PowerShell execution, suspicious script behavior, affected files, device scope, network activity, and related Defender telemetry.

## Scenario

A new ransomware threat named PwnCrypt was reported. The known indicator of compromise was file activity containing the string pwncrypt.

## Tools Used

- Microsoft Defender for Endpoint
- Advanced Hunting
- KQL
- PowerShell
- MITRE ATT&CK Framework
- GitHub documentation

## Key Findings

- pwncrypt.ps1 was observed on the endpoint.
- Business-related files were renamed with the pwncrypt marker.
- cmd.exe launched powershell.exe.
- PowerShell used -ExecutionPolicy Bypass.
- PowerShell executed C:\ProgramData\pwncrypt.ps1.
- PowerShell telemetry showed tool/script download behavior.
- No clear evidence of successful external data exfiltration was confirmed during the reviewed network window.

## Screenshots

Screenshots are stored in the Screenshots folder.

## MITRE ATT&CK Mapping

- T1059.001 - PowerShell
- T1105 - Ingress Tool Transfer
- T1074.001 - Data Staged: Local Data Staging
- T1486 - Data Encrypted for Impact
- T1560.001 - Archive Collected Data: Archive via Utility

## Response Recommendations

- Isolate the affected device.
- Preserve evidence and relevant KQL results.
- Review affected files and recoverability.
- Scope the IOC across all devices.
- Reimage or rebuild the affected VM if required.
- Block confirmed malicious sources in an enterprise environment.
