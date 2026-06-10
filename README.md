# Sigma Rules Collection
 
![Sigma](https://img.shields.io/badge/Sigma-Detection_Rules-blue?style=flat)
![Splunk](https://img.shields.io/badge/Splunk-SPL-000000?style=flat&logo=splunk&logoColor=white)
![Elastic](https://img.shields.io/badge/Elastic-KQL-005571?style=flat&logo=elastic&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
 
Original Sigma detection rules written as part of my 180-day SOC analyst roadmap. Each rule includes the detection logic, the ATT&CK technique it maps to, and notes on false positives.
 
Sigma is a generic signature format for SIEM systems — write once, convert to Splunk SPL, Elastic KQL, or any other query language. These rules were written, tested, and converted as part of Days 20-21 of my roadmap.
 
---

## Rules
 
### Suspicious PowerShell Execution
**File:** `suspicious_powershell.yml`
**Detects:** PowerShell launched with encoded commands or download cradles
**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell
**False positives:** Legitimate IT admin scripts, software deployment tools
 
```yaml
title: Suspicious PowerShell Execution
status: experimental
description: Detects PowerShell execution with encoded commands or download cradles
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'IEX'
            - 'DownloadString'
            - 'FromBase64String'
    condition: selection
falsepositives:
    - Legitimate admin scripts using encoded commands
    - Software deployment tools
level: medium
tags:
    - attack.execution
    - attack.t1059.001
```
 
---
 
### Whoami Execution After Lateral Movement
**File:** `whoami_recon.yml`
**Detects:** whoami.exe being run — common attacker recon step post-compromise
**MITRE:** T1033 — System Owner/User Discovery
**False positives:** IT admin scripts, login scripts
 
```yaml
title: Whoami Execution
status: experimental
description: Detects execution of whoami — common post-exploitation recon
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
falsepositives:
    - Admin scripts
    - Login automation
level: low
tags:
    - attack.discovery
    - attack.t1033
```
 
---
 