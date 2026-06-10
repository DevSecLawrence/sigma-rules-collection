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
 
### New Local Admin Account Created
**File:** `new_local_admin.yml`
**Detects:** Creation of a new local administrator account — common persistence technique
**MITRE:** T1136.001 — Create Account: Local Account
**False positives:** Legitimate IT provisioning
 
```yaml
title: New Local Admin Account Created
status: experimental
description: Detects creation of a new local administrator account
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
falsepositives:
    - Legitimate user provisioning by IT
level: medium
tags:
    - attack.persistence
    - attack.t1136.001
```
 
---
 
## Conversion
 
These rules were converted to Splunk SPL and Elastic KQL using `sigma-cli`. Converted queries are in the `converted/` folder.
 
---
 
## Part of
 
[SOC Analyst Journey — 180-day roadmap](https://github.com/DevSecLawrence/soc-analyst-journey)