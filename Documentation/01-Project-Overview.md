# Hybrid Enterprise SOC, Threat Detection & Incident Response Lab

## Project Overview

This project demonstrates the design, deployment, monitoring, detection, investigation, response, threat-hunting, and automation workflow of a small hybrid enterprise Security Operations Center (SOC) lab.

The environment combines an on-premises Active Directory lab running in VMware with Microsoft Azure and Microsoft Sentinel. The project was designed to simulate how a SOC analyst monitors a Windows enterprise environment, detects suspicious activity, investigates incidents, validates containment actions, performs threat hunting, maps detections to MITRE ATT&CK, and automates repetitive investigation tasks.

The lab was built around a Windows Server 2019 domain controller named `DC01`, a Windows 10 domain-joined client, and a Kali Linux testing machine. The domain controller was connected to Azure using Azure Arc. Windows Security events and Sysmon telemetry were collected through Azure Monitor Agent and Data Collection Rules, stored in a Log Analytics workspace, and analyzed in Microsoft Sentinel.

The project focuses on practical SOC skills rather than only infrastructure deployment. Controlled security events were generated inside the lab and followed through the complete lifecycle:

**Generate Activity → Collect Logs → Detect → Alert → Create Incident → Investigate → Hunt → Respond → Verify → Automate**

---

## Why This Project Was Built

The goal of this project was to create a realistic hands-on SOC environment that demonstrates both infrastructure and security operations skills.

The project was designed to show practical experience with:

- Active Directory administration
- Windows security auditing
- Sysmon telemetry
- Azure Arc
- Azure Monitor Agent
- Data Collection Rules
- Log Analytics
- Microsoft Sentinel
- Kusto Query Language (KQL)
- Custom analytics rules
- Incident investigation
- Threat hunting
- MITRE ATT&CK mapping
- Containment and recovery
- SOC automation
- Security documentation

This project complements the separate Active Directory enterprise infrastructure lab by adding centralized monitoring, detection engineering, investigation, response, and automation capabilities.

---

## Project Objectives

The primary objectives were to:

- Build a small enterprise Active Directory environment.
- Create realistic Windows users, groups, permissions, and policies.
- Connect an on-premises Windows Server to Microsoft Azure.
- Collect Windows Security logs from the domain controller.
- Deploy Sysmon for enhanced endpoint visibility.
- Ingest security telemetry into a Log Analytics workspace.
- Enable Microsoft Sentinel for SIEM monitoring.
- Build custom KQL queries for security analysis.
- Create custom Sentinel analytics rules.
- Simulate controlled security events.
- Generate and investigate Sentinel incidents.
- Perform proactive threat hunting across collected telemetry.
- Map detections to the MITRE ATT&CK framework.
- Perform containment and recovery actions.
- Verify remediation through security logs.
- Implement automated SOC investigation tasks.
- Document the entire SOC detection and response lifecycle.
- Produce a GitHub-ready portfolio project with screenshots, KQL, detection rules, incident reports, and architecture diagrams.

---

## High-Level Architecture

The lab follows a hybrid architecture.

```text
Windows 10 Client / Kali Linux
            |
            | Authentication / Test Activity
            v
         DC01
Windows Server 2019
Active Directory + DNS
Windows Security Logs + Sysmon
            |
            v
        Azure Arc
            |
            v
   Azure Monitor Agent
            |
            v
  Data Collection Rules
            |
      +-----+------+
      |            |
      v            v
SecurityEvent     Event
  Table           Table
      |            |
      +-----+------+
            |
            v
   Log Analytics Workspace
       law-soc-lab
            |
            v
    Microsoft Sentinel
            |
    +-------+--------+----------------+
    |                |                |
    v                v                v
KQL Hunting     Analytics Rules    Incidents
                    |                |
                    v                v
              MITRE Mapping     Investigation
                                     |
                                     v
                               Response Actions
                                     |
                                     v
                              SOC Automation
                                     |
                                     v
                           Investigation Tasks
```

Two architecture diagrams are maintained in the repository:

- Main white-background GitHub architecture diagram
- Dark technical architecture diagram

These diagrams visually represent the same telemetry and incident-response flow shown above.

---

## Lab Environment

### 1. Domain Controller

| Item | Configuration |
|---|---|
| Hostname | `DC01` |
| Operating System | Windows Server 2019 |
| Domain | `corp.local` |
| IP Address | `192.168.207.10/24` |
| Default Gateway | `192.168.207.2` |
| Primary Roles | Active Directory Domain Services, DNS |
| Security Monitoring | Windows Security Auditing, Sysmon |
| Cloud Connection | Azure Arc |
| Telemetry Agent | Azure Monitor Agent |

The domain controller serves as the central infrastructure and monitoring target for the project.

It provides:

- Active Directory authentication
- DNS services
- User and group management
- Security group management
- Group Policy processing
- Windows Security auditing
- Sysmon telemetry
- Security events used by Sentinel detections

### 2. Windows 10 Domain Client

| Item | Configuration |
|---|---|
| Hostname | `DESKTOP-82C5TLV` |
| Operating System | Windows 10 |
| Domain | `corp.local` |
| IP Address during testing | Approximately `192.168.207.128` |
| DNS Server | `192.168.207.10` |

The Windows client was used for domain authentication, failed-password testing, account-lockout generation, file-share access validation, Group Policy testing, Active Directory access testing, and controlled user activity.

### 3. Kali Linux

Kali Linux was used as a controlled security-testing system inside the VMware lab.

Its purpose included Active Directory enumeration, SMB testing, permission validation, security-control validation, and controlled offensive-security testing.

The project does not treat Kali as a monitored production endpoint. It is primarily a testing system used to generate or validate activity against the enterprise lab.

---

## Active Directory Foundation

The SOC project was built on top of a working enterprise Active Directory environment.

The environment included:

- Domain: `corp.local`
- Domain Controller: `DC01`
- Organizational Units: IT, HR, Finance, Management, Workstations
- Security groups: HR-SG, Finance-SG, Management-SG
- Departmental file shares
- NTFS and share permissions
- Group Policy Objects
- Password policy
- Account lockout policy
- Domain-joined Windows client
- Shared printer testing

This foundation allowed the SOC project to monitor realistic Active Directory events rather than isolated standalone Windows events.

---

## Azure Resources

The Azure portion of the project was deployed in a dedicated resource group.

| Resource | Configuration |
|---|---|
| Resource Group | `rg-soc-lab` |
| Region | Central India |
| Log Analytics Workspace | `law-soc-lab` |
| SIEM | Microsoft Sentinel |
| Hybrid Connection | Azure Arc |
| Monitoring Agent | Azure Monitor Agent |
| Collection Method | Data Collection Rules |

Sensitive Azure identifiers such as subscription IDs, tenant IDs, workspace IDs, machine IDs, and credentials are intentionally excluded from the public documentation.

---

## Azure Arc Integration

`DC01` was connected to Azure as an Azure Arc-enabled server.

Azure Arc allowed the on-premises VMware server to appear as an Azure-managed machine while remaining inside the local lab.

The Arc connection was used to enable Azure Monitor Agent deployment, Azure monitoring integration, Data Collection Rule association, and centralized security telemetry ingestion.

---

## Azure Monitor Agent

Azure Monitor Agent (AMA) was used as the primary telemetry collection agent.

AMA collected configured security data from `DC01` and forwarded it to the Log Analytics workspace.

---

## Data Collection Rules

A Data Collection Rule was created to define which Windows Security events should be collected from `DC01`.

Primary DCR:

`dcr-dc01-security-events`

The DCR was associated with the Arc-enabled domain controller.

This provided centralized control over telemetry collection and ensured that security events from the lab reached the Log Analytics workspace.

---

## Log Analytics Workspace

Workspace:

`law-soc-lab`

The Log Analytics workspace acts as the centralized log store for the project.

Security data from `DC01` was queried using Kusto Query Language.

Two important tables were used.

### SecurityEvent

The `SecurityEvent` table contains Windows Security auditing events.

| Event ID | Description |
|---|---|
| 4625 | Failed logon |
| 4720 | User account created |
| 4728 | Member added to a privileged group |
| 4729 | Member removed from a privileged group |
| 4740 | User account locked out |
| 4767 | User account unlocked |

### Event

The `Event` table was used to store Sysmon telemetry collected from `Microsoft-Windows-Sysmon/Operational`.

| Sysmon Event ID | Description |
|---|---|
| 1 | Process creation |
| 12 | Registry object create/delete activity |
| 13 | Registry value modification |

---

## Sysmon Monitoring

Sysmon was installed on `DC01` to provide deeper endpoint telemetry than standard Windows Security logs alone.

Sysmon was used to monitor:

- Process execution
- PowerShell command lines
- Parent-child process relationships
- Registry persistence activity
- Registry value modification
- Registry value deletion

The Sysmon logs were successfully ingested into Microsoft Sentinel through the `Event` table.

---

## Microsoft Sentinel

Microsoft Sentinel was enabled on the Log Analytics workspace.

Sentinel was used for:

- Centralized security monitoring
- KQL hunting
- Custom analytics rules
- Security alerts
- Incident generation
- Incident investigation
- MITRE ATT&CK mapping
- Automation rules
- Investigation-task automation

The project intentionally focused on custom detections that could be validated directly inside the lab.

---

## Detection Engineering

Six custom analytics rules were created and tested.

### Detection 1 — Repeated Failed Logons

Purpose: detect repeated authentication failures that may indicate password guessing.

Primary event: `4625`

MITRE ATT&CK: `T1110.001 - Password Guessing`

### Detection 2 — New Active Directory User Created

Purpose: detect creation of new Active Directory domain accounts.

Primary event: `4720`

MITRE ATT&CK: `T1136.002 - Create Account: Domain Account`

### Detection 3 — Privileged AD Group Membership Change

Purpose: detect when an account is added to a privileged Active Directory group.

Primary event: `4728`

MITRE ATT&CK: `T1098.007 - Additional Local or Domain Groups`

The test account was later removed from the privileged group and Event ID `4729` was used to verify remediation.

### Detection 4 — Suspicious PowerShell Command Execution

Purpose: detect suspicious PowerShell command-line patterns using Sysmon process telemetry.

Primary Sysmon event: `1`

Indicators tested included:

- `ExecutionPolicy Bypass`
- `NoProfile`
- `EncodedCommand`
- `-enc`
- Hidden PowerShell execution patterns

MITRE ATT&CK: `T1059.001 - PowerShell`

This rule was also used as the trigger for SOC automation testing.

### Detection 5 — Registry Run-Key Persistence

Purpose: detect changes to Windows Registry Run keys that may be used for persistence.

Primary Sysmon events: `13` and `12`

MITRE ATT&CK: `T1547.001 - Registry Run Keys / Startup Folder`

A harmless registry persistence value was created and later removed as part of the response exercise.

### Detection 6 — Active Directory Account Lockout

Purpose: detect account-lockout events and identify the affected account and caller computer.

Primary event: `4740`

Supporting events: `4625` and `4767`

MITRE ATT&CK context: `T1110.001 - Password Guessing`

The lockout itself is not treated as a separate ATT&CK technique. In this project, the lockout was generated by controlled repeated password failures.

---

## Controlled Security Simulations

All security events were generated inside an authorized isolated lab.

Simulations included:

- Repeated incorrect password attempts
- New domain-user creation
- Addition of a test user to Domain Admins
- Suspicious PowerShell command execution
- Registry Run-key persistence
- Active Directory account lockout

These simulations were intentionally harmless and were used only to validate defensive monitoring.

---

## Threat Hunting

Five core threat-hunting scenarios were completed.

### Hunt 1 — Failed Logon Analysis

Goal: identify accounts with repeated failed authentication attempts and source IP addresses.

The hunt highlighted repeated failures for `test-user`, `soc-test`, `Administrator`, and `hr-user`.

### Hunt 2 — Active Directory Account and Group Changes

Goal: review account creation and security group membership activity.

The hunt included Events `4720`, `4728`, `4729`, and related group-management events.

### Hunt 3 — Suspicious PowerShell Activity

Goal: identify suspicious PowerShell processes using Sysmon Event ID `1`.

The query extracted the user, process image, command line, and parent process.

### Hunt 4 — Registry Persistence

Goal: identify registry activity targeting Windows Run-key locations.

The hunt used Sysmon Events `12` and `13` and showed both persistence creation and removal.

### Hunt 5 — Account Lockout and Recovery

Goal: review the complete authentication lifecycle around a test account.

The hunt summarized Events `4625`, `4740`, and `4767`, allowing the incident timeline to be reconstructed using centralized logs.

---

## Incident Investigation

The project generated multiple Sentinel incidents from controlled security events.

Investigation activities included:

- Reviewing incident severity
- Reviewing alert evidence
- Identifying affected users
- Identifying source computers
- Reviewing process command lines
- Reviewing parent processes
- Reviewing registry paths
- Reviewing account changes
- Correlating events across telemetry sources
- Classifying security-testing incidents
- Resolving completed incidents

The project demonstrates how raw events are converted into actionable SOC incidents.

---

## Incident Response Exercises

Three major response exercises were completed.

### Response Exercise 1 — Privileged Group Membership

A controlled test user was added to `Domain Admins`.

Response:

- Investigated the privileged-group change
- Removed the user from the privileged group
- Verified removal through Event ID `4729`

### Response Exercise 2 — Registry Persistence

A harmless Run-key persistence value was created.

Response:

- Investigated the registry modification
- Removed the persistence value
- Verified removal through Sysmon Event ID `12`

### Response Exercise 3 — Account Lockout

The `test-user` account was intentionally locked after repeated invalid authentication attempts.

Response:

- Investigated Event ID `4740`
- Confirmed the affected user and caller computer
- Unlocked the account
- Verified `badPwdCount = 0`
- Verified `LockedOut = False`
- Confirmed recovery using Event ID `4767`
- Verified that the recovery event reached Microsoft Sentinel

---

## MITRE ATT&CK Coverage

| Detection | MITRE Technique | Tactic |
|---|---|---|
| Repeated Failed Logons | T1110.001 Password Guessing | Credential Access |
| New AD User Created | T1136.002 Domain Account | Persistence |
| Privileged AD Group Change | T1098.007 Additional Local or Domain Groups | Persistence / Privilege Escalation |
| Suspicious PowerShell | T1059.001 PowerShell | Execution |
| Registry Run-Key Persistence | T1547.001 Registry Run Keys / Startup Folder | Persistence / Privilege Escalation |
| AD Account Lockout | T1110.001 Password Guessing context | Credential Access |

Detailed mapping is maintained separately in `MITRE-ATTACK/MITRE-ATTACK-Mapping.md`.

---

## SOAR / Automation

Microsoft Sentinel automation was implemented to improve incident triage.

A Standard automation rule was created:

`SOC PowerShell Investigation Tasks`

Trigger:

`When incident is created`

Condition:

The incident must be generated from the `Suspicious PowerShell Command Execution` analytics rule.

Three tasks are automatically added to new matching incidents:

1. Review PowerShell process and command line
2. Check related events and persistence indicators
3. Contain, document, and close the incident

The automation was validated with a fresh controlled PowerShell execution.

The event was captured by Sysmon, ingested into Sentinel, detected by the PowerShell analytics rule, converted into a new incident, processed by the automation rule, and automatically assigned all three investigation tasks.

This demonstrated a working detection-to-automation workflow.

---

## Detection-to-Response Lifecycle

```text
Security Activity
        ↓
Endpoint / AD Telemetry
        ↓
Azure Monitor Agent
        ↓
Log Analytics
        ↓
Microsoft Sentinel
        ↓
KQL Detection
        ↓
Security Alert
        ↓
Incident
        ↓
Investigation
        ↓
Threat Hunting
        ↓
Containment / Recovery
        ↓
Verification
        ↓
Automation
```

---

## Skills Demonstrated

### Infrastructure

- Windows Server administration
- Active Directory
- DNS
- Group Policy
- Windows networking
- VMware

### Cloud

- Microsoft Azure
- Azure Arc
- Azure Monitor
- Azure Monitor Agent
- Log Analytics
- Data Collection Rules

### Security Operations

- SIEM monitoring
- Microsoft Sentinel
- Security log analysis
- Incident triage
- Incident investigation
- Threat hunting
- Detection engineering
- Security event correlation
- Containment and recovery
- SOC automation

### Detection Engineering

- Kusto Query Language
- Windows Security events
- Sysmon telemetry
- Custom Sentinel analytics rules
- Entity extraction
- Custom alert details
- MITRE ATT&CK mapping

### Security Testing

- Controlled authentication testing
- Active Directory account testing
- Group membership testing
- PowerShell execution testing
- Registry persistence testing
- Security-control validation

---

## Evidence Collected

The repository includes screenshots documenting major project milestones.

Evidence categories include:

- Azure configuration
- Azure Arc onboarding
- Azure Monitor Agent
- Data Collection Rules
- Log Analytics
- Microsoft Sentinel
- KQL queries
- Analytics rules
- Security incidents
- Incident investigations
- Threat hunting
- Response actions
- SOAR automation
- Troubleshooting

Sensitive information should be redacted before publishing screenshots publicly.

Redaction targets include:

- Azure subscription IDs
- Tenant IDs
- Workspace IDs
- Machine/resource IDs
- Email addresses where unnecessary
- Authentication secrets
- Access tokens

No exposed client secret should ever be committed to GitHub.

---

## Repository Structure

```text
Enterprise-SOC-Lab/
│
├── README.md
│
├── Architecture/
│   ├── Enterprise-SOC-Architecture.png
│   ├── Enterprise-SOC-Architecture-Dark.png
│   └── Architecture-Explanation.md
│
├── Documentation/
│   ├── 01-Project-Overview.md
│   ├── 02-Infrastructure-and-Azure-Setup.md
│   ├── 03-Detection-Rules.md
│   ├── 04-Threat-Hunting.md
│   ├── 05-Incident-Investigation.md
│   ├── 06-Response-and-Containment.md
│   ├── 07-SOAR-Automation.md
│   └── 08-Troubleshooting-and-Lessons.md
│
├── KQL/
│   ├── 01-Failed-Logon-Hunt.kql
│   ├── 02-AD-Account-and-Group-Changes-Hunt.kql
│   ├── 03-Suspicious-PowerShell-Hunt.kql
│   ├── 04-Registry-Persistence-Hunt.kql
│   └── 05-Account-Lockout-Recovery-Timeline.kql
│
├── Detection-Rules/
├── MITRE-ATTACK/
│   └── MITRE-ATTACK-Mapping.md
├── Incident-Reports/
├── Screenshots/
│   ├── Azure/
│   ├── Azure-Arc/
│   ├── Azure-Monitor/
│   ├── Sentinel/
│   ├── KQL/
│   ├── Detection/
│   ├── Incidents/
│   ├── Investigation/
│   ├── Response/
│   ├── Threat-Hunting/
│   ├── Automation/
│   └── Troubleshooting/
└── Automation/
```

---

## Project Outcome

The project successfully demonstrated an end-to-end hybrid SOC environment.

The final environment was able to:

- Monitor an on-premises Active Directory server from Azure.
- Collect both Windows Security and Sysmon telemetry.
- Store and query security logs in Log Analytics.
- Detect six different security behaviors using custom Sentinel analytics.
- Generate actionable security incidents.
- Investigate incidents using centralized telemetry.
- Perform five proactive threat hunts.
- Map detections to MITRE ATT&CK.
- Perform and verify containment actions.
- Automate incident investigation tasks.
- Document evidence suitable for a professional GitHub portfolio.

The result is a practical blue-team project demonstrating the complete workflow from infrastructure and telemetry collection to detection engineering, investigation, response, threat hunting, and SOC automation.

---

## Authorized Lab Use

All security testing documented in this project was performed inside a privately controlled and authorized lab environment.

No production system or third-party environment was targeted.

The attack simulations were intentionally limited to safe validation of defensive controls and telemetry.

---

## Next Documentation Sections

The remaining technical documentation expands on this overview:

1. Infrastructure and Azure Setup
2. Detection Rules
3. Threat Hunting
4. Incident Investigation
5. Response and Containment
6. SOAR Automation
7. Troubleshooting and Lessons Learned
8. Final GitHub README and project packaging


---

## Complete Command and Evidence References

Every command-line action used in the build, testing, response and troubleshooting phases is consolidated here:

[`../Commands/Complete-Command-Reference.md`](../Commands/Complete-Command-Reference.md)

Every project screenshot provided during the build has been retained and organized here:

[`../Screenshots/README.md`](../Screenshots/README.md)

The repository intentionally uses public-safe redacted versions of screenshots that originally exposed Azure credentials or unique cloud identifiers.
