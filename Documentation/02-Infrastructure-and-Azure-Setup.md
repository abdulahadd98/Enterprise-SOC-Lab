# Infrastructure and Azure Setup

## 1. Purpose

This document explains how the infrastructure and cloud-monitoring components of the Hybrid Enterprise SOC Lab were built.

The environment connects a local VMware-based Active Directory domain controller to Microsoft Azure and Microsoft Sentinel using the following pipeline:

```text
VMware Lab
    ↓
DC01 - Windows Server 2019
    ↓
Windows Security Logs + Sysmon
    ↓
Azure Arc
    ↓
Azure Monitor Agent (AMA)
    ↓
Data Collection Rules (DCR)
    ↓
Log Analytics Workspace
    ↓
Microsoft Sentinel
```

The purpose of this design is to monitor an on-premises Windows environment from a cloud SIEM while keeping the actual server inside the local VMware lab.

---

# 2. Lab Infrastructure

## 2.1 VMware Environment

The project uses VMware to host the local enterprise lab.

### Virtual Machines

| System | Purpose | Operating System |
|---|---|---|
| DC01 | Domain Controller, DNS, monitored server | Windows Server 2019 |
| Windows Client | Domain client and authentication testing | Windows 10 |
| Kali Linux | Controlled security testing | Kali Linux |

---

## 2.2 Network Design

The lab network used the `192.168.207.0/24` address space.

### DC01

```text
Hostname: DC01
Domain: corp.local
IP Address: 192.168.207.10
Subnet Mask: 255.255.255.0
Default Gateway: 192.168.207.2
DNS Server: 192.168.207.10
```

The domain controller uses a static IP address because services such as Active Directory and DNS require a stable server address.

### Windows 10 Client

During testing the Windows client used approximately:

```text
IP Address: 192.168.207.128
DNS Server: 192.168.207.10
Domain: corp.local
```

The client points DNS to `DC01` so that it can resolve the Active Directory domain and locate domain services.

---

# 3. Windows Server Preparation

Before integrating the server with Azure, the local Windows infrastructure was verified.

## 3.1 Verify Hostname

Run:

```powershell
hostname
```

Expected result:

```text
DC01
```

---

## 3.2 Verify Network Configuration

Run:

```powershell
ipconfig /all
```

Confirm:

```text
IPv4 Address: 192.168.207.10
Default Gateway: 192.168.207.2
DNS Server: 192.168.207.10
```

---

## 3.3 Verify Domain Controller Discovery

Run:

```cmd
nltest /dsgetdc:corp.local
```

Expected result:

The command should identify `DC01` as a domain controller for `corp.local`.

---

## 3.4 Verify DNS

Run:

```cmd
nslookup corp.local
```

The domain should resolve to the domain controller.

Example:

```text
Name: corp.local
Address: 192.168.207.10
```

---

## 3.5 Verify Active Directory Health

Run:

```cmd
dcdiag
```

For a more focused DNS validation:

```cmd
dcdiag /test:dns
```

The lab passed the required Active Directory and DNS checks before Azure integration.

---

# 4. Time Configuration

Correct system time is important for authentication, event timestamps, and incident investigation.

The Windows Server timezone was configured for India.

Example PowerShell verification:

```powershell
Get-TimeZone
```

The server was configured to use:

```text
India Standard Time
```

The Windows Time service was also configured to use:

```text
time.windows.com
```

Useful commands:

```cmd
w32tm /query /status
```

```cmd
w32tm /query /configuration
```

---

# 5. Azure Resource Group

A dedicated Azure resource group was created for the SOC lab.

```text
Resource Group: rg-soc-lab
Region: Central India
```

Using a dedicated resource group makes the project easier to manage and later clean up.

### Recommended Screenshot

```text
Screenshots/Azure/01-Resource-Group-rg-soc-lab.png
```

Before publishing publicly, ensure subscription identifiers are redacted.

---

# 6. Log Analytics Workspace

A Log Analytics workspace was created for centralized security log storage.

```text
Workspace Name: law-soc-lab
Region: Central India
Resource Group: rg-soc-lab
Pricing: Pay-as-you-go
```

The workspace became the central destination for Windows Security and Sysmon telemetry.

### Why Log Analytics Is Important

Log Analytics provides the data layer used by Microsoft Sentinel.

The project uses Kusto Query Language (KQL) to query telemetry stored in the workspace.

### Recommended Screenshot

```text
Screenshots/Azure/02-Log-Analytics-Workspace.png
```

Redact:

- Subscription ID
- Workspace ID
- Tenant ID
- Unnecessary personal information

---

# 7. Microsoft Sentinel Enablement

Microsoft Sentinel was enabled on:

```text
law-soc-lab
```

This connected the Log Analytics workspace to the SIEM environment used for:

- KQL hunting
- Analytics rules
- Alerts
- Incidents
- MITRE ATT&CK mapping
- Automation rules
- SOC investigation workflows

### Recommended Screenshot

```text
Screenshots/Sentinel/01-Microsoft-Sentinel-Enabled.png
```

---

# 8. Azure Arc Onboarding

## 8.1 Why Azure Arc Was Used

The monitored Windows Server runs locally in VMware rather than as an Azure VM.

Azure Arc allows this non-Azure server to be represented and managed as an Azure-connected machine.

The architecture becomes:

```text
Local Windows Server
        ↓
Azure Arc Connected Machine Agent
        ↓
Azure Management Plane
```

---

## 8.2 Arc Connected Machine

The server `DC01` was onboarded to Azure Arc.

The final connected server was verified through the Azure Arc portal and locally using the Arc agent.

Useful command:

```powershell
azcmagent show
```

This command can display:

- Connection status
- Azure resource information
- Tenant information
- Subscription information
- Machine identifiers

### IMPORTANT PUBLIC-DOCUMENTATION WARNING

Do not publish an unredacted `azcmagent show` screenshot.

Redact:

```text
Subscription ID
Tenant ID
Resource ID
Machine ID
Agent authentication information
Email/account information
```

Suggested sanitized screenshot:

```text
Screenshots/Azure-Arc/01-DC01-Azure-Arc-Connected-REDACTED.png
```

---

# 9. Azure Arc Authentication Troubleshooting

The initial Azure Arc onboarding attempt encountered an authentication restriction.

A device-code authentication flow was blocked by Microsoft Entra security settings.

The onboarding process was then performed using a dedicated service principal for the lab.

## Security Lesson

A service principal secret used during onboarding must be treated as a credential.

During the lab, temporary credentials and elevated permissions were removed after onboarding.

Final cleanup included:

- Removing temporary Contributor access
- Removing the temporary application secret
- Verifying that no active client secret remained

### GitHub Safety Rule

Never commit:

```text
Client secrets
Passwords
Tokens
Private keys
Connection credentials
```

If a secret ever appears in a screenshot, redact the screenshot before publication even if the secret has already been revoked.

---

# 10. Azure Resource Provider Troubleshooting

During Arc onboarding, a resource provider / authorization issue was encountered.

The Arc workflow required the appropriate Azure resource provider to be available for the subscription.

The environment was corrected and Arc onboarding was completed successfully.

This issue is documented because cloud onboarding failures are an important part of real-world infrastructure work.

Suggested screenshot folder:

```text
Screenshots/Troubleshooting/
```

Possible filename:

```text
01-Azure-Arc-Registration-Troubleshooting.png
```

Only use a screenshot if sensitive identifiers have been removed.

---

# 11. Azure Monitor Agent

Azure Monitor Agent (AMA) was deployed to the Arc-enabled server.

AMA is responsible for collecting configured monitoring data and forwarding it to Azure Monitor / Log Analytics.

Architecture:

```text
DC01
 ↓
Azure Arc
 ↓
Azure Monitor Agent
 ↓
Data Collection Rule
 ↓
Log Analytics
```

The agent deployment was verified through Azure after Arc onboarding.

Suggested screenshot:

```text
Screenshots/Azure-Monitor/01-Azure-Monitor-Agent-DC01.png
```

---

# 12. Data Collection Rule

A Data Collection Rule was created for Windows Security telemetry.

```text
DCR Name: dcr-dc01-security-events
Monitored Resource: DC01
Destination: law-soc-lab
Collection Type: Windows Security Events
```

The DCR was associated with the Arc-enabled `DC01` resource.

The rule was configured to collect security events required by the SOC detections.

---

# 13. Windows Security Event Collection

The project used the `SecurityEvent` table for Windows Security auditing.

Events used during the project included:

| Event ID | Description | Project Use |
|---|---|---|
| 4625 | Failed logon | Password guessing / failed authentication |
| 4720 | User account created | New domain account detection |
| 4728 | Member added to global security group | Privileged group change |
| 4729 | Member removed from global security group | Response verification |
| 4740 | User account locked out | Account lockout detection |
| 4767 | User account unlocked | Recovery verification |

---

# 14. Verify SecurityEvent Ingestion

Open Microsoft Sentinel / Log Analytics and run:

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer == "DC01.corp.local"
| take 20
```

Expected result:

Rows from `DC01.corp.local` should appear.

To check specific event IDs:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where EventID in (4625, 4720, 4728, 4729, 4740, 4767)
| project TimeGenerated, Computer, EventID, Activity, TargetAccount, SubjectAccount
| order by TimeGenerated desc
```

### Recommended Screenshot

```text
Screenshots/KQL/01-SecurityEvent-Ingestion-Validation.png
```

---

# 15. Sysmon Installation

Sysmon was installed on `DC01` to provide detailed endpoint telemetry.

Sysmon extends visibility beyond standard Windows Security logs.

The project used Sysmon to observe:

- Process creation
- PowerShell execution
- Command-line arguments
- Parent-child process relationships
- Registry modifications
- Registry deletion

---

# 16. Verify Sysmon Locally

Open:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

Important events used in this project:

```text
Event ID 1  = Process Create
Event ID 12 = Registry object create/delete
Event ID 13 = Registry value set
```

### Recommended Screenshot

```text
Screenshots/Azure-Monitor/02-Sysmon-Operational-Log.png
```

---

# 17. Sysmon Data Ingestion

Sysmon events were successfully ingested into the Log Analytics `Event` table.

To validate:

```kusto
Event
| where TimeGenerated > ago(30m)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
```

Expected result:

Sysmon events from `DC01.corp.local` should appear.

### Recommended Screenshot

```text
Screenshots/KQL/02-Sysmon-Event-Ingestion-Validation.png
```

---

# 18. Validate Sysmon Process Creation

A harmless PowerShell command can be used to generate a test process.

Example:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-TELEMETRY-TEST'"
```

Verify locally in Sysmon:

```text
Event ID 1
```

Then query Sentinel:

```kusto
Event
| where TimeGenerated > ago(30m)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| where RenderedDescription contains "SOC-TELEMETRY-TEST"
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
```

This validates:

```text
Process Execution
    ↓
Sysmon
    ↓
AMA
    ↓
Log Analytics
    ↓
Microsoft Sentinel
```

---

# 19. Final Data Flow

At the end of the setup phase, the working telemetry pipeline was:

```text
┌─────────────────────────────┐
│ VMware Enterprise Lab       │
│                             │
│ Windows 10 ───────┐         │
│ Kali Linux ───────┼────┐    │
│                   │    │    │
│                   ▼    │    │
│              DC01      │    │
│       Windows Server 2019   │
│       AD DS + DNS            │
│       Security Logs          │
│       Sysmon                 │
└──────────────┬──────────────┘
               │
               ▼
          Azure Arc
               │
               ▼
     Azure Monitor Agent
               │
               ▼
    Data Collection Rules
               │
        ┌──────┴───────┐
        ▼              ▼
 SecurityEvent        Event
        │              │
        └──────┬───────┘
               ▼
    Log Analytics Workspace
         law-soc-lab
               │
               ▼
       Microsoft Sentinel
```

---

# 20. Validation Checklist

Before building detection rules, the following checks were completed:

- [x] VMware machines were operational
- [x] DC01 had a static IP address
- [x] Active Directory was healthy
- [x] DNS resolution worked
- [x] Windows client was domain joined
- [x] Domain secure channel worked
- [x] Time configuration was corrected
- [x] Azure resource group created
- [x] Log Analytics workspace created
- [x] Microsoft Sentinel enabled
- [x] DC01 connected through Azure Arc
- [x] Azure Monitor Agent installed
- [x] DCR associated with DC01
- [x] Windows Security events reached `SecurityEvent`
- [x] Sysmon installed
- [x] Sysmon events reached `Event`
- [x] KQL queries returned current DC01 telemetry

At this point the lab was ready for detection engineering.

---

# 21. Troubleshooting Summary

## Problem 1 — Azure Arc Authentication

### Symptom

The initial device-code authentication flow was blocked by tenant security settings.

### Resolution

A dedicated service principal was temporarily used to complete Arc onboarding.

### Security Follow-Up

After onboarding:

- Temporary elevated role assignment was removed.
- Temporary application secret was removed.
- No secret is stored in the public project.

---

## Problem 2 — Azure Resource Registration / Permissions

### Symptom

Arc registration could not complete because the required Azure subscription-level operation was not available under the initial permissions.

### Resolution

Temporary required permissions were granted to complete registration.

After setup, unnecessary privileges were removed.

### Lesson Learned

Cloud onboarding can require permissions at a different scope than normal resource configuration.

Always remove temporary privilege after setup.

---

## Problem 3 — AMA / Data Visibility

### Symptom

Logs did not immediately appear in Sentinel.

### Troubleshooting Steps

The following components were checked:

```text
Arc connection
↓
AMA installation
↓
DCR association
↓
Log Analytics destination
↓
Event source
↓
KQL query time range
```

Telemetry was eventually confirmed in both:

```text
SecurityEvent
Event
```

### Lesson Learned

When troubleshooting SIEM ingestion, validate the pipeline one component at a time instead of changing multiple settings simultaneously.

---

# 22. Security and Privacy Considerations

The following information must not appear in the public GitHub repository:

- Azure client secrets
- Authentication tokens
- Passwords
- Subscription IDs when unnecessary
- Tenant IDs when unnecessary
- Workspace IDs
- Machine IDs
- Private access credentials
- Email addresses unless intentionally public

Screenshots from Azure Arc and Azure portal must be reviewed before upload.

Recommended approach:

```text
Original Screenshot
       ↓
Redact Sensitive Fields
       ↓
Save Sanitized Copy
       ↓
Commit Sanitized Copy Only
```

---

# 23. Evidence Files to Include

Recommended evidence for this section:

```text
Screenshots/Azure/
├── 01-Resource-Group-rg-soc-lab.png
├── 02-Log-Analytics-Workspace.png
└── 03-Microsoft-Sentinel-Workspace.png

Screenshots/Azure-Arc/
├── 01-DC01-Azure-Arc-Connected-REDACTED.png
└── 02-Azure-Arc-Server-Overview-REDACTED.png

Screenshots/Azure-Monitor/
├── 01-Azure-Monitor-Agent-DC01.png
├── 02-Data-Collection-Rule.png
└── 03-DCR-DC01-Association.png

Screenshots/KQL/
├── 01-SecurityEvent-Ingestion-Validation.png
└── 02-Sysmon-Event-Ingestion-Validation.png

Screenshots/Troubleshooting/
└── Selected sanitized troubleshooting evidence
```

Only screenshots that improve the project story should be included.

---

# 24. Build Result

At the end of this phase, the on-premises domain controller was successfully integrated with Azure.

The final working chain was:

```text
DC01
→ Azure Arc
→ Azure Monitor Agent
→ Data Collection Rule
→ Log Analytics
→ Microsoft Sentinel
```

Both Windows Security and Sysmon telemetry were successfully available for KQL analysis.

This infrastructure became the foundation for the next phase:

**Custom Detection Engineering and Analytics Rules**

---

## Complete Screenshot Evidence

All screenshots from this project stage are retained in the detailed public-safe evidence galleries:

- [Azure foundation](../Screenshots/01-Azure-Foundation.md)
- [Azure Arc onboarding](../Screenshots/02-Azure-Arc.md)
- [Azure Monitor / AMA / DCR](../Screenshots/03-Azure-Monitor-AMA-DCR.md)
- [Sysmon setup](../Screenshots/05-Sysmon.md)
- [Troubleshooting](../Screenshots/11-Troubleshooting.md)
- [Security cleanup](../Screenshots/12-Security-Cleanup.md)

