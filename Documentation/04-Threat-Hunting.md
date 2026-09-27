# Threat Hunting

## 1. Purpose

This document records the proactive threat-hunting phase of the Hybrid Enterprise SOC Lab.

Unlike scheduled analytics rules, which automatically generate alerts when predefined conditions are met, threat hunting is an analyst-driven process used to search telemetry for suspicious patterns, reconstruct activity, validate hypotheses, and discover relationships between events.

The lab used Microsoft Sentinel and Kusto Query Language (KQL) to perform five core hunts across Windows Security and Sysmon telemetry.

The hunting workflow followed this model:

```text
Security Question
      ↓
Select Data Source
      ↓
Write KQL Query
      ↓
Review Results
      ↓
Identify Patterns
      ↓
Correlate Related Events
      ↓
Document Findings
      ↓
Escalate / Respond if Needed
```

---

# 2. Threat-Hunting Data Sources

Two primary Microsoft Sentinel tables were used.

## SecurityEvent

Used for Windows Security auditing, including:

```text
4625 - Failed logon
4720 - User account created
4728 - Member added to a security group
4729 - Member removed from a security group
4732 - Member added to a local security group
4733 - Member removed from a local security group
4740 - User account locked out
4756 - Member added to a universal security group
4757 - Member removed from a universal security group
4767 - User account unlocked
```

## Event

Used for Sysmon telemetry from:

```text
Microsoft-Windows-Sysmon/Operational
```

Important Sysmon events used during hunting:

```text
1  - Process creation
12 - Registry object create/delete
13 - Registry value modification
```

---

# 3. Hunt Summary

| Hunt | Objective | Main Data Source | Key Events |
|---|---|---|---|
| 1 | Failed logon analysis | SecurityEvent | 4625 |
| 2 | AD account and group changes | SecurityEvent | 4720, 4728, 4729, 4732, 4733, 4756, 4757 |
| 3 | Suspicious PowerShell activity | Event / Sysmon | 1 |
| 4 | Registry persistence activity | Event / Sysmon | 12, 13 |
| 5 | Account lockout and recovery timeline | SecurityEvent | 4625, 4740, 4767 |

---

# 4. Hunt 1 — Failed Logon Analysis

## Objective

Identify accounts receiving repeated authentication failures and determine the source IP addresses associated with those attempts.

This hunt supports investigation of:

- Password guessing
- Brute-force activity
- User mistakes
- Cached credentials
- Misconfigured services
- Possible account targeting

## KQL

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by TargetAccount, IpAddress
| order by FailedAttempts desc
```

Repository file:

```text
KQL/01-Failed-Logon-Hunt.kql
```

## What the Query Does

The query:

1. Searches the last 24 hours.
2. Limits results to the domain controller.
3. Filters for Event ID `4625`.
4. Groups failures by target account and source IP.
5. Counts failed authentication attempts.
6. Records the first and last failure time.
7. Sorts the most frequently targeted accounts first.

## Lab Findings

The validated results included:

```text
CORP\test-user       → 8 failures → 192.168.207.128
CORP\soc-test        → 3 failures → 192.168.207.128
CORP\Administrator   → 3 failures → 127.0.0.1
CORP\hr-user         → 1 failure  → 192.168.207.128
```

## Analysis

The results clearly showed which accounts experienced repeated authentication failures and where those attempts originated.

The `test-user` account had the highest number of failed attempts and was later used during the account-lockout exercise.

The loopback address:

```text
127.0.0.1
```

associated with some Administrator failures indicates local authentication activity on the server rather than activity from the Windows client.

## Analyst Questions

When reviewing similar results, ask:

- Which account has the highest failure count?
- Are several accounts being targeted from one IP?
- Is the source IP expected?
- Are the failures spread across many usernames?
- Did any successful logon occur after the failures?
- Did a lockout occur?
- Is the activity consistent with normal user behavior?

## Recommended Follow-Up

Correlate suspicious results with:

```text
4624 - Successful logon
4740 - Account lockout
4767 - Account unlock
```

## Evidence

```text
Screenshots/Threat-Hunting/01-Failed-Logon-Hunt.png
```

---

# 5. Hunt 2 — Active Directory Account and Group Changes

## Objective

Review identity-management changes in Active Directory, especially account creation and security-group membership modifications.

This hunt helps detect or investigate:

- Unauthorized account creation
- Privilege escalation
- Persistence through account manipulation
- Administrative changes
- Group membership abuse

## KQL

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where EventID in (4720, 4728, 4729, 4732, 4733, 4756, 4757)
| project
    TimeGenerated,
    EventID,
    SubjectAccount,
    TargetAccount,
    MemberName,
    Activity
| order by TimeGenerated desc
```

Repository file:

```text
KQL/02-AD-Account-and-Group-Changes-Hunt.kql
```

## Event Coverage

```text
4720 - User account created
4728 - Member added to global security group
4729 - Member removed from global security group
4732 - Member added to local security group
4733 - Member removed from local security group
4756 - Member added to universal security group
4757 - Member removed from universal security group
```

## Lab Findings

The hunt returned nine identity-related events during the testing window.

Important events included:

```text
4720 - Controlled domain account creation
4728 - Test user added to Domain Admins
4729 - Test user removed from Domain Admins
```

These events helped reconstruct both the simulated security activity and the later containment action.

## Why This Hunt Matters

A single event may not tell the complete story.

For example:

```text
4720
↓
New account created

4728
↓
Account added to privileged group

4729
↓
Account later removed
```

Viewed together, these events create a timeline showing creation, privilege change, and remediation.

## Analyst Questions

- Who created the account?
- Which account was modified?
- Which group was changed?
- Is the group privileged?
- Was the change approved?
- Did the account later authenticate?
- Was the account removed from the group?
- Were several identity changes performed by the same administrator?

## Evidence

```text
Screenshots/Threat-Hunting/02-AD-Account-and-Group-Changes-Hunt.png
```

---

# 6. Hunt 3 — Suspicious PowerShell Activity

## Objective

Find PowerShell processes containing command-line patterns that may indicate suspicious execution.

The hunt focuses on Sysmon process creation telemetry.

## Data Source

```text
Table: Event
Event Log: Microsoft-Windows-Sysmon/Operational
Sysmon Event ID: 1
```

## KQL

```kusto
Event
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| extend
    Image = extract(@"Image:\s*(.*?)\s+FileVersion:", 1, RenderedDescription),
    CommandLine = extract(@"CommandLine:\s*(.*?)\s+CurrentDirectory:", 1, RenderedDescription),
    User = extract(@"User:\s*(.*?)\s+LogonGuid:", 1, RenderedDescription),
    ParentImage = extract(@"ParentImage:\s*(.*?)\s+ParentCommandLine:", 1, RenderedDescription)
| where Image endswith "\\powershell.exe" or Image endswith "\\pwsh.exe"
| where CommandLine contains "ExecutionPolicy Bypass"
    or CommandLine contains "-NoProfile"
    or CommandLine contains "-enc"
    or CommandLine contains "EncodedCommand"
    or CommandLine contains "-w hidden"
    or CommandLine contains "-WindowStyle Hidden"
| project
    TimeGenerated,
    Computer,
    User,
    Image,
    CommandLine,
    ParentImage
| order by TimeGenerated desc
```

Repository file:

```text
KQL/03-Suspicious-PowerShell-Hunt.kql
```

## Parsing Logic

The Sysmon events were stored primarily inside:

```text
RenderedDescription
```

The query extracts:

```text
Image
CommandLine
User
ParentImage
```

This makes the raw event easier for an analyst to interpret.

## Suspicious Patterns

The hunt searches for:

```text
ExecutionPolicy Bypass
-NoProfile
-enc
EncodedCommand
-w hidden
-WindowStyle Hidden
```

These patterns are not automatically malicious.

They are useful indicators that should be reviewed in context.

## Lab Findings

The hunt returned approximately ten matching PowerShell process events during testing.

Results included:

- Controlled Administrator activity
- Repeated PowerShell validation commands
- Some SYSTEM-context PowerShell activity

The presence of SYSTEM-context results reinforced an important detection-engineering lesson:

**PowerShell alone is not proof of malicious behavior.**

Context must be reviewed before escalating an incident.

## Analyst Questions

- Which user launched PowerShell?
- Was it Administrator or SYSTEM?
- What was the full command line?
- What was the parent process?
- Was the command encoded?
- Did PowerShell spawn other processes?
- Did registry or account changes occur afterward?
- Was the activity expected system administration?

## MITRE ATT&CK

```text
T1059.001 - PowerShell
Tactic: Execution
```

## Evidence

```text
Screenshots/Threat-Hunting/03-Suspicious-PowerShell-Hunt.png
```

---

# 7. Hunt 4 — Registry Persistence

## Objective

Search Sysmon registry events for modifications to Windows Run-key locations commonly associated with logon persistence.

## Data Source

```text
Table: Event
Event Log: Microsoft-Windows-Sysmon/Operational
Sysmon Event IDs: 12 and 13
```

## KQL

```kusto
Event
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID in (12, 13)
| extend
    Image = extract(@"Image:\s*(.*?)\s+TargetObject:", 1, RenderedDescription),
    TargetObject = coalesce(
        extract(@"TargetObject:\s*(.*?)\s+Details:", 1, RenderedDescription),
        extract(@"TargetObject:\s*(.*?)\s+User:", 1, RenderedDescription)
    ),
    Details = extract(@"Details:\s*(.*?)\s+User:", 1, RenderedDescription),
    User = extract(@"User:\s*(.*)$", 1, RenderedDescription),
    EventType = extract(@"EventType:\s*(.*?)\s+UtcTime:", 1, RenderedDescription)
| where TargetObject contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
| project
    TimeGenerated,
    EventID,
    EventType,
    Computer,
    User,
    Image,
    TargetObject,
    Details
| order by TimeGenerated desc
```

Repository file:

```text
KQL/04-Registry-Persistence-Hunt.kql
```

## Why the Parser Uses `coalesce`

Sysmon Event ID `12` and Event ID `13` do not always present the same surrounding fields inside `RenderedDescription`.

The first parser version did not correctly extract all target registry paths.

The query was corrected to use:

```kusto
coalesce(
    extract(... Details ...),
    extract(... User ...)
)
```

This allowed both registry event formats to be handled in the same hunt.

## Lab Findings

The final hunt returned four relevant registry events.

The results showed both:

```text
Event ID 13 → SetValue
Event ID 12 → DeleteValue
```

for the controlled persistence test.

The test registry value was:

```text
SOC-Lab-Persistence-Test
```

and pointed to a harmless program.

## Investigation Value

This hunt demonstrated both sides of the incident lifecycle:

```text
Persistence Creation
       ↓
Detection
       ↓
Investigation
       ↓
Persistence Removal
       ↓
Verification
```

## Analyst Questions

- Which registry value was modified?
- What executable was configured?
- Which user made the change?
- Which process modified the key?
- Was the value later removed?
- Are there other suspicious autorun entries?
- Did the associated process create additional persistence?

## MITRE ATT&CK

```text
T1547.001 - Registry Run Keys / Startup Folder
Tactics: Persistence / Privilege Escalation
```

## Evidence

```text
Screenshots/Threat-Hunting/04-Registry-Persistence-Hunt.png
```

---

# 8. Hunt 5 — Account Lockout and Recovery Timeline

## Objective

Reconstruct the authentication lifecycle for the controlled `test-user` account.

The hunt correlates:

```text
Failed Authentication
        ↓
Account Lockout
        ↓
Account Recovery
```

## KQL

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where TargetAccount contains "test-user"
| where EventID in (4625, 4740, 4767)
| summarize
    Events = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by EventID
| order by EventID asc
```

Repository file:

```text
KQL/05-Account-Lockout-Recovery-Timeline.kql
```

## Event Meaning

```text
4625 - Failed logon
4740 - Account locked out
4767 - Account unlocked
```

## Lab Findings

The final results were:

```text
4625 → 8 events
4740 → 1 event
4767 → 1 event
```

These results provided a compact summary of the entire controlled account-lockout scenario.

## Timeline Interpretation

The event sequence showed:

```text
Repeated failed passwords
        ↓
4625 events generated
        ↓
Lockout threshold reached
        ↓
4740 generated
        ↓
SOC investigation
        ↓
Unlock-ADAccount
        ↓
4767 generated
        ↓
Recovery confirmed
```

## Response Verification

After unlocking:

```text
badPwdCount = 0
LockedOut = False
```

The unlock was also confirmed in Sentinel through Event ID `4767`.

## Analyst Questions

- How many failures occurred before lockout?
- Which host generated the failed attempts?
- Was the user targeted from one source?
- Did a successful authentication occur?
- Who unlocked the account?
- Was the account behavior normal after recovery?

## MITRE ATT&CK Context

```text
T1110.001 - Password Guessing
Tactic: Credential Access
```

The lockout is treated as a consequence of repeated failed password attempts, not as its own ATT&CK technique.

## Evidence

```text
Screenshots/Threat-Hunting/05-Account-Lockout-Recovery-Timeline.png
```

---

# 9. Hunt Correlation

The individual hunts become more useful when combined.

Example investigation chain:

```text
Hunt 1
Repeated Failed Logons
        ↓
Find test-user failures
        ↓
Hunt 5
Confirm 4740 account lockout
        ↓
Investigate source workstation
        ↓
Verify 4767 account recovery
```

Another chain:

```text
Hunt 2
Identify account/group change
        ↓
Review privileged membership
        ↓
Confirm 4728
        ↓
Response
        ↓
Confirm 4729
```

Another chain:

```text
Hunt 3
Suspicious PowerShell
        ↓
Review process + user
        ↓
Hunt 4
Search registry persistence
        ↓
Confirm SetValue
        ↓
Response
        ↓
Confirm DeleteValue
```

These correlations demonstrate how a SOC analyst moves between telemetry sources instead of investigating events in isolation.

---

# 10. Threat-Hunting Methodology

The project used a simple repeatable methodology.

## Step 1 — Form a Question

Example:

```text
Which users had repeated failed logons?
```

## Step 2 — Identify the Relevant Telemetry

Example:

```text
SecurityEvent / Event ID 4625
```

## Step 3 — Reduce Noise

Filter by:

```text
Computer
TimeGenerated
EventID
Account
Registry path
Process image
```

## Step 4 — Summarize or Parse

Examples:

```kusto
summarize count()
extend
extract()
coalesce()
```

## Step 5 — Review Context

Ask:

- Is this expected?
- Who performed the action?
- Which host was involved?
- What happened before and after?
- Does another data source confirm it?

## Step 6 — Document the Finding

Capture:

- Query
- Screenshot
- Result
- Interpretation
- Follow-up action

---

# 11. Query Troubleshooting Lessons

Not every query worked correctly on the first attempt.

## 11.1 Complex Account Timeline Query

A more complicated `let`, `union`, and `case`-based timeline query was initially attempted for the account lockout investigation.

That version produced semantic/query-engine errors in the lab environment.

The final hunt was intentionally simplified to:

```kusto
SecurityEvent
| where TargetAccount contains "test-user"
| where EventID in (4625, 4740, 4767)
| summarize count() by EventID
```

### Lesson

A simpler query that reliably answers the investigation question is better than unnecessary complexity.

---

## 11.2 Registry Parser Adjustment

The first registry parser did not handle all Sysmon event structures correctly.

The query was adjusted with:

```kusto
coalesce()
```

to support both Event ID `12` and `13`.

### Lesson

Always inspect raw telemetry before assuming every event type has the same text structure.

---

## 11.3 PowerShell Context

The PowerShell hunt returned both controlled Administrator activity and SYSTEM-context activity.

### Lesson

Detection conditions are not equivalent to proof of compromise.

Analysts must examine context and expected administrative behavior.

---

# 12. Detection Rules vs Threat Hunting

The project intentionally includes both.

## Analytics Rules

Purpose:

```text
Automatic continuous detection
```

Typical flow:

```text
Event → Rule → Alert → Incident
```

## Threat Hunting

Purpose:

```text
Manual proactive investigation
```

Typical flow:

```text
Question → KQL → Pattern → Investigation
```

The same telemetry can support both automated detection and analyst-led investigation.

---

# 13. GitHub Screenshot Plan

The following screenshots should be included:

```text
Screenshots/Threat-Hunting/
├── 01-Failed-Logon-Hunt.png
├── 02-AD-Account-and-Group-Changes-Hunt.png
├── 03-Suspicious-PowerShell-Hunt.png
├── 04-Registry-Persistence-Hunt.png
└── 05-Account-Lockout-Recovery-Timeline.png
```

Before upload, review each image for:

- Subscription IDs
- Tenant IDs
- Workspace IDs
- Email addresses
- Access tokens
- Secrets
- Unnecessary personal information

Only sanitized evidence should be committed publicly.

---

# 14. Hunting Skills Demonstrated

The threat-hunting phase demonstrates practical experience with:

- KQL filtering
- Event aggregation
- Timeline analysis
- Windows Security events
- Sysmon telemetry
- Regular-expression extraction
- `extend`
- `extract`
- `coalesce`
- `summarize`
- Sorting
- Event correlation
- Identity investigation
- Process analysis
- Registry analysis
- Response verification
- Detection validation

---

# 15. Outcome

Five core threat hunts were successfully completed and validated.

The hunts covered:

```text
Authentication
Identity
Privilege Changes
PowerShell Execution
Registry Persistence
Account Lockout
Account Recovery
```

The hunting phase demonstrated that the SOC environment could be used not only for automated alerting, but also for proactive analyst-led investigation and event correlation.

The next project phase documents the Sentinel incident-investigation workflow in detail.

---

## Complete Screenshot Evidence

All screenshots from this project stage are retained in the detailed public-safe evidence galleries:

- [Threat-hunting evidence](../Screenshots/09-Threat-Hunting.md)

