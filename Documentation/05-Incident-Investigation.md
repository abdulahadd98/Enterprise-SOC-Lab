# Incident Investigation

## 1. Purpose

This document records the incident-investigation phase of the Hybrid Enterprise SOC Lab.

The goal of this phase was to demonstrate how Microsoft Sentinel turns collected telemetry into analyst-actionable incidents and how those incidents can be investigated, correlated, contained, verified, and closed.

The lab followed this investigation model:

```text
Alert Generated
      ↓
Incident Created
      ↓
Review Severity and Rule
      ↓
Inspect Entities / Custom Details
      ↓
Correlate Supporting Telemetry
      ↓
Determine Expected vs Suspicious
      ↓
Perform Response
      ↓
Verify Remediation
      ↓
Classify and Close
```

The project generated several incidents during testing. This document focuses on the strongest cases because they demonstrate the complete SOC workflow rather than simply showing that an alert fired.

---

# 2. Primary Investigation Cases

The strongest documented cases were:

| Incident | Scenario | Severity | Main Evidence | Outcome |
|---|---|---:|---|---|
| #2 | New Active Directory User Created | Medium | Security Event 4720 | Investigated and test account later removed |
| #4 | Privileged AD Group Membership Change | High | Security Event 4728 | User removed from Domain Admins; 4729 verified |
| #6 | Registry Run-Key Persistence | Medium | Sysmon 13 | Persistence removed; Sysmon 12 verified |
| #9 | AD Account Lockout Detected | Medium | Security Event 4740 | Account unlocked; 4767 verified |
| #11 | Suspicious PowerShell + SOAR | High | Sysmon 1 | Automation added 3 tasks; incident resolved as expected lab testing |

Additional PowerShell incidents were generated during tuning and automation validation. Those repeated tests were useful during development but are not all needed as separate portfolio case studies.

---

# 3. Investigation Workflow Used in the Lab

## Step 1 — Open the Incident

The analyst first reviewed:

- Incident title
- Incident number
- Severity
- Analytics rule
- Creation time
- Alert count
- Entities
- Custom details

The purpose was to quickly answer:

```text
What happened?
Which system was involved?
Which user was involved?
Why did this rule fire?
```

---

## Step 2 — Review Alert Evidence

The alert details were inspected for event-specific fields.

Examples included:

```text
Target account
Subject account
Changed-by account
Member added
Privileged group
Caller computer
PowerShell command line
Parent process
Registry target
Registry details
Event ID
```

---

## Step 3 — Correlate with Raw Logs

The incident was not treated as proof by itself.

Supporting telemetry was queried in Microsoft Sentinel.

Examples:

```kusto
SecurityEvent
| where Computer == "DC01.corp.local"
```

and:

```kusto
Event
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
```

The investigation then filtered to the relevant event ID, user, command line, registry object, or time window.

---

## Step 4 — Determine Context

Each alert was evaluated against the lab context.

Possible outcomes included:

```text
Expected authorized lab activity
Suspicious activity requiring containment
False positive / benign administrative activity
```

Because this project intentionally generated controlled security events, the final classification for completed tests was expected security-testing activity.

---

## Step 5 — Perform Response

Response actions were taken where the scenario allowed a meaningful containment or recovery step.

Examples:

```text
Remove account from Domain Admins
Remove Registry Run persistence
Unlock locked AD account
```

---

## Step 6 — Verify the Response

The project did not stop after performing the response command.

The remediation was verified using separate events.

Examples:

```text
4728 → Added to privileged group
4729 → Removed from privileged group

13 → Registry value set
12 → Registry value deleted

4740 → Account locked
4767 → Account unlocked
```

This is one of the strongest parts of the project because it shows both detection and evidence-based recovery validation.

---

# 4. Case Study 1 — New Active Directory User Created

## Incident

```text
Incident #2
```

## Analytics Rule

```text
New Active Directory User Created
```

## Severity

```text
Medium
```

## Primary Event

```text
Windows Security Event ID 4720
```

## Test Activity

A controlled domain account was created in:

```text
corp.local
```

One account used during validation was:

```text
soc-detect-test
```

The creator observed in the event was:

```text
CORP\Administrator
```

## Investigation

The incident confirmed that:

- A new Active Directory account had been created.
- The action occurred on `DC01`.
- The event was collected in `SecurityEvent`.
- Event ID `4720` was available for investigation.
- Sentinel converted the detection into an incident.

## Analyst Questions

The investigation focused on:

- Who created the account?
- Was the account expected?
- Was the account enabled?
- Was it added to any privileged groups?
- Did it authenticate after creation?
- Was it created inside an expected OU?

## Outcome

The event was expected because it was created for controlled SOC testing.

After the required evidence was captured, the test account was later removed.

## MITRE ATT&CK

```text
T1136.002 - Create Account: Domain Account
Tactic: Persistence
```

## Evidence

Recommended files:

```text
Screenshots/Incidents/02-New-AD-User-Incident.png
Screenshots/Investigation/02-New-AD-User-Details.png
```

Detailed report:

```text
Incident-Reports/01-New-AD-User-Incident.md
```

---

# 5. Case Study 2 — Privileged AD Group Membership Change

## Incident

```text
Incident #4
```

## Analytics Rule

```text
Privileged AD Group Membership Change
```

## Severity

```text
High
```

## Primary Detection Event

```text
Windows Security Event ID 4728
```

## Response Verification Event

```text
Windows Security Event ID 4729
```

## Test Activity

A disabled test account:

```text
soc-priv-test
```

was temporarily added to:

```text
CORP\Domain Admins
```

## Investigation Findings

The incident exposed the important investigation fields:

```text
Changed By: CORP\Administrator
Member Added: soc-priv-test
Privileged Group: CORP\Domain Admins
Event ID: 4728
```

This provided enough context to answer the most important identity-security questions:

```text
Who made the change?
Which account received privilege?
Which privileged group was modified?
```

## Risk

Unauthorized addition to `Domain Admins` can provide extremely broad control over an Active Directory environment.

For that reason, this rule was configured as:

```text
High severity
```

## Response

The test account was removed from `Domain Admins`.

## Verification

The removal generated:

```text
Event ID 4729
```

This confirmed that the privilege had been removed.

## Investigation Lifecycle

```text
Add Test User to Domain Admins
        ↓
4728 Generated
        ↓
Sentinel Alert
        ↓
Incident #4
        ↓
Investigate ChangedBy / Member / Group
        ↓
Remove User from Domain Admins
        ↓
4729 Generated
        ↓
Containment Verified
```

## MITRE ATT&CK

```text
T1098.007 - Additional Local or Domain Groups
Tactics: Persistence / Privilege Escalation
```

## Evidence

```text
Screenshots/Incidents/03-Privileged-Group-Incident.png
Screenshots/Investigation/03-Privileged-Group-Incident-Details.png
Screenshots/Response/01-Privileged-Group-Removal-4729.png
```

Detailed report:

```text
Incident-Reports/02-Privileged-Group-Incident.md
```

---

# 6. Case Study 3 — Registry Run-Key Persistence

## Incident

```text
Incident #6
```

## Analytics Rule

```text
Registry Run-Key Persistence
```

## Severity

```text
Medium
```

## Data Source

```text
Microsoft-Windows-Sysmon/Operational
```

## Detection Event

```text
Sysmon Event ID 13
```

## Response Verification Event

```text
Sysmon Event ID 12
```

## Test Activity

A harmless registry value was created:

```text
SOC-Lab-Persistence-Test
```

under a Windows `CurrentVersion\Run` path.

The value pointed to:

```text
notepad.exe
```

This was used to safely simulate a persistence mechanism.

## Investigation

The incident and supporting Sysmon telemetry were reviewed for:

- User
- Process image
- Registry target
- Registry value
- Event type
- Host
- Timestamp

## Threat-Hunting Correlation

The registry-persistence hunt later displayed both:

```text
SetValue
DeleteValue
```

activity for the Run-key path.

This made it possible to reconstruct both the simulated persistence and its cleanup.

## Response

The `SOC-Lab-Persistence-Test` registry value was removed.

## Verification

Sysmon Event ID `12` confirmed deletion activity.

## Investigation Lifecycle

```text
Run Key Created
      ↓
Sysmon 13
      ↓
Sentinel Detection
      ↓
Incident #6
      ↓
Investigation
      ↓
Registry Value Removed
      ↓
Sysmon 12
      ↓
Response Verified
```

## MITRE ATT&CK

```text
T1547.001 - Registry Run Keys / Startup Folder
Tactics: Persistence / Privilege Escalation
```

## Evidence

```text
Screenshots/Incidents/05-Registry-Persistence-Incident.png
Screenshots/Investigation/05-Registry-Persistence-Details.png
Screenshots/Response/02-Registry-Persistence-Removal.png
Screenshots/Threat-Hunting/04-Registry-Persistence-Hunt.png
```

Detailed report:

```text
Incident-Reports/03-Registry-Persistence-Incident.md
```

---

# 7. Case Study 4 — Active Directory Account Lockout

## Incident

```text
Incident #9
```

## Analytics Rule

```text
AD Account Lockout Detected
```

## Severity

```text
Medium
```

## Detection Event

```text
Windows Security Event ID 4740
```

## Supporting Events

```text
4625 - Failed logon
4767 - Account unlocked
```

## Test Activity

The account:

```text
test-user
```

was intentionally tested with repeated invalid passwords.

The source workstation was:

```text
DESKTOP-82C5TLV
```

The configured lockout threshold was:

```text
5 invalid attempts
```

The resulting account state was:

```text
badPwdCount = 5
LockedOut = True
```

## Investigation Findings

The final rule exposed:

```text
LockedAccount: test-user
CallerComputer: DESKTOP-82C5TLV
EventID: 4740
Computer: DC01.corp.local
```

This was an improvement over the earlier query because the affected user and caller computer were separated into clearer fields.

## Threat-Hunting Correlation

The related hunt showed:

```text
4625 → 8 events
4740 → 1 event
4767 → 1 event
```

This provided a complete authentication timeline.

## Response

The account was restored using:

```powershell
Unlock-ADAccount -Identity "test-user"
```

## Verification

The account state was then checked:

```text
badPwdCount = 0
LockedOut = False
```

Windows generated:

```text
Event ID 4767
```

The unlock event was also successfully ingested into Microsoft Sentinel.

## Investigation Lifecycle

```text
Repeated Bad Passwords
        ↓
4625 Events
        ↓
Lockout Threshold Reached
        ↓
4740
        ↓
Incident #9
        ↓
Identify test-user + DESKTOP-82C5TLV
        ↓
Unlock-ADAccount
        ↓
4767
        ↓
Recovery Verified
```

## MITRE ATT&CK Context

```text
T1110.001 - Password Guessing
Tactic: Credential Access
```

The account lockout is documented as a consequence of controlled password-guessing activity rather than as a separate ATT&CK technique.

## Evidence

```text
Screenshots/Incidents/06-AD-Account-Lockout-Incident.png
Screenshots/Investigation/06-Lockout-Incident-Details.png
Screenshots/Response/03-Account-Unlock-4767.png
Screenshots/Threat-Hunting/05-Account-Lockout-Recovery-Timeline.png
```

Detailed report:

```text
Incident-Reports/04-Account-Lockout-Incident.md
```

---

# 8. Case Study 5 — Suspicious PowerShell and SOAR

## Final Validation Incident

```text
Incident #11
```

## Analytics Rule

```text
Suspicious PowerShell Command Execution
```

## Severity

```text
High
```

## Detection Source

```text
Table: Event
Log: Microsoft-Windows-Sysmon/Operational
Sysmon Event ID: 1
```

## Final Test Command

A harmless marker command was executed:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-FINAL-TEST'"
```

The test was intentionally safe and produced no malicious payload.

## Telemetry Validation

The final marker was confirmed:

1. Locally in Sysmon Event ID `1`
2. In Microsoft Sentinel
3. Through the custom PowerShell analytics rule
4. As a fresh incident

## Automation Rule

The final working automation rule was:

```text
SOC PowerShell Investigation Tasks
```

Trigger:

```text
When incident is created
```

Condition:

```text
Analytics rule name =
Suspicious PowerShell Command Execution
```

## Automated Tasks

Incident #11 automatically received the following three tasks:

```text
1. Review PowerShell process and command line
2. Check related events and persistence indicators
3. Contain, document, and close the incident
```

This was the final proof that the incident-to-automation workflow was working.

## Investigation Areas

The PowerShell incident was reviewed for:

- User
- Process image
- Full command line
- Parent process
- Host
- Related Sysmon events
- Possible registry persistence
- Related account changes

## Classification

The final incident was expected because the activity was an authorized lab validation.

After the automated tasks were verified and documented, the incident was resolved as expected security testing.

## Investigation Lifecycle

```text
Harmless PowerShell Test
        ↓
Sysmon Event ID 1
        ↓
Sentinel Ingestion
        ↓
PowerShell Analytics Rule
        ↓
Incident #11
        ↓
Standard Automation Rule
        ↓
3 Investigation Tasks Added
        ↓
Analyst Review
        ↓
Expected Security Testing
        ↓
Incident Resolved
```

## MITRE ATT&CK

```text
T1059.001 - PowerShell
Tactic: Execution
```

## Evidence

```text
Screenshots/Automation/08-SOAR-Final-Test-Sysmon-Event1.png
Screenshots/Automation/09-SOAR-Final-Test-In-Sentinel.png
Screenshots/Automation/10-SOAR-Automated-Investigation-Tasks.png
```

Detailed report:

```text
Incident-Reports/05-PowerShell-SOAR-Incident.md
```

---

# 9. Repeated PowerShell Incidents During Testing

Several PowerShell incidents were generated during rule tuning and automation testing.

Known examples included:

```text
Incident #5
Incident #7
Incident #10
Incident #11
```

Not every repeated test should become a separate GitHub incident report.

For portfolio clarity:

```text
Use #11 as the final PowerShell / SOAR case study.
```

Earlier incidents can be referenced as development and validation activity.

This avoids clutter while still showing that the detection was repeatedly tested.

---

# 10. Incident Correlation

The investigations demonstrate that incidents should be correlated with related telemetry rather than handled independently.

Example:

```text
Failed Logons
    ↓
4625
    ↓
Account Lockout
    ↓
4740
    ↓
Account Recovery
    ↓
4767
```

Another example:

```text
Privileged Group Addition
    ↓
4728
    ↓
High-Severity Incident
    ↓
Containment
    ↓
4729
```

Another example:

```text
Registry SetValue
    ↓
Sysmon 13
    ↓
Persistence Incident
    ↓
Removal
    ↓
Sysmon 12
```

This event-to-event correlation is more valuable than merely demonstrating isolated alerts.

---

# 11. Incident Severity

Severity was used to communicate the potential impact of the detected activity.

Examples from the lab:

```text
High
├── Privileged AD Group Membership Change
└── Suspicious PowerShell Command Execution

Medium
├── Repeated Failed Logons
├── New Active Directory User Created
├── Registry Run-Key Persistence
└── AD Account Lockout Detected
```

Severity does not prove malicious intent.

It helps analysts prioritize investigation.

---

# 12. Incident Classification

Because the events in this project were intentionally generated inside an authorized lab, completed validation incidents were closed as expected security-testing activity.

Recommended closure notes should state:

```text
Controlled and authorized SOC lab simulation.
Telemetry, detection, investigation, and response validation completed.
No production or third-party system involved.
```

Avoid closing incidents without notes because closure documentation is part of a professional investigation record.

---

# 13. Evidence Handling

A strong incident report should capture:

```text
Incident title
Incident number
Severity
Analytics rule
Primary event
Affected entity
Source entity
Investigation findings
Related KQL
Response action
Verification event
Final classification
Screenshots
```

Screenshots must be sanitized before publication.

Redact:

- Subscription IDs
- Tenant IDs
- Workspace IDs
- Machine IDs
- Client/application secrets
- Tokens
- Unnecessary email addresses
- Any authentication credential

---

# 14. Investigation Skills Demonstrated

The incident phase demonstrates practical experience with:

- Sentinel incident triage
- Alert review
- Entity analysis
- Custom detail review
- Windows Security event analysis
- Sysmon event analysis
- KQL correlation
- Identity-security investigation
- Privileged access investigation
- Process and command-line investigation
- Registry persistence investigation
- Authentication timeline reconstruction
- Containment
- Recovery
- Verification
- Incident classification
- Incident closure
- SOAR-assisted investigation

---

# 15. Incident Report Files

The repository contains separate reports for the main cases:

```text
Incident-Reports/
├── 01-New-AD-User-Incident.md
├── 02-Privileged-Group-Incident.md
├── 03-Registry-Persistence-Incident.md
├── 04-Account-Lockout-Incident.md
└── 05-PowerShell-SOAR-Incident.md
```

These reports can be opened independently by a recruiter or interviewer without reading the full project documentation.

---

# 16. Outcome

The incident-investigation phase demonstrated the full path from security telemetry to analyst action.

The project did not stop at:

```text
"An alert appeared."
```

Instead it demonstrated:

```text
Detection
   ↓
Incident
   ↓
Evidence Review
   ↓
Threat Hunting
   ↓
Response
   ↓
Verification
   ↓
Automation
   ↓
Closure
```

This gives the project a complete SOC investigation story rather than only a collection of detection rules.

The next phase documents the response and containment actions in greater detail.

---

## Complete Screenshot Evidence

All screenshots from this project stage are retained in the detailed public-safe evidence galleries:

- [Incident and investigation evidence](../Screenshots/07-Incidents-Investigation.md)
- [Detection evidence](../Screenshots/06-Detection-Rules.md)

