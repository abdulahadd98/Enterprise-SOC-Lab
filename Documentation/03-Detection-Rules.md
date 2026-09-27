# Custom Detection Rules

## 1. Purpose

This document describes the six custom Microsoft Sentinel analytics rules built and validated in the Hybrid Enterprise SOC Lab.

Each rule is documented with:

- Detection objective
- Data source
- Relevant Windows or Sysmon event IDs
- MITRE ATT&CK mapping
- Severity
- KQL logic
- Controlled validation method
- Expected evidence
- Investigation guidance
- Response guidance
- Recommended screenshots

The purpose of these rules is not to create production-ready detections for every environment. They are intentionally scoped to the lab so the full detection lifecycle can be demonstrated clearly:

```text
Generate Activity
      ↓
Collect Telemetry
      ↓
Run KQL Detection
      ↓
Generate Alert
      ↓
Create Incident
      ↓
Investigate
      ↓
Respond
      ↓
Verify
```

---

# 2. Detection Rule Summary

| # | Analytics Rule | Data Source | Event ID | Severity | MITRE ATT&CK |
|---|---|---|---|---|---|
| 1 | Repeated Failed Logons - Possible Password Spray | SecurityEvent | 4625 | Medium | T1110.001 Password Guessing |
| 2 | New Active Directory User Created | SecurityEvent | 4720 | Medium | T1136.002 Create Account: Domain Account |
| 3 | Privileged AD Group Membership Change | SecurityEvent | 4728 | High | T1098.007 Additional Local or Domain Groups |
| 4 | Suspicious PowerShell Command Execution | Event / Sysmon | 1 | High | T1059.001 PowerShell |
| 5 | Registry Run-Key Persistence | Event / Sysmon | 13 | Medium | T1547.001 Registry Run Keys / Startup Folder |
| 6 | AD Account Lockout Detected | SecurityEvent | 4740 | Medium | T1110.001 Password Guessing context |

---

# 3. Detection Rule 1 — Repeated Failed Logons

## Rule Name

```text
Repeated Failed Logons - Possible Password Spray
```

## Objective

Detect repeated failed authentication attempts against an Active Directory account.

The lab uses Windows Security Event ID `4625` as the primary signal.

## Data Source

```text
Table: SecurityEvent
Host: DC01.corp.local
Event ID: 4625
```

## MITRE ATT&CK

```text
Tactic: Credential Access
Technique: T1110.001 - Password Guessing
```

## Severity

```text
Medium
```

## Repository KQL

The following query represents the detection logic used for the lab documentation:

```kusto
SecurityEvent
| where TimeGenerated > ago(10m)
| where Computer == "DC01.corp.local"
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by TargetAccount, IpAddress
| where FailedAttempts >= 3
| order by FailedAttempts desc
```

## Detection Logic

The query:

1. Searches recent Windows Security events.
2. Limits the scope to `DC01.corp.local`.
3. Selects failed logon events.
4. Groups failures by account and source IP address.
5. Counts the number of failures.
6. Flags accounts with repeated authentication failures.

## Controlled Validation

Repeated incorrect passwords were intentionally entered against lab accounts from the Windows 10 domain client.

Accounts observed during the project included:

```text
CORP\test-user
CORP\soc-test
CORP\Administrator
CORP\hr-user
```

The Windows client source address during testing was approximately:

```text
192.168.207.128
```

## Threat-Hunting Evidence

The related hunt later showed:

```text
CORP\test-user       → 8 failed attempts
CORP\soc-test        → 3 failed attempts
CORP\Administrator   → 3 failed attempts
CORP\hr-user         → 1 failed attempt
```

## Investigation Questions

When this rule fires, investigate:

- Which account is being targeted?
- Which source IP generated the failures?
- Did the activity originate from a known workstation?
- Were there successful logons after the failures?
- Did the account become locked?
- Is the activity expected testing or suspicious behavior?

## Response Guidance

Possible response actions include:

- Validate the user and source workstation.
- Review Event ID `4625`.
- Review successful authentication events around the same time.
- Check for Event ID `4740` if the account was locked.
- Reset credentials if unauthorized activity is suspected.
- Isolate or investigate the source system if necessary.

## Evidence

Recommended screenshots:

```text
Screenshots/Detection/01-Repeated-Failed-Logons-Rule.png
Screenshots/Incidents/01-Repeated-Failed-Logons-Incident.png
Screenshots/Threat-Hunting/01-Failed-Logon-Hunt.png
```

---

# 4. Detection Rule 2 — New Active Directory User Created

## Rule Name

```text
New Active Directory User Created
```

## Objective

Detect creation of new Active Directory domain accounts.

## Data Source

```text
Table: SecurityEvent
Host: DC01.corp.local
Event ID: 4720
```

## MITRE ATT&CK

```text
Tactic: Persistence
Technique: T1136.002 - Create Account: Domain Account
```

## Severity

```text
Medium
```

## Repository KQL

```kusto
SecurityEvent
| where TimeGenerated > ago(10m)
| where Computer == "DC01.corp.local"
| where EventID == 4720
| project
    TimeGenerated,
    Computer,
    SubjectAccount,
    TargetAccount,
    Activity
| order by TimeGenerated desc
```

## Detection Logic

Event ID `4720` is generated when a Windows user account is created.

On a domain controller, this provides a useful signal for monitoring new Active Directory account creation.

## Controlled Validation

A controlled lab user was created in `corp.local`.

One account used during validation was:

```text
soc-detect-test
```

The account was created by:

```text
CORP\Administrator
```

The event was ingested into Sentinel and produced an incident.

## Expected Evidence

The event should identify:

- Time of creation
- Domain controller
- Account performing the action
- New account name
- Event ID `4720`

## Investigation Questions

- Was this account creation expected?
- Who created the account?
- Which OU was the account created in?
- Was the account immediately added to privileged groups?
- Did the account authenticate after creation?
- Was the account enabled or disabled?
- Does the account follow organizational naming standards?

## Response Guidance

If unauthorized:

- Disable the account.
- Review group memberships.
- Review logon history.
- Determine who created it.
- Remove the account if confirmed malicious.
- Search for additional account creation events.

## Lab Cleanup

The test account used for this validation was later removed after evidence was collected.

## Evidence

Recommended screenshots:

```text
Screenshots/Detection/02-New-AD-User-Rule.png
Screenshots/Incidents/02-New-AD-User-Incident.png
Screenshots/Investigation/02-New-AD-User-Details.png
```

---

# 5. Detection Rule 3 — Privileged AD Group Membership Change

## Rule Name

```text
Privileged AD Group Membership Change
```

## Objective

Detect when an account is added to a privileged Active Directory security group.

## Data Source

```text
Table: SecurityEvent
Host: DC01.corp.local
Primary Event ID: 4728
Response Verification Event ID: 4729
```

## MITRE ATT&CK

```text
Tactics:
- Persistence
- Privilege Escalation

Technique:
T1098.007 - Account Manipulation: Additional Local or Domain Groups
```

## Severity

```text
High
```

## Repository KQL

```kusto
SecurityEvent
| where TimeGenerated > ago(10m)
| where Computer == "DC01.corp.local"
| where EventID == 4728
| project
    TimeGenerated,
    Computer,
    SubjectAccount,
    TargetAccount,
    MemberName,
    Activity,
    EventID
| order by TimeGenerated desc
```

### Optional Privileged-Group Filtering

For a more tightly scoped production-style rule, the group field can be limited to known privileged groups such as:

```text
Domain Admins
Enterprise Admins
Schema Admins
Administrators
Account Operators
Backup Operators
```

The exact field containing the group name can vary based on event parsing, so it should be verified in the target workspace before deploying a strict filter.

## Controlled Validation

A disabled test account named:

```text
soc-priv-test
```

was temporarily added to:

```text
CORP\Domain Admins
```

The action generated:

```text
Event ID 4728
```

Microsoft Sentinel generated a High-severity incident.

## Investigation Evidence

The incident was able to identify:

```text
Changed By: CORP\Administrator
Member Added: soc-priv-test
Privileged Group: CORP\Domain Admins
Event ID: 4728
```

## Response Exercise

The account was removed from the privileged group.

Removal generated:

```text
Event ID 4729
```

This provided direct evidence that the containment action succeeded.

## Investigation Questions

- Which account was added?
- Which privileged group was modified?
- Who performed the change?
- Was there an approved administrative request?
- Did the newly privileged account authenticate afterward?
- Did the account perform additional administrative actions?

## Response Guidance

If unauthorized:

- Remove the account from the privileged group.
- Disable or reset the affected account if necessary.
- Review account logons.
- Review other group changes.
- Investigate the administrator account that performed the change.
- Verify removal using Windows Security logs.

## Evidence

Recommended screenshots:

```text
Screenshots/Detection/03-Privileged-Group-Rule.png
Screenshots/Incidents/03-Privileged-Group-Incident.png
Screenshots/Investigation/03-Privileged-Group-Incident-Details.png
Screenshots/Response/01-Privileged-Group-Removal-4729.png
```

---

# 6. Detection Rule 4 — Suspicious PowerShell Command Execution

## Rule Name

```text
Suspicious PowerShell Command Execution
```

## Objective

Detect PowerShell process execution containing command-line patterns commonly associated with suspicious or evasive execution.

## Data Source

```text
Table: Event
Log: Microsoft-Windows-Sysmon/Operational
Host: DC01.corp.local
Sysmon Event ID: 1
```

## MITRE ATT&CK

```text
Tactic: Execution
Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
```

## Severity

```text
High
```

## Repository KQL

```kusto
Event
| where TimeGenerated > ago(10m)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| extend
    Image = extract(@"Image:\s*(.*?)\s+FileVersion:", 1, RenderedDescription),
    CommandLine = extract(@"CommandLine:\s*(.*?)\s+CurrentDirectory:", 1, RenderedDescription),
    User = extract(@"User:\s*(.*?)\s+LogonGuid:", 1, RenderedDescription),
    ParentImage = extract(@"ParentImage:\s*(.*?)\s+ParentCommandLine:", 1, RenderedDescription)
| where Image endswith "\\powershell.exe"
    or Image endswith "\\pwsh.exe"
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

## Detection Logic

The query:

1. Reads Sysmon process creation telemetry.
2. Extracts the process image.
3. Extracts the command line.
4. Extracts the user.
5. Extracts the parent process.
6. Identifies PowerShell.
7. Searches for suspicious command-line patterns.

## Controlled Validation

Harmless commands were used.

Example:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-FINAL-TEST'"
```

Other markers used during testing included:

```text
SOC-RULE4-FINAL-TEST
SOC-SOAR-AUTOMATION-TEST
SOC-SOAR-AUTOMATION-TEST-2
SOC-SOAR-FINAL-TEST
```

No malicious payload was executed.

## Expected Evidence

Sysmon Event ID `1` should contain:

- `powershell.exe`
- User
- Command line
- Parent process
- Timestamp
- Host

## Sentinel Result

The rule generated multiple High-severity PowerShell incidents during testing.

The final automation validation produced a fresh incident and automatically created three SOC investigation tasks.

## Investigation Questions

- Which user executed PowerShell?
- What command line was used?
- Was `ExecutionPolicy Bypass` used?
- Was `NoProfile` used?
- Was the command encoded?
- What was the parent process?
- Did PowerShell create child processes?
- Were registry, account, or network changes observed afterward?
- Is the activity legitimate administration?

## Response Guidance

If unauthorized:

- Stop the suspicious process.
- Isolate the endpoint if necessary.
- Disable compromised accounts.
- Review child processes.
- Review persistence mechanisms.
- Review related SecurityEvent and Sysmon telemetry.
- Preserve evidence before remediation.

## SOAR Integration

This analytics rule was used as the trigger condition for the Sentinel automation rule:

```text
SOC PowerShell Investigation Tasks
```

Three tasks were automatically added to new incidents:

```text
1. Review PowerShell process and command line
2. Check related events and persistence indicators
3. Contain, document, and close the incident
```

## Evidence

Recommended screenshots:

```text
Screenshots/Detection/04-Suspicious-PowerShell-Rule.png
Screenshots/Incidents/04-Suspicious-PowerShell-Incident.png
Screenshots/Investigation/04-PowerShell-Command-Line.png
Screenshots/Automation/09-SOAR-Final-Test-In-Sentinel.png
Screenshots/Automation/10-SOAR-Automated-Investigation-Tasks.png
```

---

# 7. Detection Rule 5 — Registry Run-Key Persistence

## Rule Name

```text
Registry Run-Key Persistence
```

## Objective

Detect modification of Windows Registry Run keys that can be used to automatically launch a program when a user logs on.

## Data Source

```text
Table: Event
Log: Microsoft-Windows-Sysmon/Operational
Host: DC01.corp.local
Primary Sysmon Event ID: 13
Response Verification: Event ID 12
```

## MITRE ATT&CK

```text
Tactics:
- Persistence
- Privilege Escalation

Technique:
T1547.001 - Boot or Logon Autostart Execution:
Registry Run Keys / Startup Folder
```

## Severity

```text
Medium
```

## Repository KQL

```kusto
Event
| where TimeGenerated > ago(10m)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 13
| extend
    Image = extract(@"Image:\s*(.*?)\s+TargetObject:", 1, RenderedDescription),
    TargetObject = extract(@"TargetObject:\s*(.*?)\s+Details:", 1, RenderedDescription),
    Details = extract(@"Details:\s*(.*?)\s+User:", 1, RenderedDescription),
    User = extract(@"User:\s*(.*)$", 1, RenderedDescription)
| where TargetObject contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
| project
    TimeGenerated,
    Computer,
    User,
    Image,
    TargetObject,
    Details
| order by TimeGenerated desc
```

## Controlled Validation

A harmless registry value was created:

```text
SOC-Lab-Persistence-Test
```

The value pointed to:

```text
notepad.exe
```

The test used the CurrentVersion Run-key location.

The modification generated:

```text
Sysmon Event ID 13
```

and produced a Medium-severity Sentinel incident.

## Investigation Questions

- Which user modified the key?
- Which process performed the change?
- What registry path was modified?
- What executable or command was configured?
- Is the executable trusted?
- Did the same process make other persistence changes?
- Was the activity expected?

## Response Exercise

The test registry value was removed.

The removal was validated using:

```text
Sysmon Event ID 12
```

The threat-hunting query later showed both the creation and deletion activity.

## Response Guidance

If unauthorized:

- Preserve the registry value for evidence.
- Review the referenced executable.
- Remove malicious persistence.
- Review other autorun locations.
- Review process creation events associated with the modification.
- Scan for additional persistence mechanisms.
- Verify the key/value is removed.

## Evidence

Recommended screenshots:

```text
Screenshots/Detection/05-Registry-Run-Key-Rule.png
Screenshots/Incidents/05-Registry-Persistence-Incident.png
Screenshots/Investigation/05-Registry-Persistence-Details.png
Screenshots/Response/02-Registry-Persistence-Removal.png
Screenshots/Threat-Hunting/04-Registry-Persistence-Hunt.png
```

---

# 8. Detection Rule 6 — Active Directory Account Lockout

## Rule Name

```text
AD Account Lockout Detected
```

## Objective

Detect Active Directory account lockout activity and identify the affected account and the caller computer.

## Data Source

```text
Table: SecurityEvent
Host: DC01.corp.local
Primary Event ID: 4740
Supporting Events:
- 4625
- 4767
```

## MITRE ATT&CK

```text
Tactic: Credential Access
Technique Context: T1110.001 - Password Guessing
```

The account lockout itself is not treated as a separate ATT&CK technique.

In this lab, Event ID `4740` was generated as the defensive consequence of repeated failed password attempts.

## Severity

```text
Medium
```

## Final KQL Used

```kusto
let ingestion_delay = 10m;
let rule_frequency = 5m;
SecurityEvent
| where TimeGenerated >= ago(ingestion_delay + rule_frequency)
| where ingestion_time() > ago(rule_frequency)
| where Computer == "DC01.corp.local"
| where EventID == 4740
| extend
    LockedUser = iff(
        isempty(TargetUserName),
        tostring(split(TargetAccount, "\\")[1]),
        TargetUserName
    ),
    CallerComputer = coalesce(
        tostring(column_ifexists("WorkstationName", "")),
        tostring(column_ifexists("Workstation", "")),
        TargetDomainName
    )
| project
    TimeGenerated,
    Computer,
    EventID,
    LockedUser,
    TargetAccount,
    CallerComputer,
    Activity
```

## Why the Query Was Adjusted

The first version of the rule used `TargetAccount` directly.

During testing, the resulting incident displayed an account value that also contained the caller workstation context.

The rule was improved by extracting:

```text
LockedUser
```

and separately identifying:

```text
CallerComputer
```

This produced clearer incident details.

## Entity Mapping

The final rule mapped:

```text
Account Name → LockedUser
```

## Custom Details

The final rule included:

```text
LockedAccount
CallerComputer
EventID
Activity
```

## Controlled Validation

The account:

```text
CORP\test-user
```

was intentionally tested with repeated incorrect passwords from:

```text
DESKTOP-82C5TLV
```

The configured account lockout threshold was:

```text
5 invalid logon attempts
```

After the test:

```text
badPwdCount = 5
LockedOut = True
```

DC01 generated:

```text
Event ID 4740
```

## Sentinel Incident

The final incident displayed:

```text
Locked Account: test-user
Caller Computer: DESKTOP-82C5TLV
Event ID: 4740
Host: DC01.corp.local
```

## Investigation Questions

- Which user was locked?
- Which workstation generated the failures?
- How many failed logons occurred?
- Were the failures expected?
- Did the source generate failures against additional accounts?
- Were there successful logons before or after the lockout?
- Was this user targeted by password guessing?

## Response Exercise

The account was restored using:

```powershell
Unlock-ADAccount -Identity "test-user"
```

State was then validated:

```text
badPwdCount = 0
LockedOut = False
```

Windows Security generated:

```text
Event ID 4767 - A user account was unlocked
```

The recovery event was also visible in Microsoft Sentinel.

## Related Timeline Hunt

The final compact hunt used:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where TargetAccount contains "test-user"
| where EventID in (4625, 4740, 4767)
| summarize
    Events=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated)
    by EventID
| order by EventID asc
```

Results:

```text
4625 → 8 events
4740 → 1 event
4767 → 1 event
```

## Evidence

Recommended screenshots:

```text
Screenshots/Detection/06-AD-Account-Lockout-Rule.png
Screenshots/Incidents/06-AD-Account-Lockout-Incident.png
Screenshots/Investigation/06-Lockout-Incident-Details.png
Screenshots/Response/03-Account-Unlock-4767.png
Screenshots/Threat-Hunting/05-Account-Lockout-Recovery-Timeline.png
```

---

# 9. Analytics Rule Configuration Guidance

For this lab, analytics rules were configured as scheduled detections.

Important settings to document for each rule include:

```text
Rule name
Description
Severity
Query
Query frequency
Lookup period
Entity mappings
Custom details
MITRE ATT&CK mapping
Incident creation
Alert grouping
Rule status
```

The exact scheduling interval may differ between rules depending on the activity being detected.

For GitHub documentation, the focus should be on the logic and validation rather than claiming a production tuning standard.

---

# 10. False Positive Considerations

Custom detections should always account for legitimate administrative activity.

Examples include:

### Failed Logons

Possible legitimate causes:

- Mistyped passwords
- Cached credentials
- Expired passwords
- Service account configuration errors

### New Account Creation

Possible legitimate causes:

- Employee onboarding
- Test accounts
- Service account provisioning

### Privileged Group Changes

Possible legitimate causes:

- Approved administrative changes
- Temporary support access
- Planned maintenance

### PowerShell

Possible legitimate causes:

- System administration
- Microsoft management agents
- Scheduled scripts
- Security tools

### Registry Run Keys

Possible legitimate causes:

- Application installation
- User startup programs
- Management software

### Account Lockouts

Possible legitimate causes:

- User mistakes
- Old stored credentials
- Services using outdated passwords

This is why Sentinel incidents require investigation rather than treating every alert as confirmed compromise.

---

# 11. Detection Engineering Lessons

The project demonstrated several important detection-engineering lessons.

## 11.1 Verify the Raw Event First

Before writing a rule:

```text
Generate event
→ Verify locally
→ Verify ingestion
→ Inspect fields
→ Build KQL
```

This avoids building rules against fields that are not actually populated.

---

## 11.2 Sysmon Parsing Requires Validation

Sysmon data in the `Event` table was primarily contained in:

```text
RenderedDescription
```

Fields such as:

```text
Image
CommandLine
User
ParentImage
TargetObject
Details
```

were extracted with KQL.

The parser was refined during testing when the exact text layout differed between registry event types.

---

## 11.3 Detection and Response Evidence Should Be Separate

For some scenarios:

```text
Detection Event ≠ Response Verification Event
```

Examples:

```text
4728 = account added to privileged group
4729 = account removed from privileged group

13 = registry value set
12 = registry value deleted

4740 = account locked
4767 = account unlocked
```

Using both sides creates a much stronger incident-response story.

---

## 11.4 Entity Mapping Improves Investigations

The account lockout rule became more useful after extracting:

```text
LockedUser
CallerComputer
```

instead of relying only on the raw `TargetAccount` field.

Good entity mapping improves the incident experience and analyst readability.

---

## 11.5 Detections Should Be Tested End-to-End

Every important rule should be validated through the full chain:

```text
Activity
↓
Local Event
↓
Cloud Ingestion
↓
KQL Match
↓
Analytics Rule
↓
Alert
↓
Incident
↓
Investigation
```

The PowerShell rule was additionally validated through:

```text
Incident
↓
Automation Rule
↓
Automatic Investigation Tasks
```

---

# 12. Final Detection Coverage

The six rules provide visibility across multiple attack stages:

```text
Credential Access
├── Repeated Failed Logons
└── AD Account Lockout

Persistence
├── New AD User Created
├── Privileged Group Membership Change
└── Registry Run-Key Persistence

Privilege Escalation
├── Privileged Group Membership Change
└── Registry Run-Key Persistence

Execution
└── Suspicious PowerShell
```

This provides a small but meaningful detection set across:

- Identity
- Authentication
- Privilege
- Process execution
- Registry persistence

---

# 13. GitHub Files

The repository should contain this overview document plus separate KQL / rule files.

Recommended structure:

```text
Detection-Rules/
├── 01-Repeated-Failed-Logons.kql
├── 02-New-AD-User-Created.kql
├── 03-Privileged-AD-Group-Change.kql
├── 04-Suspicious-PowerShell.kql
├── 05-Registry-Run-Key-Persistence.kql
└── 06-AD-Account-Lockout.kql
```

Detailed threat-hunting queries should remain in:

```text
KQL/
```

This keeps scheduled detections separate from proactive hunting content.

---

# 14. Outcome

All six custom analytics rules were successfully represented in the final project documentation.

The detection set demonstrates the ability to:

- Understand Windows and Sysmon telemetry
- Translate security behaviors into KQL
- Build custom Sentinel analytics
- Map detections to MITRE ATT&CK
- Validate detections with controlled activity
- Generate incidents
- Investigate evidence
- Perform response actions
- Verify remediation
- Connect detections to automation

The next project phase documents the five completed threat hunts in detail.

---

## Complete Screenshot Evidence

All screenshots from this project stage are retained in the detailed public-safe evidence galleries:

- [SecurityEvent / KQL evidence](../Screenshots/04-SecurityEvent-KQL.md)
- [Detection rule evidence](../Screenshots/06-Detection-Rules.md)
- [Incident evidence](../Screenshots/07-Incidents-Investigation.md)

