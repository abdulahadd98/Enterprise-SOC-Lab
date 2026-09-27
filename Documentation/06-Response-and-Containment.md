# Response and Containment

## 1. Purpose

This document records the response and containment phase of the Hybrid Enterprise SOC Lab.

The goal of this phase was to demonstrate that security monitoring should not stop at detection and investigation. A complete SOC workflow should also include a response action and evidence proving that the response actually worked.

The lab focused on three practical response exercises:

```text
1. Remove unauthorized privileged group membership
2. Remove registry-based persistence
3. Recover a locked Active Directory account
```

Each response followed the same model:

```text
Detection
   ↓
Investigation
   ↓
Containment / Recovery Action
   ↓
Verification Event
   ↓
Confirm Secure State
   ↓
Close Incident
```

This approach demonstrates the difference between simply acknowledging an alert and actually completing an incident-response lifecycle.

---

# 2. Response Summary

| # | Scenario | Detection Event | Response | Verification Event |
|---|---|---|---|---|
| 1 | Privileged AD group membership | 4728 | Remove test account from Domain Admins | 4729 |
| 2 | Registry Run-key persistence | Sysmon 13 | Delete persistence registry value | Sysmon 12 |
| 3 | AD account lockout | 4740 | Unlock account | 4767 |

---

# 3. Response Exercise 1 — Privileged Group Membership Removal

## Scenario

A controlled test account:

```text
soc-priv-test
```

was temporarily added to:

```text
CORP\Domain Admins
```

The purpose was to validate detection and response for an unauthorized privileged-access scenario.

---

## Detection

The group membership change generated:

```text
Windows Security Event ID 4728
```

The custom Microsoft Sentinel analytics rule:

```text
Privileged AD Group Membership Change
```

created a High-severity incident.

The investigation identified:

```text
Changed By: CORP\Administrator
Member Added: soc-priv-test
Privileged Group: CORP\Domain Admins
Event ID: 4728
```

---

## Risk

Membership in `Domain Admins` provides highly privileged access within an Active Directory domain.

An unauthorized addition to this group could allow an attacker to:

- Administer domain systems
- Modify Active Directory objects
- Create or change users and groups
- Change security policies
- Access sensitive resources
- Establish additional persistence

Because of this potential impact, the incident was treated as high priority.

---

## Containment Action

The test account was removed from the privileged group.

This was performed using Active Directory administration tools.

A PowerShell equivalent for documentation purposes is:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "soc-priv-test"
```

When prompted, confirm the removal if required.

---

## Verification

After removal, the Windows Security log generated:

```text
Event ID 4729
```

Event ID `4729` indicates that a member was removed from a global security group.

The verification event was reviewed to confirm:

```text
Account: soc-priv-test
Group: Domain Admins
Action: Member removed
```

---

## Response Lifecycle

```text
soc-priv-test added to Domain Admins
            ↓
Event ID 4728
            ↓
Sentinel Incident
            ↓
Analyst Investigation
            ↓
Remove account from Domain Admins
            ↓
Event ID 4729
            ↓
Containment Verified
```

---

## Verification Query

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where EventID in (4728, 4729)
| project
    TimeGenerated,
    EventID,
    SubjectAccount,
    TargetAccount,
    MemberName,
    Activity
| order by TimeGenerated desc
```

---

## Analyst Validation Checklist

- [x] Privileged group change detected
- [x] Actor identified
- [x] Added account identified
- [x] Privileged group identified
- [x] Account removed
- [x] Removal event generated
- [x] Removal visible in centralized telemetry
- [x] Incident documented

---

## MITRE ATT&CK

```text
T1098.007 - Additional Local or Domain Groups
Tactics:
- Persistence
- Privilege Escalation
```

---

## Evidence

Recommended screenshots:

```text
Screenshots/Investigation/03-Privileged-Group-Incident-Details.png
Screenshots/Response/01-Privileged-Group-Removal-4729.png
```

---

# 4. Response Exercise 2 — Registry Persistence Removal

## Scenario

A controlled registry value was created to simulate Windows logon persistence.

Test value:

```text
SOC-Lab-Persistence-Test
```

Registry location:

```text
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

The value pointed to a harmless program:

```text
notepad.exe
```

The purpose was to simulate a common persistence method without using a malicious payload.

---

## Detection

Sysmon captured the registry modification using:

```text
Event ID 13
```

The Sentinel analytics rule:

```text
Registry Run-Key Persistence
```

generated a Medium-severity incident.

The investigation reviewed:

- Registry path
- Registry value
- Process image
- User
- Host
- Event type
- Timestamp

---

## Risk

Windows Run keys can automatically launch programs when a user logs on.

Attackers can abuse these registry locations to maintain persistence.

The presence of an unexpected Run-key value therefore requires investigation.

---

## Containment Action

The test persistence entry was removed.

Example PowerShell command:

```powershell
Remove-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SOC-Lab-Persistence-Test"
```

---

## Verification

Sysmon generated:

```text
Event ID 12
```

for the registry deletion activity.

The final threat-hunting query showed both:

```text
Event 13 → SetValue
Event 12 → DeleteValue
```

This provided evidence that the persistence mechanism had been removed.

---

## Response Lifecycle

```text
Run Key Created
      ↓
Sysmon 13
      ↓
Sentinel Incident
      ↓
Analyst Investigation
      ↓
Remove Registry Value
      ↓
Sysmon 12
      ↓
Persistence Removal Verified
```

---

## Verification Query

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

---

## Analyst Validation Checklist

- [x] Persistence activity detected
- [x] Registry target identified
- [x] Associated user reviewed
- [x] Process image reviewed
- [x] Persistence value removed
- [x] Deletion event generated
- [x] Cleanup verified through Sysmon
- [x] Incident documented

---

## MITRE ATT&CK

```text
T1547.001 - Registry Run Keys / Startup Folder
Tactics:
- Persistence
- Privilege Escalation
```

---

## Evidence

Recommended screenshots:

```text
Screenshots/Investigation/05-Registry-Persistence-Details.png
Screenshots/Response/02-Registry-Persistence-Removal.png
Screenshots/Threat-Hunting/04-Registry-Persistence-Hunt.png
```

---

# 5. Response Exercise 3 — Active Directory Account Recovery

## Scenario

The Active Directory account:

```text
test-user
```

was intentionally locked through repeated invalid password attempts from:

```text
DESKTOP-82C5TLV
```

The domain policy used a lockout threshold of:

```text
5 invalid logon attempts
```

---

## Detection

Before recovery, the account state showed:

```text
badPwdCount = 5
LockedOut = True
```

Windows generated:

```text
Event ID 4740
```

The Sentinel rule:

```text
AD Account Lockout Detected
```

created a Medium-severity incident.

The final rule extracted:

```text
LockedAccount: test-user
CallerComputer: DESKTOP-82C5TLV
EventID: 4740
```

---

## Risk

Account lockout can be caused by:

- User mistakes
- Cached credentials
- Misconfigured services
- Password guessing
- Brute-force attempts
- Compromised hosts repeatedly using invalid credentials

For this reason, a lockout should be investigated before immediately unlocking the account in a real environment.

---

## Investigation Before Recovery

The analyst reviewed:

- Locked account
- Caller computer
- Failed authentication events
- Failed logon count
- Source IP / workstation
- Time of lockout
- Whether the activity was expected

In this lab, the activity was confirmed as controlled testing.

---

## Recovery Action

The account was unlocked using:

```powershell
Unlock-ADAccount -Identity "test-user"
```

---

## Account State Verification

After recovery:

```text
badPwdCount = 0
LockedOut = False
```

This verified that the account was restored successfully.

A useful validation command is:

```powershell
Get-ADUser -Identity "test-user" -Properties LockedOut,badPwdCount |
Select-Object SamAccountName,LockedOut,badPwdCount
```

Expected result after successful recovery:

```text
SamAccountName : test-user
LockedOut      : False
badPwdCount    : 0
```

---

## Security Event Verification

Windows generated:

```text
Event ID 4767
```

which represents:

```text
A user account was unlocked
```

The event showed:

```text
Subject: CORP\Administrator
Target: CORP\test-user
```

The same event was successfully ingested into Microsoft Sentinel.

---

## Verification Query

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "DC01.corp.local"
| where TargetAccount contains "test-user"
| where EventID in (4625, 4740, 4767)
| project
    TimeGenerated,
    EventID,
    SubjectAccount,
    TargetAccount,
    Activity
| order by TimeGenerated asc
```

---

## Timeline Summary Query

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

Observed lab result:

```text
4625 → 8 events
4740 → 1 event
4767 → 1 event
```

---

## Response Lifecycle

```text
Repeated Invalid Passwords
        ↓
4625 Failed Logons
        ↓
Lockout Threshold Reached
        ↓
4740 Account Locked
        ↓
Sentinel Incident
        ↓
Analyst Investigation
        ↓
Unlock-ADAccount
        ↓
Account State Normalized
        ↓
4767 Account Unlocked
        ↓
Recovery Verified in Sentinel
```

---

## Analyst Validation Checklist

- [x] Account lockout detected
- [x] Locked user identified
- [x] Caller computer identified
- [x] Failed authentication activity reviewed
- [x] Activity confirmed as controlled testing
- [x] Account unlocked
- [x] Account state checked
- [x] Unlock event generated
- [x] Unlock visible in Sentinel
- [x] Incident documented

---

## MITRE ATT&CK Context

```text
T1110.001 - Password Guessing
Tactic: Credential Access
```

The lockout is documented as a consequence of the controlled password-guessing activity.

---

## Evidence

Recommended screenshots:

```text
Screenshots/Investigation/06-Lockout-Incident-Details.png
Screenshots/Response/03-Account-Unlock-4767.png
Screenshots/Threat-Hunting/05-Account-Lockout-Recovery-Timeline.png
```

---

# 6. Detection vs Response Events

One of the most important lessons in the project was that a detection event and a response-verification event are often different.

The lab demonstrated:

```text
DETECTION                  RESPONSE VERIFICATION
---------                  ---------------------

4728                       4729
Member added               Member removed

Sysmon 13                  Sysmon 12
Registry value set         Registry value deleted

4740                       4767
Account locked             Account unlocked
```

This concept is valuable in incident response because it gives the analyst evidence that remediation actually occurred.

---

# 7. Containment Principles Demonstrated

The response exercises followed several important principles.

## 7.1 Investigate Before Acting

A security alert should not automatically trigger destructive remediation without context.

Before containment, identify:

```text
Affected user
Source computer
Process
Registry key
Group
Administrative actor
Timeline
```

---

## 7.2 Use the Least Disruptive Effective Action

Examples:

```text
Remove one unauthorized group membership
instead of deleting the account immediately

Remove one persistence registry value
instead of resetting the whole server

Unlock the affected user
after confirming the lockout is understood
```

---

## 7.3 Verify Every Response

A response is not considered complete until it is validated.

Examples:

```text
Remove user from group
→ verify 4729

Delete persistence
→ verify Sysmon 12

Unlock user
→ verify LockedOut=False and 4767
```

---

## 7.4 Preserve Evidence Before Cleanup

In a real incident, evidence should be collected before removing artifacts.

Relevant evidence may include:

- Event logs
- Process command lines
- Registry values
- Account activity
- Timestamps
- Network information
- Incident screenshots

In this lab, screenshots and KQL results were captured before cleanup where possible.

---

# 8. Incident Closure

Once the response was validated, the related Sentinel incidents were resolved.

Because the activity was intentionally generated inside the lab, closure notes used the equivalent of:

```text
Authorized security testing / expected activity.
Detection, investigation, containment, and verification completed successfully.
```

This prevents the incident history from being ambiguous.

---

# 9. Response Evidence Matrix

| Scenario | Detection | Containment / Recovery | Verification | Status |
|---|---|---|---|---|
| Privileged group change | 4728 | Remove `soc-priv-test` from Domain Admins | 4729 | Completed |
| Registry persistence | Sysmon 13 | Remove `SOC-Lab-Persistence-Test` | Sysmon 12 | Completed |
| Account lockout | 4740 | Unlock `test-user` | 4767 + account state | Completed |

---

# 10. Skills Demonstrated

The response phase demonstrates practical experience with:

- Active Directory incident response
- Privileged-access containment
- Registry persistence remediation
- Account recovery
- PowerShell administration
- Event-based verification
- Windows Security auditing
- Sysmon validation
- Microsoft Sentinel investigation
- KQL verification
- Incident closure
- Evidence-based remediation

---

# 11. Recommended Screenshot Structure

```text
Screenshots/Response/
├── 01-Privileged-Group-Removal-4729.png
├── 02-Registry-Persistence-Removal.png
└── 03-Account-Unlock-4767.png
```

Additional supporting evidence can remain under:

```text
Screenshots/Investigation/
Screenshots/Threat-Hunting/
Screenshots/Incidents/
```

---

# 12. Final Response Outcome

All three major response exercises were completed successfully.

The project demonstrated that the SOC could:

```text
Detect
↓
Investigate
↓
Contain / Recover
↓
Verify
↓
Close
```

The strongest evidence was that each response was validated with an independent system event rather than relying only on the analyst's command or assumption.

The next phase documents the Microsoft Sentinel SOAR / automation workflow that automatically added investigation tasks to new suspicious PowerShell incidents.

---

## Complete Screenshot Evidence

All screenshots from this project stage are retained in the detailed public-safe evidence galleries:

- [Response and containment evidence](../Screenshots/08-Response-Containment.md)
- [Incident evidence](../Screenshots/07-Incidents-Investigation.md)

