# Troubleshooting and Lessons Learned

## 1. Purpose

This document records the main troubleshooting steps, design decisions, and lessons learned while building the Hybrid Enterprise SOC, Threat Detection & Incident Response Lab.

The project was intentionally documented beyond the "happy path." Real SOC and cloud deployments rarely work perfectly on the first attempt. Recording failed approaches, root causes, corrections, and validation steps demonstrates practical troubleshooting ability and makes the project easier to reproduce.

The troubleshooting approach used throughout the project was:

```text
Observe the problem
        ↓
Identify the affected layer
        ↓
Verify the previous working layer
        ↓
Change one thing at a time
        ↓
Retest
        ↓
Collect evidence
        ↓
Document the fix
```

---

# 2. Troubleshooting Summary

Major issues encountered during the project included:

| # | Area | Problem | Final Resolution |
|---|---|---|---|
| 1 | Time / AD | Time configuration needed validation | Corrected timezone and verified Windows Time |
| 2 | Azure Arc | Device-code authentication blocked | Used a temporary service principal |
| 3 | Azure permissions | Arc registration required additional subscription-level access | Temporarily granted required permissions, then removed |
| 4 | Azure security | Temporary client secret used during onboarding | Revoked/removed secret after successful Arc connection |
| 5 | AMA / DCR | Telemetry did not appear immediately | Validated Arc → AMA → DCR → workspace → query path |
| 6 | Sysmon | Raw fields were embedded in RenderedDescription | Parsed fields with KQL `extract()` |
| 7 | Registry hunting | Event 12 and 13 text formats differed | Used `coalesce()` to support both formats |
| 8 | Lockout detection | TargetAccount was not clean enough for alert display | Extracted `LockedUser` and `CallerComputer` separately |
| 9 | Account timeline hunt | Complex query generated semantic errors | Replaced it with a simpler reliable query |
| 10 | PowerShell testing | New alerts were grouped into an existing incident | Resolved old incident before clean automation validation |
| 11 | SOAR | Enhanced automation rule did not add expected custom tasks | Rebuilt workflow as a Standard automation rule |
| 12 | Documentation | Screenshots contained sensitive Azure identifiers | Added redaction rules before GitHub publishing |

---

# 3. Lesson 1 — Validate the Local Infrastructure Before the Cloud Layer

Before troubleshooting Azure, the local domain controller was checked first.

Important checks included:

```powershell
hostname
```

```cmd
ipconfig /all
```

```cmd
nslookup corp.local
```

```cmd
nltest /dsgetdc:corp.local
```

```cmd
dcdiag
```

```cmd
dcdiag /test:dns
```

Expected environment:

```text
Hostname: DC01
Domain: corp.local
IP: 192.168.207.10
DNS: 192.168.207.10
Gateway: 192.168.207.2
```

### Lesson

Do not troubleshoot Sentinel ingestion while the domain controller, DNS, networking, or time configuration is unstable.

Always prove the source system is healthy first.

---

# 4. Lesson 2 — Time Configuration Matters

Correct time is important for:

- Kerberos authentication
- Active Directory
- Event timestamps
- Incident timelines
- Cloud telemetry correlation

The server timezone was corrected to:

```text
India Standard Time
```

Windows Time was validated with commands such as:

```cmd
w32tm /query /status
```

and configured to use:

```text
time.windows.com
```

### Lesson

A timestamp mismatch can make a healthy event appear missing when the real problem is time interpretation.

Before assuming telemetry failed, verify:

```text
Server time
Timezone
Query time range
Azure portal time display
```

---

# 5. Lesson 3 — Azure Arc Authentication Can Be Blocked by Tenant Security

## Problem

The original Azure Arc onboarding attempt used device-code authentication.

The sign-in flow was blocked by tenant security settings.

The error showed that the authentication method was not permitted under the environment's security configuration.

## Resolution

A dedicated service principal was temporarily created for Arc onboarding.

The service principal allowed the Arc agent to authenticate non-interactively.

### Important Security Lesson

A service principal secret is a credential.

It must be protected exactly like a password.

The project therefore included explicit cleanup after onboarding.

---

# 6. Lesson 4 — Cloud Permissions Must Be Applied at the Correct Scope

## Problem

Arc onboarding also encountered a permission / registration problem.

The initial role assignment was not sufficient for all required subscription-level operations.

## Resolution

Temporary Contributor-level access was used at the required scope so the Azure Hybrid Compute registration/onboarding step could complete.

After successful setup:

```text
Temporary Contributor access was removed.
```

### Lesson

Azure permissions are scope-sensitive.

A user or service principal may have permission to work with one resource but still lack permission to:

- Register a resource provider
- Create a resource at another scope
- Assign or associate monitoring resources
- Perform subscription-level operations

Troubleshoot permission failures by checking:

```text
Identity
Role
Scope
Required operation
```

not only the role name.

---

# 7. Lesson 5 — Remove Temporary Privilege After Setup

The Arc onboarding workflow required temporary credentials and permissions.

After the setup was working:

- Temporary Contributor access was removed.
- The temporary application client secret was removed.
- The app registration showed no active client secret.

### Lesson

Successful deployment is not the end of the task.

Security cleanup is part of deployment.

The project follows:

```text
Grant temporary access
        ↓
Complete setup
        ↓
Validate service
        ↓
Remove unnecessary privilege
        ↓
Verify cleanup
```

This is a practical example of reducing unnecessary standing privilege.

---

# 8. Lesson 6 — Never Publish Secrets Even After Revocation

During troubleshooting, sensitive information appeared in screenshots.

This included cloud identifiers and a temporary application secret.

Even after revocation, that credential must never be copied into GitHub.

Public screenshots should be reviewed for:

```text
Client secrets
Tokens
Passwords
Subscription IDs
Tenant IDs
Workspace IDs
Machine IDs
Application IDs when unnecessary
Emails where unnecessary
Resource IDs
```

### Lesson

"Revoked" does not mean "safe to publish."

Secrets should be removed from documentation entirely.

---

# 9. Lesson 7 — Troubleshoot Telemetry as a Pipeline

## Problem

After Arc onboarding, telemetry did not immediately appear where expected.

Changing random Sentinel settings would have made troubleshooting harder.

Instead, the project validated the path layer by layer.

The pipeline was:

```text
DC01
↓
Azure Arc
↓
Azure Monitor Agent
↓
Data Collection Rule
↓
Log Analytics Workspace
↓
Microsoft Sentinel
↓
KQL query
```

## Validation Method

### Step 1

Confirm Arc connection.

Example:

```powershell
azcmagent show
```

### Step 2

Confirm Azure Monitor Agent deployment.

### Step 3

Confirm the DCR is associated with `DC01`.

### Step 4

Confirm the DCR destination is:

```text
law-soc-lab
```

### Step 5

Run a basic query before testing a complex rule.

Example:

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer == "DC01.corp.local"
| take 20
```

### Lesson

When data is missing, test the pipeline from left to right.

Do not start with the analytics rule if the underlying telemetry has not yet been proven.

---

# 10. Lesson 8 — Ingestion Delay Must Be Considered

Security telemetry is not always visible instantly.

During testing, events sometimes required time before appearing in Sentinel.

This affected:

- Detection validation
- Incident creation
- Automation testing

### Lesson

Use a reasonable query window while testing.

Example:

```kusto
| where TimeGenerated > ago(30m)
```

Also distinguish:

```text
Event generation time
TimeGenerated
Ingestion time
Analytics rule execution time
Incident creation time
```

The final account-lockout rule explicitly considered ingestion delay.

---

# 11. Lesson 9 — Inspect Raw Sysmon Events Before Writing Parsers

Sysmon events arrived in the `Event` table.

Important information such as:

```text
Image
CommandLine
User
ParentImage
TargetObject
Details
```

was embedded in:

```text
RenderedDescription
```

The project therefore used KQL parsing.

Example:

```kusto
extend
    Image = extract(@"Image:\s*(.*?)\s+FileVersion:", 1, RenderedDescription),
    CommandLine = extract(@"CommandLine:\s*(.*?)\s+CurrentDirectory:", 1, RenderedDescription)
```

### Lesson

Do not assume a field exists just because it appears in Event Viewer.

First inspect the raw event representation in the destination table.

Then build the parser around the actual stored structure.

---

# 12. Lesson 10 — Similar Sysmon Event IDs Can Have Different Text Layouts

## Problem

The registry hunting query initially parsed Event ID `13` correctly but did not handle Event ID `12` reliably.

The `TargetObject` field appeared next to different surrounding labels in the two event types.

## Resolution

The parser was changed to:

```kusto
TargetObject = coalesce(
    extract(@"TargetObject:\s*(.*?)\s+Details:", 1, RenderedDescription),
    extract(@"TargetObject:\s*(.*?)\s+User:", 1, RenderedDescription)
)
```

### Result

The corrected query returned both:

```text
SetValue
DeleteValue
```

events.

### Lesson

A parser should be tested against every event type it claims to support.

A query that works for one Sysmon event ID may not work unchanged for another.

---

# 13. Lesson 11 — Raw Account Fields May Need Normalization

## Problem

The first account-lockout analytics rule displayed an account value that was not ideal for incident triage.

Using the raw `TargetAccount` field made the alert less readable.

## Resolution

The final rule extracted a clean user field:

```kusto
LockedUser = iff(
    isempty(TargetUserName),
    tostring(split(TargetAccount, "\\")[1]),
    TargetUserName
)
```

It separately extracted the source/caller computer:

```kusto
CallerComputer = coalesce(
    tostring(column_ifexists("WorkstationName", "")),
    tostring(column_ifexists("Workstation", "")),
    TargetDomainName
)
```

### Result

The final incident displayed:

```text
LockedAccount: test-user
CallerComputer: DESKTOP-82C5TLV
```

### Lesson

Detection quality is not only about matching an event.

Good detections should present information in a way that helps the analyst investigate quickly.

---

# 14. Lesson 12 — Entity Mapping Improves Incident Quality

The account-lockout rule was improved by mapping:

```text
Account Name → LockedUser
```

and adding useful custom details.

### Lesson

Entity mapping helps turn a raw KQL result into a clearer SOC incident.

Important fields should be:

- Clean
- Human-readable
- Relevant to the investigation
- Separated by meaning

For example:

```text
Affected account
Source computer
Actor
Target group
Command line
Registry path
```

should not be collapsed into one confusing string.

---

# 15. Lesson 13 — Simpler KQL Can Be Better

## Problem

A more complex account-lockout timeline query using combinations of:

```text
let
union
case
```

generated semantic/query-engine errors during testing.

## Resolution

The final timeline was simplified to:

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

### Result

The query produced the needed evidence:

```text
4625 → 8
4740 → 1
4767 → 1
```

### Lesson

Complexity is not a goal.

The best query is the simplest query that reliably answers the investigation question.

---

# 16. Lesson 14 — Verify Detection Locally Before Blaming Sentinel

For every major test, the project followed:

```text
Generate Activity
↓
Verify Local Windows / Sysmon Event
↓
Verify Cloud Ingestion
↓
Verify Analytics Rule
↓
Verify Incident
```

Example for PowerShell:

```text
Run harmless PowerShell command
↓
Check Sysmon Event ID 1 locally
↓
Query Event table
↓
Confirm Sentinel rule
↓
Confirm incident
```

### Lesson

If the local event does not exist, Sentinel cannot detect it.

Always prove the source event first.

---

# 17. Lesson 15 — Detection Does Not Equal Compromise

The suspicious PowerShell query returned legitimate-looking SYSTEM activity as well as controlled Administrator activity.

PowerShell is used by:

- Administrators
- Management tools
- Microsoft services
- Security products
- Automation scripts

### Lesson

A detection is a signal for investigation.

It is not automatically proof that an attacker is present.

Analysts should review:

```text
User
Parent process
Command line
Host
Timing
Related changes
Expected administration
```

before deciding severity or response.

---

# 18. Lesson 16 — Separate Detection Evidence from Response Evidence

The project used different events to prove the beginning and end of an incident.

Examples:

```text
4728 = member added
4729 = member removed

Sysmon 13 = registry value set
Sysmon 12 = registry value deleted

4740 = account locked
4767 = account unlocked
```

### Lesson

A response action is stronger when another event proves it succeeded.

Do not document:

```text
"I ran the command, so the incident was fixed."
```

Prefer:

```text
"I performed the action and verified the resulting state/event."
```

---

# 19. Lesson 17 — Account Lockout Should Be Investigated Before Recovery

The lab account was intentionally locked, so it was safe to restore after confirming the scenario.

In a real environment, immediately unlocking an account without investigation could allow continued attack activity.

Before unlocking, review:

- Source computer
- Failed authentication count
- Target account
- Time window
- Other targeted users
- Successful logons
- Whether the activity is expected

### Lesson

Recovery should follow context validation.

---

# 20. Lesson 18 — Incident Grouping Can Affect Automation Testing

## Problem

The first SOAR test produced a new PowerShell alert but it was grouped into an existing open incident.

This made it difficult to prove whether the incident-created automation trigger had executed.

## Resolution

The existing PowerShell incident was resolved before the next clean validation.

### Lesson

When testing an automation with:

```text
Trigger = When incident is created
```

you need an actual new incident.

A new alert added to an old incident may not test the same trigger condition.

---

# 21. Lesson 19 — Test Automation Independently from Detection

The PowerShell detection itself was working before the automation was proven.

The project validated automation separately.

Final test sequence:

```text
1. Generate SOC-SOAR-FINAL-TEST
2. Verify Sysmon Event ID 1
3. Verify Event table
4. Wait for new PowerShell incident
5. Open Tasks
6. Confirm all three custom tasks
```

### Lesson

Do not say "SOAR works" merely because an incident exists.

The automation action itself must have visible evidence.

---

# 22. Lesson 20 — Enhanced Automation Did Not Produce the Expected Result

## Initial Design

An Enhanced automation rule was created with:

```text
Trigger: When case is created
Action: Create case tasks
```

The configuration looked correct in the portal.

## Problem

The expected three custom tasks did not appear in the new PowerShell incident.

The automation execution evidence also did not show the intended result.

## Decision

Rather than continuing to force the same implementation, the workflow was rebuilt using a Standard Sentinel automation rule.

### Lesson

A professional troubleshooting decision can be:

```text
Stop investing time in a path that is not producing verifiable results.
Use a simpler supported workflow that satisfies the security objective.
```

The important result is a working, tested control.

---

# 23. Lesson 21 — Standard Automation Rule Worked Reliably

Final rule:

```text
SOC PowerShell Investigation Tasks
```

Trigger:

```text
When incident is created
```

Condition:

```text
Analytics rule =
Suspicious PowerShell Command Execution
```

Actions:

```text
Add task:
Review PowerShell process and command line

Add task:
Check related events and persistence indicators

Add task:
Contain, document, and close the incident
```

Final validation:

```text
Incident #11
```

contained all three tasks.

### Lesson

Automation should be validated with a final clean test and a clear success condition.

For this project, success was:

```text
Fresh incident + exactly three custom tasks
```

---

# 24. Lesson 22 — Human-in-the-Loop Automation Was the Better Design

The project did not automatically disable users, delete files, or isolate machines.

Instead, it automatically created investigation tasks.

### Reason

PowerShell detections can have legitimate causes.

Fully automatic remediation can create business impact if a false positive occurs.

### Lesson

Automation should match confidence.

A useful maturity model is:

```text
Low confidence
→ enrich and assign tasks

Medium confidence
→ notify and require analyst approval

High confidence
→ consider automated containment
```

The lab intentionally used the first model.

---

# 25. Lesson 23 — Close Test Incidents After Validation

Repeated testing generated several incidents.

Leaving old incidents open caused confusion during later automation testing.

The project therefore resolved test incidents after evidence was captured.

Closure notes used the equivalent of:

```text
Authorized lab security testing.
Detection and validation completed.
```

### Lesson

Keeping the incident queue clean makes later tests easier to interpret.

---

# 26. Lesson 24 — Threat Hunting and Detection Rules Serve Different Purposes

The same data supported both automated rules and manual hunting.

Example:

```text
Detection:
Repeated failed logons automatically create an alert.

Hunt:
Summarize all failed logons by user and IP across 24 hours.
```

### Lesson

A mature SOC workflow needs both:

```text
Automated detection
+
Analyst-driven investigation
```

Threat hunting can reveal patterns that a single alert does not show.

---

# 27. Lesson 25 — Correlation Creates a Better Investigation Story

The strongest project evidence was not a single screenshot.

It was a sequence.

Examples:

```text
4625
↓
4740
↓
4767
```

```text
4728
↓
4729
```

```text
Sysmon 13
↓
Sysmon 12
```

### Lesson

A timeline is more valuable than isolated events.

When documenting an incident, show:

```text
Cause
Detection
Response
Verification
```

---

# 28. Lesson 26 — Keep Testing Harmless and Controlled

Security simulations used:

- Test accounts
- Incorrect lab passwords
- Harmless PowerShell markers
- Notepad-based Run-key persistence
- Controlled group membership changes

No malicious payload was required to validate the defensive controls.

### Lesson

A defensive lab can demonstrate valuable SOC skills without creating unnecessary risk.

The important part is the telemetry and investigation process.

---

# 29. Lesson 27 — Build Documentation While Testing

Throughout the project, screenshots were captured at major checkpoints.

This is much easier than trying to reconstruct evidence after the lab is complete.

Recommended evidence categories:

```text
Azure
Azure-Arc
Azure-Monitor
Sentinel
KQL
Detection
Incidents
Investigation
Response
Threat-Hunting
Automation
Troubleshooting
```

### Lesson

Treat documentation as part of the technical project, not an afterthought.

---

# 30. Lesson 28 — Screenshot Quality Matters

A GitHub repository should not contain every screenshot taken during troubleshooting.

Use screenshots that prove:

```text
Configuration
Detection
Investigation
Response
Automation
```

Avoid:

- Duplicate screenshots
- Blank portal pages
- Screenshots with irrelevant browser UI
- Screenshots containing secrets
- Screenshots that do not support a technical point

### Lesson

Evidence should strengthen the story, not overwhelm it.

---

# 31. Lesson 29 — Use Consistent Filenames

The project uses descriptive screenshot names.

Example:

```text
01-Failed-Logon-Hunt.png
02-AD-Account-and-Group-Changes-Hunt.png
03-Suspicious-PowerShell-Hunt.png
04-Registry-Persistence-Hunt.png
05-Account-Lockout-Recovery-Timeline.png
```

Automation examples:

```text
07-Standard-PowerShell-Automation-Rule-Active.png
09-SOAR-Final-Test-In-Sentinel.png
10-SOAR-Automated-Investigation-Tasks.png
```

### Lesson

A consistent naming convention makes the repository much easier to navigate.

---

# 32. Lesson 30 — Separate Detection KQL from Hunting KQL

The final repository uses:

```text
Detection-Rules/
```

for analytics-rule queries and:

```text
KQL/
```

for threat-hunting queries.

### Lesson

Although some queries may look similar, their operational purpose is different.

This structure makes the repository easier for an interviewer or SOC analyst to understand.

---

# 33. Lesson 31 — Use Dedicated Project Folders

The final repository structure separates:

```text
Architecture
Documentation
Detection-Rules
KQL
MITRE-ATTACK
Incident-Reports
Automation
Screenshots
```

### Lesson

A technical portfolio project should be navigable without requiring the reader to understand your personal file organization.

---

# 34. Lesson 32 — Document What Actually Worked

The project avoids presenting the failed Enhanced automation rule as the final solution.

Instead:

```text
Failed approach
→ documented as troubleshooting

Working Standard automation
→ documented as final implementation
```

### Lesson

A strong project does not need to pretend everything worked the first time.

Troubleshooting often demonstrates more practical skill than a perfect setup walkthrough.

---

# 35. Lesson 33 — Avoid Overclaiming MITRE Mapping

The account-lockout rule is a good example.

Event ID `4740` represents a lockout.

A lockout itself is not treated as a unique MITRE ATT&CK technique.

In the lab it was associated with:

```text
T1110.001 - Password Guessing
```

because the lockout was intentionally caused by repeated invalid password attempts.

### Lesson

ATT&CK mapping should describe the behavior being detected, not simply attach a technique to every Windows event.

---

# 36. Lesson 34 — Severity Is a Prioritization Aid, Not a Verdict

Examples:

```text
High:
Privileged group change
Suspicious PowerShell

Medium:
Failed logons
New user
Registry persistence
Account lockout
```

A High-severity incident can still be authorized administrative activity.

### Lesson

Severity tells the analyst what deserves attention first.

It does not independently determine whether something is malicious.

---

# 37. Lesson 35 — Preserve a Clean Final State

At the end of testing, cleanup included or should include:

```text
Remove test privilege
Remove registry persistence
Unlock test account
Resolve test incidents
Disable superseded automation
Remove temporary Azure secrets
Remove temporary excessive Azure permissions
```

Additional final cleanup can include deleting unused test accounts after evidence is complete.

### Lesson

A finished lab should not remain in a deliberately insecure test state.

---

# 38. Final Troubleshooting Methodology

The project produced a repeatable troubleshooting model.

## Endpoint Problem

```text
Did the event actually occur?
↓
Check Event Viewer / Sysmon
```

## Collection Problem

```text
Is the agent connected?
↓
Check Arc / AMA
```

## Routing Problem

```text
Is the DCR correct and associated?
```

## Storage Problem

```text
Does Log Analytics contain the event?
```

## Query Problem

```text
Does a basic KQL query return the event?
↓
Inspect raw fields
```

## Detection Problem

```text
Does the analytics rule query match?
↓
Check time window / frequency
```

## Incident Problem

```text
Was an alert generated?
Was it grouped into an existing incident?
```

## Automation Problem

```text
Was a fresh incident created?
Did the automation condition match?
Did the expected action occur?
```

This layered method prevents unrelated changes and reduces troubleshooting time.

---

# 39. Final Lessons Summary

The most important lessons from the project were:

1. Validate the source before troubleshooting the SIEM.
2. Build and test the telemetry pipeline one layer at a time.
3. Inspect raw event structure before writing KQL parsers.
4. Prefer simple reliable queries over unnecessary complexity.
5. Improve detections with clean field extraction and entity mapping.
6. Treat detections as investigation signals, not proof of compromise.
7. Verify remediation with independent evidence.
8. Test automation separately from detection.
9. Use fresh incidents for incident-created automation testing.
10. Remove temporary credentials and privileges after cloud onboarding.
11. Never publish secrets or sensitive cloud identifiers.
12. Document failed approaches as lessons, but present only validated controls as final solutions.
13. Keep security testing controlled and harmless.
14. Maintain a clean evidence structure for GitHub.
15. Build documentation as part of the project, not after it.

---

# 40. Project Outcome

The troubleshooting phase strengthened the project because the final environment was not merely configured — it was repeatedly validated and corrected.

The finished workflow successfully demonstrated:

```text
Active Directory
        ↓
Windows Security + Sysmon
        ↓
Azure Arc
        ↓
Azure Monitor Agent
        ↓
Data Collection Rules
        ↓
Log Analytics
        ↓
Microsoft Sentinel
        ↓
Custom Detections
        ↓
Incidents
        ↓
Threat Hunting
        ↓
Containment / Recovery
        ↓
Verification
        ↓
SOC Automation
```

The lab therefore demonstrates not only SOC tooling knowledge, but also practical troubleshooting, evidence validation, cloud-security hygiene, and incident-response discipline.

This completes the detailed technical documentation phase of the Hybrid Enterprise SOC Lab.

---

## Complete Screenshot Evidence

All screenshots from this project stage are retained in the detailed public-safe evidence galleries:

- [Troubleshooting evidence](../Screenshots/11-Troubleshooting.md)
- [Azure Arc evidence](../Screenshots/02-Azure-Arc.md)
- [Security cleanup evidence](../Screenshots/12-Security-Cleanup.md)

