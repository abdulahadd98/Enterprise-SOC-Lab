# SOAR and Incident Automation

## 1. Purpose

This document records the Security Orchestration, Automation, and Response (SOAR) phase of the Hybrid Enterprise SOC Lab.

The objective was to demonstrate that Microsoft Sentinel can do more than detect activity and create incidents. A matching incident can also trigger an automation workflow that helps standardize analyst triage.

The final working workflow was:

```text
Suspicious PowerShell Activity
        ↓
Sysmon Event ID 1
        ↓
Microsoft Sentinel Ingestion
        ↓
Suspicious PowerShell Analytics Rule
        ↓
New Sentinel Incident
        ↓
Standard Automation Rule
        ↓
Three Investigation Tasks Added Automatically
        ↓
SOC Analyst Investigation
        ↓
Classification and Closure
```

The final validation succeeded with Incident `#11`.

---

# 2. Automation Objective

The automation was designed for incidents created by the custom rule:

```text
Suspicious PowerShell Command Execution
```

The goal was not to automatically delete files, disable users, or perform destructive remediation.

Instead, the workflow automatically creates a consistent investigation checklist for the analyst.

This is appropriate for the lab because suspicious PowerShell activity can be legitimate administration or malicious behavior. Human review is therefore still required.

---

# 3. Detection Dependency

The automation depends on the PowerShell analytics rule documented in:

```text
Documentation/03-Detection-Rules.md
```

Primary telemetry:

```text
Table: Event
Event Log: Microsoft-Windows-Sysmon/Operational
Sysmon Event ID: 1
Host: DC01.corp.local
```

MITRE ATT&CK:

```text
T1059.001 - PowerShell
Tactic: Execution
```

The analytics rule looks for PowerShell process creation containing patterns such as:

```text
ExecutionPolicy Bypass
-NoProfile
-enc
EncodedCommand
-w hidden
-WindowStyle Hidden
```

These indicators are treated as investigation signals rather than proof of compromise.

---

# 4. Initial Automation Attempt — Enhanced Rule

An initial automation workflow was created using an Enhanced automation rule.

## Configuration

Name:

```text
Auto-Triage Suspicious PowerShell Incidents
```

Trigger:

```text
When case is created
```

Conditions included:

```text
Case type = Incident
Analytics Rule Name = Suspicious PowerShell Command Execution
```

Action:

```text
Create case tasks
```

Three tasks were configured:

```text
1. Review PowerShell process and command line
2. Check related events and persistence indicators
3. Contain, document, and close the incident
```

The rule appeared active in the portal.

---

# 5. Enhanced Rule Validation Attempt

A harmless test command was executed:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-AUTOMATION-TEST'"
```

The event was successfully:

```text
Generated locally
↓
Captured by Sysmon Event ID 1
↓
Ingested into Microsoft Sentinel
↓
Matched by the PowerShell analytics rule
```

However, the alert was correlated into an existing PowerShell incident instead of producing a clean new automation test.

That incident was resolved before continuing.

---

# 6. Second Enhanced Rule Test

A second harmless marker was used:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-AUTOMATION-TEST-2'"
```

Again, telemetry successfully reached Sentinel.

A new incident was eventually created:

```text
Incident #10
```

However, the incident Tasks panel did not show the three custom investigation tasks.

Only the portal's existing/default task content was visible.

The Enhanced automation rule also did not provide evidence that the intended action had run.

---

# 7. Troubleshooting Decision

At this point, the following components were already known to be working:

```text
PowerShell execution
        ↓
Sysmon
        ↓
Azure Monitor / Log Analytics
        ↓
Sentinel
        ↓
Analytics rule
        ↓
Incident creation
```

The remaining problem was specifically the task-creation automation.

Instead of repeatedly changing the same Enhanced workflow, the project switched to a Standard Microsoft Sentinel automation rule using explicit `Add task` actions.

This made the final automation easier to validate and document.

---

# 8. Enhanced Rule Cleanup

Before the final test:

- The old Enhanced automation rule was disabled.
- Incident `#10` was resolved.
- A clean new incident was required for the final validation.

This prevented the old automation path and previous active incident from confusing the final result.

The disabled Enhanced rule can remain as troubleshooting evidence if desired, but it should not be presented as the final working implementation.

---

# 9. Final Working Automation Rule

The final rule was created as a Standard automation rule.

## Rule Name

```text
SOC PowerShell Investigation Tasks
```

## Workspace

```text
law-soc-lab
```

## Trigger

```text
When incident is created
```

## Condition

The incident must originate from:

```text
Suspicious PowerShell Command Execution
```

## Status

```text
Active
```

## Expiration

```text
Indefinite
```

---

# 10. Automated Investigation Tasks

The automation rule uses three `Add task` actions.

## Task 1

Title:

```text
Review PowerShell process and command line
```

Priority:

```text
High
```

Purpose:

Review the user, process image, full PowerShell command line, parent process, host, and execution context.

The analyst should determine whether the activity is legitimate administration or potentially malicious execution.

---

## Task 2

Title:

```text
Check related events and persistence indicators
```

Priority:

```text
High
```

Purpose:

Review related telemetry for evidence of:

- Child processes
- Registry Run-key changes
- Account creation
- Privileged group changes
- Failed logons
- Other persistence indicators
- Related Windows Security or Sysmon activity

This encourages correlation instead of investigating the PowerShell event in isolation.

---

## Task 3

Title:

```text
Contain, document, and close the incident
```

Priority:

```text
High
```

Purpose:

If activity is unauthorized:

- Contain the affected host if required
- Stop or investigate the suspicious process
- Remove persistence
- Restrict or disable affected accounts where appropriate
- Preserve evidence
- Document findings
- Verify that the threat is no longer present
- Classify and close the incident

For authorized testing, the incident should be documented and closed as expected security-testing activity.

---

# 11. Final SOAR Validation

A final harmless PowerShell marker was executed on `DC01`:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-FINAL-TEST'"
```

This command was deliberately non-destructive.

---

# 12. Local Telemetry Verification

The execution was first verified locally through Sysmon.

Expected:

```text
Log: Microsoft-Windows-Sysmon/Operational
Event ID: 1
Marker: SOC-SOAR-FINAL-TEST
```

This proved that the endpoint telemetry existed before troubleshooting the cloud workflow.

Recommended evidence:

```text
Screenshots/Automation/08-SOAR-Final-Test-Sysmon-Event1.png
```

---

# 13. Sentinel Ingestion Verification

The final marker was then verified in Microsoft Sentinel using KQL.

```kusto
Event
| where TimeGenerated > ago(30m)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| where RenderedDescription contains "SOC-SOAR-FINAL-TEST"
| project
    TimeGenerated,
    Computer,
    EventID,
    RenderedDescription
| order by TimeGenerated desc
```

The query returned the expected event.

This confirmed:

```text
DC01
↓
Sysmon
↓
Azure Monitor Agent
↓
Log Analytics
↓
Microsoft Sentinel
```

Recommended evidence:

```text
Screenshots/Automation/09-SOAR-Final-Test-In-Sentinel.png
```

---

# 14. Final Incident Validation

The PowerShell analytics rule generated a fresh incident:

```text
Incident #11
```

The incident was created after the earlier test incident had been resolved, which made it suitable for a clean automation validation.

---

# 15. Automation Success

The Tasks panel for Incident `#11` automatically contained all three custom tasks:

```text
1. Review PowerShell process and command line
2. Check related events and persistence indicators
3. Contain, document, and close the incident
```

This was the final proof that the Standard automation rule was working correctly.

Recommended evidence:

```text
Screenshots/Automation/10-SOAR-Automated-Investigation-Tasks.png
```

---

# 16. Final Automation Workflow

```text
powershell.exe
-ExecutionPolicy Bypass
-NoProfile
        ↓
Sysmon Event ID 1
        ↓
Event Table
        ↓
Suspicious PowerShell Analytics Rule
        ↓
High-Severity Incident #11
        ↓
SOC PowerShell Investigation Tasks
        ↓
Task 1: Review PowerShell
Task 2: Check Related Activity
Task 3: Contain / Document / Close
        ↓
Analyst Review
        ↓
Expected Authorized Lab Activity
        ↓
Incident Resolved
```

---

# 17. Incident Closure

After validating the automatic task creation:

- The three investigation tasks were completed.
- Incident `#11` was resolved.
- The activity was classified as expected authorized security testing.

Recommended closure note:

```text
Authorized SOC lab validation.
Suspicious PowerShell detection and automation workflow successfully tested.
The incident automatically received all three investigation tasks.
No malicious payload or third-party system was involved.
```

---

# 18. Why Task Automation Was Chosen

The lab intentionally automated analyst workflow rather than destructive remediation.

Automatic containment can create risk if a detection has false positives.

For example, PowerShell may be used by:

- Administrators
- Microsoft management services
- Monitoring agents
- Scheduled tasks
- Security products

A safer workflow for this project is therefore:

```text
Detect automatically
↓
Create incident automatically
↓
Add investigation tasks automatically
↓
Keep analyst decision-making human-controlled
```

This demonstrates SOAR without pretending that every alert should trigger automatic blocking.

---

# 19. Automation Troubleshooting Lessons

## 19.1 A Working Detection Does Not Guarantee Working Automation

The lab proved that:

```text
Telemetry working
+
Analytics rule working
+
Incident created
```

does not automatically prove that the automation action executed.

Automation must be validated separately.

---

## 19.2 Always Use a Fresh Incident for Automation Testing

The first test was grouped into an existing incident.

This made it difficult to determine whether the automation rule had fired as intended.

The final validation used:

```text
Resolve previous incident
↓
Generate fresh event
↓
Wait for fresh incident
↓
Check Tasks panel
```

This produced much clearer evidence.

---

## 19.3 Avoid Repeated Test Noise

Repeated PowerShell tests generated several incidents during development.

Known PowerShell-related incident numbers included:

```text
#5
#7
#10
#11
```

Only the final successful validation should be emphasized in the project documentation.

Earlier incidents should be described as tuning and troubleshooting activity.

---

## 19.4 Disable Failed / Superseded Automation

The non-working Enhanced rule was disabled after the Standard rule was validated.

This reduces confusion and prevents multiple automation paths from acting on the same incident.

---

## 19.5 Test Each Layer Separately

The final troubleshooting workflow was:

```text
1. Verify command executed
2. Verify Sysmon event locally
3. Verify event in Sentinel
4. Verify analytics rule matched
5. Verify new incident created
6. Verify automation added tasks
```

This is much more effective than changing the entire pipeline at once.

---

# 20. SOAR Evidence Matrix

| Stage | Evidence | Result |
|---|---|---|
| Local process creation | Sysmon Event ID 1 | Passed |
| Cloud ingestion | Sentinel `Event` table | Passed |
| Detection | Suspicious PowerShell rule | Passed |
| Incident creation | Incident #11 | Passed |
| Automation trigger | Standard automation rule | Passed |
| Task creation | 3 custom SOC tasks | Passed |
| Analyst closure | Expected lab testing | Passed |

---

# 21. Recommended Screenshot Set

```text
Screenshots/Automation/
├── 01-Auto-Triage-PowerShell-Rule-Active.png
├── 02-SOAR-Test-Sysmon-Event1.png
├── 03-SOAR-Test-Event-In-Sentinel.png
├── 04-PowerShell-Alerts-Correlated-In-Existing-Incident.png
├── 05-SOAR-Test2-Sysmon-Event1.png
├── 06-SOAR-Test2-Event-In-Sentinel.png
├── 07-Standard-PowerShell-Automation-Rule-Active.png
├── 08-SOAR-Final-Test-Sysmon-Event1.png
├── 09-SOAR-Final-Test-In-Sentinel.png
└── 10-SOAR-Automated-Investigation-Tasks.png
```

For the final README, only the strongest screenshots are required.

Recommended README evidence:

```text
07-Standard-PowerShell-Automation-Rule-Active.png
09-SOAR-Final-Test-In-Sentinel.png
10-SOAR-Automated-Investigation-Tasks.png
```

The remaining screenshots can stay inside the detailed project folders.

---

# 22. GitHub Security Review

Before publishing automation screenshots, check for:

- Subscription IDs
- Tenant IDs
- Workspace IDs
- Email addresses
- Azure resource IDs
- Application IDs where unnecessary
- Client secrets
- Tokens
- Authentication information

The previously exposed Arc service-principal secret must never appear in the repository.

Only sanitized screenshots should be committed.

---

# 23. Skills Demonstrated

This phase demonstrates practical experience with:

- Microsoft Sentinel automation rules
- Incident-based triggers
- Rule conditions
- Automated task creation
- SOC workflow standardization
- PowerShell detection
- Sysmon validation
- KQL telemetry validation
- Incident triage
- Automation troubleshooting
- False-positive-aware response design
- Human-in-the-loop SOAR
- Incident closure

---

# 24. SOAR vs Full Automatic Remediation

This project demonstrates SOAR through automated incident triage rather than fully automatic remediation.

The difference is:

```text
This Project
------------

Alert
↓
Incident
↓
Automatically add investigation tasks
↓
Human analyst investigates
↓
Human analyst decides response
```

A more advanced production environment may also use playbooks or Logic Apps for actions such as:

```text
Disable account
Isolate endpoint
Block IP
Send Teams / email notification
Open ITSM ticket
Collect additional enrichment
```

Those actions were not required for this project because the goal was to build a safe, explainable, validated SOC workflow.

---

# 25. Final SOAR Outcome

The final automation implementation was successful.

The project demonstrated:

```text
Endpoint Activity
        ↓
Telemetry Collection
        ↓
Custom Detection
        ↓
Incident Creation
        ↓
Automated SOC Tasks
        ↓
Analyst Investigation
        ↓
Incident Closure
```

This completed the practical SOAR component of the Hybrid Enterprise SOC Lab.

The next documentation phase records the troubleshooting decisions and lessons learned across the complete project.

---

## Complete Screenshot Evidence

All screenshots from this project stage are retained in the detailed public-safe evidence galleries:

- [SOAR automation evidence](../Screenshots/10-SOAR-Automation.md)
- [Troubleshooting evidence](../Screenshots/11-Troubleshooting.md)

