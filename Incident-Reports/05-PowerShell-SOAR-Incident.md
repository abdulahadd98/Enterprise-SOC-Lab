# Incident Report — Suspicious PowerShell with SOC Automation

## Incident Summary

```text
Final Validation Incident: #11
Rule: Suspicious PowerShell Command Execution
Severity: High
Host: DC01.corp.local
Primary Event: Sysmon 1
```

## Scenario

A harmless PowerShell command was executed to validate the complete detection and automation chain:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-FINAL-TEST'"
```

## Detection

The command was captured locally by Sysmon Event ID `1`.

The same telemetry was then confirmed in Microsoft Sentinel.

The custom PowerShell analytics rule generated a fresh incident.

## Automation

The Standard Sentinel automation rule:

```text
SOC PowerShell Investigation Tasks
```

was configured to run when a new incident was created by the PowerShell analytics rule.

Incident #11 automatically received:

```text
1. Review PowerShell process and command line
2. Check related events and persistence indicators
3. Contain, document, and close the incident
```

## Investigation

The analyst reviewed:

- User
- Process image
- Command line
- Parent process
- Host
- Related Sysmon events
- Persistence indicators
- Related identity activity

## MITRE ATT&CK

```text
T1059.001 - PowerShell
Tactic: Execution
```

## Outcome

The event was confirmed as an authorized final SOAR validation.

After documenting the three automatically created tasks, the incident was resolved as expected security testing.

## Evidence

```text
Screenshots/Automation/08-SOAR-Final-Test-Sysmon-Event1.png
Screenshots/Automation/09-SOAR-Final-Test-In-Sentinel.png
Screenshots/Automation/10-SOAR-Automated-Investigation-Tasks.png
```

## Final Classification

Authorized security-testing activity.

## Analyst Takeaway

This case demonstrates the complete chain from endpoint telemetry to detection, incident creation, automated triage tasks, analyst review, and closure.
