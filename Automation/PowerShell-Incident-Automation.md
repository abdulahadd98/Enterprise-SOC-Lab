# SOC PowerShell Investigation Tasks — Automation Reference

## Final Working Rule

```text
Name: SOC PowerShell Investigation Tasks
Type: Standard automation rule
Trigger: When incident is created
Condition: Analytics rule name = Suspicious PowerShell Command Execution
Status: Active
Expiration: Indefinite
```

## Actions

```text
1. Add task
   Review PowerShell process and command line

2. Add task
   Check related events and persistence indicators

3. Add task
   Contain, document, and close the incident
```

## Final Validation

```text
Marker: SOC-SOAR-FINAL-TEST
Telemetry: Sysmon Event ID 1
Final Incident: #11
Result: All 3 custom tasks automatically created
```

## Important Note

The earlier Enhanced automation-rule attempt did not produce the expected custom tasks and was disabled.

The Standard automation rule above is the final validated implementation.
