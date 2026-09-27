# Incident Report — Registry Run-Key Persistence

## Incident Summary

```text
Incident: #6
Rule: Registry Run-Key Persistence
Severity: Medium
Host: DC01.corp.local
Detection Event: Sysmon 13
Verification Event: Sysmon 12
```

## Scenario

A harmless registry persistence value was created:

```text
SOC-Lab-Persistence-Test
```

under a Windows `CurrentVersion\Run` location.

The value referenced:

```text
notepad.exe
```

## Detection

Sysmon Event ID `13` captured the registry value modification.

The event was ingested into the Sentinel `Event` table and generated a Medium-severity incident.

## Investigation

The analyst reviewed:

- User
- Process image
- Registry target
- Registry value details
- Event type
- Host
- Timestamp

## Response

The test registry persistence value was removed.

## Verification

Sysmon Event ID `12` recorded the deletion activity.

The threat-hunting query later displayed both the creation and removal events.

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

## Final Classification

Authorized security-testing activity.

## Analyst Takeaway

Sysmon makes it possible to connect a persistence modification with the process, user, and later removal event, giving analysts stronger evidence than a simple registry snapshot.
