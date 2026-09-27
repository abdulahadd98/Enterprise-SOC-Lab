# Incident Report — Privileged AD Group Membership Change

## Incident Summary

```text
Incident: #4
Rule: Privileged AD Group Membership Change
Severity: High
Host: DC01.corp.local
Detection Event: 4728
Verification Event: 4729
```

## Scenario

A disabled test account:

```text
soc-priv-test
```

was temporarily added to:

```text
CORP\Domain Admins
```

to validate privileged-access monitoring.

## Detection

Event ID `4728` was generated and ingested into Microsoft Sentinel.

The incident exposed:

```text
Changed By: CORP\Administrator
Member Added: soc-priv-test
Privileged Group: CORP\Domain Admins
Event ID: 4728
```

## Investigation

The analyst verified:

- Who performed the change
- Which account received privilege
- Which privileged group was modified
- Whether the change was expected

## Response

The test user was removed from `Domain Admins`.

## Verification

Event ID `4729` confirmed the account had been removed from the privileged group.

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

## Final Classification

Authorized security-testing activity.

## Analyst Takeaway

Privilege-change detections are strongest when the investigation records the actor, affected member, target group, and a separate event proving containment.
