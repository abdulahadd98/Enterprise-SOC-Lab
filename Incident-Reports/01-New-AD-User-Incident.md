# Incident Report — New Active Directory User Created

## Incident Summary

```text
Incident: #2
Rule: New Active Directory User Created
Severity: Medium
Host: DC01.corp.local
Primary Event: 4720
```

## Scenario

A controlled Active Directory test account was created in the `corp.local` domain to validate identity monitoring in Microsoft Sentinel.

Test account used during validation:

```text
soc-detect-test
```

The event showed the action was performed by:

```text
CORP\Administrator
```

## Detection

Windows Security Event ID `4720` was generated on `DC01` and ingested into Microsoft Sentinel through the `SecurityEvent` table.

The custom analytics rule detected the event and generated Incident #2.

## Investigation

The analyst reviewed:

- New account name
- Creator account
- Domain controller
- Event ID
- Time of account creation
- Related account and group activity

## MITRE ATT&CK

```text
T1136.002 - Create Account: Domain Account
Tactic: Persistence
```

## Outcome

The activity was confirmed as authorized lab testing.

The test account was later removed after evidence collection.

## Evidence

```text
Screenshots/Incidents/02-New-AD-User-Incident.png
Screenshots/Investigation/02-New-AD-User-Details.png
```

## Analyst Takeaway

New account creation should be correlated with group membership changes and subsequent authentication to determine whether the account represents normal administration or suspicious persistence.
