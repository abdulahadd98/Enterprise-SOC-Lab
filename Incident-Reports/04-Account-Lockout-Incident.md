# Incident Report — Active Directory Account Lockout

## Incident Summary

```text
Incident: #9
Rule: AD Account Lockout Detected
Severity: Medium
Host: DC01.corp.local
Locked Account: test-user
Caller Computer: DESKTOP-82C5TLV
Detection Event: 4740
Recovery Event: 4767
```

## Scenario

Repeated incorrect passwords were intentionally generated against:

```text
CORP\test-user
```

from the Windows 10 client.

The configured account-lockout threshold was five invalid attempts.

## Detection

The test produced:

```text
badPwdCount = 5
LockedOut = True
```

Windows Security Event ID `4740` was generated on `DC01`.

The Sentinel incident displayed:

```text
LockedAccount: test-user
CallerComputer: DESKTOP-82C5TLV
EventID: 4740
```

## Supporting Evidence

The associated threat hunt showed:

```text
4625 → 8 events
4740 → 1 event
4767 → 1 event
```

## Response

The account was restored using:

```powershell
Unlock-ADAccount -Identity "test-user"
```

## Verification

The account state was checked:

```text
badPwdCount = 0
LockedOut = False
```

Event ID `4767` confirmed the account unlock and was also visible in Sentinel.

## MITRE ATT&CK Context

```text
T1110.001 - Password Guessing
Tactic: Credential Access
```

The lockout is documented as a consequence of controlled repeated password failures.

## Evidence

```text
Screenshots/Incidents/06-AD-Account-Lockout-Incident.png
Screenshots/Investigation/06-Lockout-Incident-Details.png
Screenshots/Response/03-Account-Unlock-4767.png
Screenshots/Threat-Hunting/05-Account-Lockout-Recovery-Timeline.png
```

## Final Classification

Authorized security-testing activity.

## Analyst Takeaway

Authentication incidents should be investigated as a timeline: failures, lockout, source host, response, and recovery verification.
