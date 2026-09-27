# MITRE ATT&CK Mapping

This document maps the six custom Microsoft Sentinel detections in the Hybrid Enterprise SOC Lab to relevant MITRE ATT&CK techniques.

> The mapping describes the behavior represented by the controlled lab activity. A Windows event by itself is not automatically proof that an ATT&CK technique occurred maliciously.

## Coverage Summary

| # | Detection | ATT&CK Tactic | Technique |
|---|---|---|---|
| 1 | Repeated Failed Logons | Credential Access | T1110.001 — Password Guessing |
| 2 | New Active Directory User Created | Persistence | T1136.002 — Create Account: Domain Account |
| 3 | Privileged AD Group Membership Change | Persistence / Privilege Escalation | T1098.007 — Additional Local or Domain Groups |
| 4 | Suspicious PowerShell Command Execution | Execution | T1059.001 — PowerShell |
| 5 | Registry Run-Key Persistence | Persistence / Privilege Escalation | T1547.001 — Registry Run Keys / Startup Folder |
| 6 | AD Account Lockout Detected | Credential Access context | T1110.001 — Password Guessing |

---

## 1. Repeated Failed Logons

**MITRE ATT&CK Technique:** T1110.001 — Password Guessing  
**Tactic:** Credential Access  
**Data Source:** Windows Security Event ID 4625

### Detection

The Microsoft Sentinel analytics rule identifies repeated failed authentication attempts against Active Directory accounts.

### Lab Validation

Controlled incorrect-password attempts were generated against test accounts from the Windows client. Event ID 4625 was collected from DC01 and ingested into Microsoft Sentinel.

### SOC Relevance

Repeated authentication failures can indicate password guessing, but they can also result from user mistakes, cached credentials, or service misconfiguration. The alert therefore requires investigation.

Official reference: https://attack.mitre.org/techniques/T1110/001/

---

## 2. New Active Directory User Created

**MITRE ATT&CK Technique:** T1136.002 — Create Account: Domain Account  
**Tactic:** Persistence  
**Data Source:** Windows Security Event ID 4720

### Detection

The custom Sentinel rule detects creation of a new Active Directory domain user account.

### Lab Validation

A controlled test account was created in `corp.local`. DC01 generated Event ID 4720 and Sentinel created an incident.

### SOC Relevance

Unauthorized domain-account creation may be used to maintain credentialed access.

Official reference: https://attack.mitre.org/techniques/T1136/002/

---

## 3. Privileged Active Directory Group Membership Change

**MITRE ATT&CK Technique:** T1098.007 — Account Manipulation: Additional Local or Domain Groups  
**Tactics:** Persistence / Privilege Escalation  
**Data Source:** Windows Security Event IDs 4728 and 4729

### Detection

The Sentinel analytics rule detects when an account is added to a privileged Active Directory group.

### Lab Validation

A disabled test account named `soc-priv-test` was temporarily added to `CORP\Domain Admins`.

DC01 generated Event ID 4728 and Sentinel created a High-severity incident.

### Response

The account was removed from Domain Admins and Event ID 4729 was used to verify containment.

### SOC Relevance

Adding an existing account to a privileged group may be used to preserve access or obtain elevated permissions.

Official reference: https://attack.mitre.org/techniques/T1098/007/

---

## 4. Suspicious PowerShell Command Execution

**MITRE ATT&CK Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Tactic:** Execution  
**Data Source:** Sysmon Event ID 1

### Detection

The Sentinel rule uses Sysmon process creation telemetry to identify PowerShell command lines containing selected suspicious patterns.

### Lab Validation

Harmless test markers were executed with flags such as:

```text
-ExecutionPolicy Bypass
-NoProfile
```

The final SOAR validation used:

```text
SOC-SOAR-FINAL-TEST
```

### SOAR Validation

This detection was used to create a fresh incident that automatically received three SOC investigation tasks.

### SOC Relevance

PowerShell is a legitimate administrative tool that can also be abused for execution. Context such as user, parent process, command line, and related activity must be reviewed.

Official reference: https://attack.mitre.org/techniques/T1059/001/

---

## 5. Registry Run-Key Persistence

**MITRE ATT&CK Technique:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder  
**Tactics:** Persistence / Privilege Escalation  
**Data Source:** Sysmon Event IDs 12 and 13

### Detection

The Sentinel rule detects modifications to Windows `CurrentVersion\Run` locations.

### Lab Validation

A controlled value named:

```text
SOC-Lab-Persistence-Test
```

was created and pointed to a harmless Notepad executable.

Sysmon Event ID 13 captured the change.

### Response

The value was removed and Sysmon Event ID 12 was used to verify cleanup.

### SOC Relevance

Registry Run keys can cause programs to execute when a user logs on, making them useful persistence locations.

Official reference: https://attack.mitre.org/techniques/T1547/001/

---

## 6. Active Directory Account Lockout Detected

**MITRE ATT&CK Technique Context:** T1110.001 — Password Guessing  
**Tactic:** Credential Access  
**Data Sources:** Windows Security Event IDs 4625, 4740, and 4767

### Detection

The Sentinel rule detects Event ID 4740 and extracts the locked user and caller computer.

### Lab Validation

Repeated incorrect passwords were generated against `CORP\test-user` from the Windows client.

The lab observed:

```text
badPwdCount = 5
LockedOut = True
```

and Event ID 4740.

### Response

The user was unlocked with:

```powershell
Unlock-ADAccount -Identity "test-user"
```

The recovery was verified with:

```text
badPwdCount = 0
LockedOut = False
Event ID 4767
```

### Mapping Note

Account lockout is not treated as a separate ATT&CK technique. In this lab, the lockout was the consequence of controlled repeated password guessing, so it is documented in the context of T1110.001.

Official reference: https://attack.mitre.org/techniques/T1110/001/

---

## Final Coverage

```text
Credential Access
├── T1110.001 Password Guessing
│   ├── Repeated Failed Logons
│   └── AD Account Lockout Context
│
Persistence
├── T1136.002 Domain Account
├── T1098.007 Additional Local or Domain Groups
└── T1547.001 Registry Run Keys / Startup Folder
│
Privilege Escalation
├── T1098.007 Additional Local or Domain Groups
└── T1547.001 Registry Run Keys / Startup Folder
│
Execution
└── T1059.001 PowerShell
```
