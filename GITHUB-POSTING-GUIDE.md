# GitHub Posting Guide

The repository is packaged as a public portfolio project.

## Recommended repository settings

**Repository name**

```text
Enterprise-SOC-Lab
```

**Description**

```text
Hybrid Active Directory SOC lab using Azure Arc, Microsoft Sentinel, Sysmon, KQL,
custom detections, threat hunting, incident response and SOAR automation.
```

**Suggested GitHub topics**

```text
cybersecurity
soc
microsoft-sentinel
azure
azure-arc
active-directory
sysmon
kql
threat-hunting
incident-response
detection-engineering
mitre-attack
blue-team
```

## Upload

Upload the **contents** of the `Enterprise-SOC-Lab` directory as the repository root.

The repository root should contain:

```text
README.md
Architecture/
Automation/
Commands/
Detection-Rules/
Documentation/
Incident-Reports/
KQL/
MITRE-ATTACK/
Screenshots/
PROJECT-STATUS.md
SECURITY-NOTES.md
```

Do not create an extra nested `Enterprise-SOC-Lab/Enterprise-SOC-Lab/` folder.

## Public-safety checks already applied

- The temporary Azure Arc client secret is not reproduced anywhere in the text documentation.
- Credential-bearing Arc screenshots use deliberately redacted public copies.
- Unique Azure identifiers in high-risk screenshots are obscured.
- Commands that originally contained cloud identifiers use placeholders.
- Raw conversation screenshots are not included outside the sanitized evidence package.

## Before pressing Publish

Check:

```text
[ ] README architecture image renders
[ ] SOAR Incident #11 image renders
[ ] Screenshot gallery links open
[ ] KQL files open as text
[ ] Detection-Rules files open as text
[ ] No secret/password/token appears in GitHub search
[ ] Repository is under the intended GitHub account
```

## Recommended files to show a recruiter first

1. `README.md`
2. `Architecture/Enterprise-SOC-Architecture.png`
3. `Documentation/03-Detection-Rules.md`
4. `Documentation/04-Threat-Hunting.md`
5. `Documentation/05-Incident-Investigation.md`
6. `Documentation/07-SOAR-Automation.md`
7. `Screenshots/10-SOAR-Automation.md`
8. `Commands/Complete-Command-Reference.md`

## After publishing

Keep the Azure lab only if you still need a live demonstration. Otherwise, perform the final Azure cost cleanup after
you have confirmed that the public repository contains every required configuration, query, screenshot and incident report.
