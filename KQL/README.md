# KQL Query Index

## Detection Rules

See [`../Detection-Rules/`](../Detection-Rules/):

1. `01-Repeated-Failed-Logons.kql`
2. `02-New-AD-User-Created.kql`
3. `03-Privileged-AD-Group-Change.kql`
4. `04-Suspicious-PowerShell.kql`
5. `05-Registry-Run-Key-Persistence.kql`
6. `06-AD-Account-Lockout.kql`

## Threat Hunts

1. `01-Failed-Logon-Hunt.kql`
2. `02-AD-Account-and-Group-Changes-Hunt.kql`
3. `03-Suspicious-PowerShell-Hunt.kql`
4. `04-Registry-Persistence-Hunt.kql`
5. `05-Account-Lockout-Recovery-Timeline.kql`

## Query screenshots

All query-development screenshots provided during the project are retained under:

- `../Screenshots/KQL/01-SecurityEvent-Ingestion-and-Validation/`
- `../Screenshots/KQL/02-Sysmon-Ingestion-and-Detection-Development/`
- `../Screenshots/Threat-Hunting/01-Final-Hunts/`

The five strongest final hunt screenshots are also available directly in
`../Screenshots/Threat-Hunting/`.
