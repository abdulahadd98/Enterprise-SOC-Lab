# Complete Command Reference

This file consolidates the command-line work used during the Hybrid Enterprise SOC Lab.
Commands are grouped by the stage in which they were used. Repeated commands are shown once unless
a later variant was materially different.

> **Security:** Azure subscription IDs, tenant IDs, application/client IDs, secrets, resource IDs,
> passwords and tokens are intentionally replaced with placeholders. The original exposed Arc
> onboarding secret was revoked and must never be published.

---

## 1. Windows Server / Active Directory validation

```powershell
hostname
ipconfig /all
nslookup corp.local
nltest /dsgetdc:corp.local
dcdiag
dcdiag /test:dns
```

Time validation:

```powershell
Get-TimeZone
w32tm /query /status
w32tm /query /configuration
```

The server was configured for India Standard Time and synchronized with `time.windows.com`.

---

## 2. Azure Arc onboarding

The public-safe form of the Arc connection command is:

```powershell
$subscriptionId = "<AZURE-SUBSCRIPTION-ID>"
$tenantId       = "<MICROSOFT-ENTRA-TENANT-ID>"
$spAppId        = "<SERVICE-PRINCIPAL-APPLICATION-ID>"
$spSecret       = Read-Host "Enter NEW service principal secret"

& "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" connect `
  --subscription-id $subscriptionId `
  --resource-group "rg-soc-lab" `
  --location "centralindia" `
  --tenant-id $tenantId `
  --service-principal-id $spAppId `
  --service-principal-secret $spSecret `
  --tags "Environment=Lab,Project=Enterprise-SOC,Role=DomainController"
```

After successful onboarding:

```powershell
Remove-Variable spSecret -ErrorAction SilentlyContinue

& "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" show
```

The original screenshots contained real Azure identifiers and a temporary secret.
Public repository copies are intentionally redacted.

---

## 3. Azure Arc / extension troubleshooting

Commands captured during AMA/extension troubleshooting:

```powershell
Get-Process MonAgentCore -ErrorAction SilentlyContinue

& "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" extension list

Get-Service ExtensionService

Get-ChildItem "C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent" `
  -ErrorAction SilentlyContinue

Get-ChildItem "C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent" |
  Select-Object Name, LastWriteTime
```

Log inspection:

```powershell
Get-Content "C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent\extension.1.log" -Tail 80

Get-Content "C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent\state.json"
```

Connectivity / DNS troubleshooting included:

```powershell
nslookup pn.his.arc.azure.com 8.8.8.8
Get-Process MonAgentCore -ErrorAction SilentlyContinue
```

---

## 4. Failed-logon simulation from the Windows client

Interactive SMB authentication attempts were used to generate controlled failed logons.

```powershell
net use \\192.168.207.10\IPC$ /user:CORP\test-user *
```

The password was entered interactively and is not stored in the repository.

Other controlled tests used:

```powershell
net use \\192.168.207.10\IPC$ /user:CORP\soc-test *
net use \\192.168.207.10\IPC$ /delete /y
```

A related access test shown in the evidence used:

```powershell
net use \\192.168.207.10\IPC$ /user:CORP\hr-user *
```

---

## 5. Active Directory account state checks

```powershell
Get-ADUser test-user -Properties badPwdCount,LockedOut |
  Select-Object SamAccountName,badPwdCount,LockedOut
```

The same check was repeated before and after controlled authentication attempts.

---

## 6. Sysmon download and installation

Initial service / driver discovery:

```powershell
Get-Service sysmon* -ErrorAction SilentlyContinue

Get-CimInstance Win32_SystemDriver |
  Where-Object {$_.Name -like "Sysmon*"} |
  Select-Object Name, State
```

Create the working directory and download Sysmon:

```powershell
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force

Invoke-WebRequest `
  -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "C:\Tools\Sysmon\Sysmon.zip"

Expand-Archive `
  -Path "C:\Tools\Sysmon\Sysmon.zip" `
  -DestinationPath "C:\Tools\Sysmon" `
  -Force

Get-ChildItem C:\Tools\Sysmon
```

Configuration-file inspection:

```powershell
notepad C:\Tools\Sysmon\sysmonconfig.xml
Get-Content C:\Tools\Sysmon\sysmonconfig.xml
```

The configuration was saved in UTF-8 and validated:

```powershell
Set-Content "C:\Tools\Sysmon\sysmonconfig.xml" -Encoding UTF8
[xml]$config = Get-Content "C:\Tools\Sysmon\sysmonconfig.xml"
$config.Sysmon.schemaversion
```

Install Sysmon:

```powershell
cd C:\Tools\Sysmon

.\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml

Get-Service Sysmon64
```

Verify recent Sysmon events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
  Select-Object TimeCreated, Id, ProviderName
```

Generate a harmless process event:

```powershell
cmd.exe /c whoami
```

Validate Sysmon Event ID 1:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-Sysmon/Operational'
  Id        = 1
  StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message
```

---

## 7. Active Directory privileged-group simulation

The controlled privileged-access exercise used a disabled test account named `soc-priv-test`.

Public documentation uses the following safe commands:

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "soc-priv-test"
```

Containment:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "soc-priv-test"
```

Verification was performed through Event IDs `4728` and `4729`.

---

## 8. Suspicious PowerShell simulation

Harmless markers were used instead of malicious payloads.

Examples used during the project:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-RULE4-FINAL-TEST'"

powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-AUTOMATION-TEST'"

powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-AUTOMATION-TEST-2'"

powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output 'SOC-SOAR-FINAL-TEST'"
```

All of these were non-destructive test strings.

---

## 9. Registry Run-key persistence simulation

The controlled Run-key value was:

```text
SOC-Lab-Persistence-Test
```

The target location was:

```text
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```

A harmless Notepad executable was used.

Create / inspect the value:

```powershell
New-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SOC-Lab-Persistence-Test" `
  -Value "C:\Windows\System32\notepad.exe" `
  -PropertyType String `
  -Force

Get-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SOC-Lab-Persistence-Test"
```

Verify Sysmon Event ID 13:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-Sysmon/Operational'
  Id        = 13
  StartTime = (Get-Date).AddMinutes(-5)
} |
Where-Object {$_.Message -match 'SOC-Lab-Persistence-Test'} |
Select-Object -First 3 TimeCreated,Id,Message
```

Remove the persistence value:

```powershell
Remove-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SOC-Lab-Persistence-Test" `
  -ErrorAction SilentlyContinue
```

Confirm that the value no longer exists:

```powershell
Get-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SOC-Lab-Persistence-Test" `
  -ErrorAction SilentlyContinue
```

Verify Sysmon Event ID 12:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-Sysmon/Operational'
  Id        = 12
  StartTime = (Get-Date).AddMinutes(-10)
} |
Where-Object {$_.Message -match 'SOC-Lab-Persistence-Test'} |
Select-Object -First 5 TimeCreated,Id,Message
```

---

## 10. Account-lockout simulation and recovery

Check the current domain lockout policy:

```powershell
Get-ADDefaultDomainPasswordPolicy |
  Select-Object LockoutThreshold,LockoutDuration,LockoutObservationWindow
```

Check account state:

```powershell
Get-ADUser "test-user" -Properties badPwdCount,LockedOut |
  Select-Object SamAccountName,badPwdCount,LockedOut
```

Controlled incorrect SMB authentications were generated from the Windows client:

```powershell
net use \\DC01\IPC$ /user:CORP\test-user *
```

After the threshold was reached, Event ID `4740` was verified:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4740
  StartTime = (Get-Date).AddMinutes(-10)
} |
Select-Object -First 5 TimeCreated,Id,Message
```

Recover the account:

```powershell
Unlock-ADAccount -Identity "test-user"
```

Confirm recovery:

```powershell
Get-ADUser "test-user" -Properties badPwdCount,LockedOut |
  Select-Object SamAccountName,badPwdCount,LockedOut
```

Verify Event ID `4767`:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4767
  StartTime = (Get-Date).AddMinutes(-10)
} |
Select-Object -First 5 TimeCreated,Id,Message
```

---

## 11. KQL validation and hunting

All validated KQL is stored in:

```text
Detection-Rules/
KQL/
```

The final repository contains six detection queries and five threat-hunting queries.

The final SOAR marker validation query was:

```kusto
Event
| where TimeGenerated > ago(30m)
| where Computer == "DC01.corp.local"
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| where RenderedDescription contains "SOC-SOAR-FINAL-TEST"
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
```

---

## 12. Cleanup commands

Credential cleanup after Arc onboarding:

```powershell
Remove-Variable spSecret -ErrorAction SilentlyContinue
```

Lab response cleanup:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "soc-priv-test"

Remove-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SOC-Lab-Persistence-Test" `
  -ErrorAction SilentlyContinue

Unlock-ADAccount -Identity "test-user"
```

Azure role assignments and application secrets were also removed through the Azure portal after Arc onboarding was complete.

---

## Command evidence

The associated terminal screenshots are stored throughout:

```text
Screenshots/Azure-Arc/
Screenshots/Azure-Monitor/
Screenshots/Incidents/
Screenshots/Response/
Screenshots/Automation/
```

Screenshots that originally exposed real Azure credentials or identifiers are intentionally blurred in the public repository.


---

## 13. Privileged-group test account creation and membership verification

The disabled privilege-escalation test account was created with:

```powershell
New-ADUser `
  -Name "SOC-Priv-Test" `
  -SamAccountName "soc-priv-test" `
  -Path "CN=Users,DC=corp,DC=local" `
  -Enabled $false
```

Verify the account state:

```powershell
Get-ADUser soc-priv-test |
  Select-Object Name,SamAccountName,Enabled
```

Add the controlled test account to Domain Admins:

```powershell
Add-ADGroupMember `
  -Identity "Domain Admins" `
  -Members "soc-priv-test"
```

Verify membership:

```powershell
Get-ADGroupMember "Domain Admins" |
  Where-Object {$_.SamAccountName -eq "soc-priv-test"} |
  Select-Object Name,SamAccountName
```

Remove the account during containment:

```powershell
Remove-ADGroupMember `
  -Identity "Domain Admins" `
  -Members "soc-priv-test" `
  -Confirm:$false
```

Confirm that the account is no longer present:

```powershell
Get-ADGroupMember "Domain Admins" |
  Where-Object {$_.SamAccountName -eq "soc-priv-test"}
```

These commands produced the privileged-group detection and response evidence associated with
Windows Security Event IDs `4728` and `4729`.
