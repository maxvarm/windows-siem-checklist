# Checklist for Windows AD Logging
This repository includes PowerShell script that checks for minimal requirements for onboarding Windows / Active Directory security logging into SIEM. The checklist is aimed to generate as few logs as possible to save SIEM license while retaining visibility of most common AD attacks.

It is centered around two log sources: WinEventLog Security and Microsoft Sysmon, which generates far better logs than its default Windows 4688, 4657, or 4663 alternatives. See Usage section for more details and these links for more information:

* https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
* https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon


# Usage
Run the script with administrative privileges. The script does not change any configurations and does not utilize any third-party utilities. It is a simple sequence of checks using auditpol.exe and powershell cmdlets.
```
powershell -ep bypass .\windows-siem-checklist.ps1
```
![Script Output](https://user-images.githubusercontent.com/24703293/232227229-0761c4e9-83bf-4b52-b71d-e9522881b14d.png)

# List of Checks
* **Event Log GPO**
  + Maxiumum security logs size is at least 102400kb
  + Retention method for security log is set to "As Needed"
* **Advanced Audit GPO**
  + Account Logon -> Credential Validation is set to "Success and Failure"
  + Account Logon -> Kerberos Authentication Service is set to "Success and Failure"
  + Account Logon -> Kerberos Service Ticket Operations is set to "Success and Failure"
  + Account Management -> Computer Account Management is set to "Success and Failure"
  + Account Management -> Security Group Management is set to "Success and Failure"
  + Account Management -> User Account Management is set to "Success and Failure"
  + Detailed Tracking -> DPAPI Activity is set to "Success and Failure"
  + DS Access -> Directory Service Access is set to "Success and Failure"
  + DS Access -> Directory Service Changes is set to "Success and Failure"
  + DS Access -> Directory Service Replication is set to "Success and Failure"
  + Logon/Logoff -> Logon is set to "Success and Failure"
  + Object Access -> File Share is set to "Success and Failure"
  + Object Access -> Other Object Access Events is set to "Success and Failure"
  + Policy Change -> Authentication Policy Change is set to "Success and Failure"
  + System -> Security System Extension is set to "Success and Failure"
* **Sysmon Global Config**
  + Sysmon is updated to at least 14.15 version
  + Sysmon service is currently active and running
  + Sysmon config has "HashAlgorithms" field set to MD5 or SHA256
  + Sysmon config has "CheckRevocation" field enabled
* **Sysmon Audit Config**
  + Sysmon detects process creation and logs event code 1
  + Sysmon detects process injection and logs event code 8
  + Sysmon detects LSASS memory dump and logs event code 10
  + Sysmon detects registry operations and logs event code 12-14


# Caveats
* The script can't check if GPO is applied for whole domain. Make sure your logging settings are consistent across AD by linking the logging group policy to domain object and run "gpupdate /Force" to apply it immediately.
* Proposed "Directory Service Access" and "Other Object Access Events" subcategories generate a lot of 4662 events, but they are the only reliable options to detect DPAPI backup key dump and DCSync attack. Try to filter it on SIEM side.
* The script does not check for all Sysmon configuration entries and performs only basic checks. If you are not sure what to enable - start with [this config](https://github.com/Neo23x0/sysmon-config)

