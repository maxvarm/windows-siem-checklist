#Requires -RunAsAdministrator

function Msg-Title {
    param ($msg)
    Write-Host
    Write-Host ("===" * 30)
    Write-Host "[!] $msg"
    Write-Host ("===" * 30)
}

function Msg-Pass {
    param ($msg)
    Write-Host "[+] Passed: " -ForegroundColor "GREEN" -NoNewLine
    Write-Host "$msg";
}

function Msg-Fail {
    param ($msg)
    Write-Host "[-] Failed: " -ForegroundColor "RED" -NoNewLine
    Write-Host "$msg";
}

function Msg-Info {
    param ($msg)
    Write-Host "[*] Guide: " -ForegroundColor "BLUE" -NoNewLine
    Write-Host "$msg";
}

# Checks by using 'Get-LogProperties' powershell cmdlet
function Get-LoggingLimits {
    Msg-Info "1. From Domain Controller, Open Group Policy Management (gpmc.exe)"
    Msg-Info "2. Open existing or create new Group Policy linked to the whole AD domain"
    Msg-Info "3. Go to Computer Configuration -> Windows Settings -> Security Settings"
    Msg-Info "4. Proceed to Event Log, set Retention method for security logs to 'As needed'"
    Msg-Info "5. Set 'Maximum security log size' policy to at least 102400 kilobytes"
    Msg-Info "6. Save the settings by running 'gpupdate /Force' and verify the changes"
    Write-Host ""
    $data = Get-LogProperties 'Security'
    $maxSize = [math]::floor($data.MaxLogSize / 1024)
    if ($data.Retention -eq $true) {
        Msg-Fail "(Incorrect Retention) Event Log -> Retention method for security log"
    }
    else {
        Msg-Pass "(Correct Retention) Event Log -> Retention method for security log"
    }
    if ($maxSize -lt 102400) {
        Msg-Fail "(${maxSize}kb < 102400kb) Event Log -> Maximum security log size"
    }
    else {
        Msg-Pass "(${maxSize}kb >= 102400kb) Event Log -> Maximum security log size"
    }
}

# Checks by using auditpol.exe functionality
function Get-LoggingSettings {
    Msg-Info "1. From Domain Controller, Open Group Policy Management (gpmc.exe)"
    Msg-Info "2. Open existing or create new Group Policy linked to the whole AD domain"
    Msg-Info "3. Go to Computer Configuration -> Windows Settings -> Security Settings"
    Msg-Info "4. Proceed to Advanced Audit Policy Configuration -> Audit Policies"
    Msg-Info "5. For each mentioned entry, make sure it is set as 'Success and Failure'"
    Msg-Info "6. Save the settings by running 'gpupdate /Force' and verify the changes"
    Write-Host ""
    $checklistuple = @(
        @("Credential Validation", "Account Logon"),
        @("Kerberos Authentication Service", "Account Logon"),
        @("Kerberos Service Ticket Operations", "Account Logon"),
        @("Computer Account Management", "Account Management")
        @("Security Group Management", "Account Management"),
        @("User Account Management", "Account Management"),
        @("DPAPI Activity", "Detailed Tracking"),
        @("Directory Service Access", "DS Access"),
        @("Directory Service Changes", "DS Access"),
        @("Directory Service Replication", "DS Access"),
        @("Logon", "Logon/Logoff"),
        @("File Share", "Object Access"),
        @("Other Object Access Events", "Object Access"),
        @("Authentication Policy Change", "Policy Change"),
        @("Security System Extension", "System")
    )
    $binpath = "$env:SystemDrive/Windows/System32/auditpol.exe"
    foreach ($item in $checklistuple) {
        $subcategory = $item[0]
        $category = $item[1]

        $data = & $binpath /get /subcategory:"$subcategory" | Out-String
        $data -match "$subcategory\s+(?<status>.+\w)" | Out-Null
        $status = $Matches.status
        if ($status -eq "Success and Failure") {
            Msg-Pass "(Audit OK) $category -> Audit $subcategory"
        }
        else {
            Msg-Fail "($status) $category -> Audit $subcategory"
        }
    }
}

# Checks by simply matching 'Sysmon64.exe -c' output
function Get-SysmonStatus {
    Msg-Info "1. Make sure to update Sysmon to 14.15 to patch CVE-2022-41120 vulnerabilty"
    Msg-Info "2. Verify that its service is running by running 'Get-Service Sysmon64'"
    Msg-Info "3. Ensure your Sysmon config has 'HashAlgorithms' field set to MD5 or SHA256"
    Msg-Info "4. Ensure your Sysmon config has 'CheckRevocation' field enabled"
    Write-Host ""
    $binpath = "$env:SystemDrive\Windows\Sysmon64.exe"
    $data = & $binpath -c 2>$null | Out-String
    $data -match "System Monitor v(?<major>\d+)\.(?<minor>\d+) - " | Out-Null
    $major = [int]$Matches.major
    $minor = [int]$Matches.minor
    if ($major -lt 14 -or ($major -eq 14 -and $minor -lt 14)) {
        Msg-Fail "(v$major.$minor Installed) Sysmon version is outdated and vulnerable"
    }
    else {
        Msg-Pass "(v$major.$minor Installed) Sysmon version is new, stable and patched"
    }
    if ((Get-Service -ErrorAction SilentlyContinue SysmonDrv).Status -eq "Running") {
        Msg-Pass "(Sysmon Enabled) Sysmon service is in operational, running status"
    }
    else {
        Msg-Pass "(Sysmon Disabled) Sysmon service is either disabled or stopped"
    }
    if ($data -match "CRL checking:\s+enabled") {
        Msg-Pass "(CRL Enrichment OK) CRL checking is enabled and logged by Sysmon"
    }
    else {
        Msg-Fail "(CRL Enrichment Disabled) CRL checking is disabled and not logged by Sysmon"
    }
    if ($data -match "HashingAlgorithms:\s+(MD5|SHA)") {
        Msg-Pass "(Hash Enrichment OK) Hash calculation of started processes is enabled in Sysmon"
    }
    else {
        Msg-Fail "(Hash Enrichment Disabled) Hash calculation of started processes is disabled in Sysmon"
    }
}

# Checks by using 'Get-WinEvent' powershell cmdlet
function Get-SysmonSettings {
    Msg-Info "1. Apply the config from here https://github.com/Neo23x0/sysmon-config"
    Msg-Info "2. Or, if using custom config, make sure to log at least the following:"
    Msg-Info "3. Event code 1, process creation, avoid making  wildcard exclusions"
    Msg-Info "4. Event code 8, remote thread creation, at least into system processes"
    Msg-Info "5. Event code 10, process access, detect credentials dump from LSASS memory"
    Msg-Info "6. Event code 12-14, registry operation, detect various persistence methods"
    Write-Host ""
    $ErrorActionPreference = "silentlycontinue"
    $log = "Microsoft-Windows-Sysmon/Operational"
    $checklistuple = @(
        @("1", "Process creation",
        (Get-WinEvent -MaxEvents 1 @{logname=$log;id="1"})),
        @("8", "Process injection",
        (Get-WinEvent -MaxEvents 1 @{logname=$log;id="8"})),
        @("10", "LSASS memory dump",
        ((Get-WinEvent -MaxEvents 1 @{logname=$log;id="10"}).Message -match "\\system32\\lsass.exe")),
        @("12", "Registry operations",
        (Get-WinEvent -MaxEvents 1 @{logname=$log;id="12"}))
    )
    foreach ($item in $checklistuple) {
        $code = $item[0]
        $text = $item[1]
        $status = $item[2]
        if ($status) {
            Msg-Pass "(Event Code $code OK) $text can be detected and logged"
        }
        else {
            Msg-Fail "(Event Code $code Error) $text logging is likely not enabled"
        }
    }
    $ErrorActionPreference = "continue"
}


Msg-Title "Security Logging Limits and Retention Check"
Get-LoggingLimits
Msg-Title "Security Logging Advanced Audit Policy Check"
Get-LoggingSettings

if (Get-Service -ErrorAction SilentlyContinue SysmonDrv) {
    Msg-Title "Sysmon Status and Global Configuration Check"
    Get-SysmonStatus
    Msg-Title "Sysmon Logging and Detection Scope Check"
    Get-SysmonSettings
}
else {
    Msg-Title "Sysmon is not Enabled and not Installed"
    Msg-Info "1. Download it here https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
    Msg-Info "2. Create custom config or use a good one https://github.com/Neo23x0/sysmon-config"
    Msg-Info "3. Install Sysmon as administrator by running 'Sysmon64.exe -c <config.xml>'"
    Write-Host ""
    Msg-Fail "(Sysmon Not Installed) Sysmon is a great, required extension to Windows logging"
}

Write-Host