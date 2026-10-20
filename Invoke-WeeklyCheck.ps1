#Requires -Version 5.1
<#
.SYNOPSIS
    Weekly check of %LOCALAPPDATA%\Packages, emailed via Resend. Run by the
    PermissionTrap-WeeklyCheck scheduled task (as you, not elevated); you do
    not normally run it yourself.

.DESCRIPTION
    1. Decides whether this week's check is due: it is if no check has
       succeeded since the most recent Sunday 18:00. The task also runs at
       every logon, so a check missed while the laptop was off happens at
       the next logon; otherwise it logs SKIP and stops. -Force skips this.
    2. Checks Packages and every app folder in it for missing SYSTEM
       (S-1-5-18) or Administrators (S-1-5-32-544) - the same check as part 1
       of Get-PermissionReport.ps1.
    3. Emails the result via Resend: the affected folders and what to do, or
       "all clear" with how many weekly checks in a row have been clear.
    4. Logs the run to C:\ProgramData\PermissionTrap\weekly.log.

    If the email cannot be sent, the check is not counted as done, so it is
    tried again at the next logon or Sunday.

    Settings come from weekly-config.json, written by Install-WeeklyCheck.ps1.
    The Resend API key is in weekly-resend.key, encrypted with DPAPI for your
    Windows account only.

.PARAMETER Force
    Run the check even if this week's check was already done.
#>
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$StateDir   = Join-Path $env:ProgramData 'PermissionTrap'
$ConfigFile = Join-Path $StateDir 'weekly-config.json'
$KeyFile    = Join-Path $StateDir 'weekly-resend.key'
$StateFile  = Join-Path $StateDir 'weekly-state.json'
$LogFile    = Join-Path $StateDir 'weekly.log'
$MaxLogSize = 5MB
$SystemSid  = 'S-1-5-18'
$AdminsSid  = 'S-1-5-32-544'

# --- Logging ------------------------------------------------------------------

function Write-Log([string]$Text) {
    # Keep one old log: weekly.log -> weekly.log.1 at 5 MB (content moved, so
    # weekly.log keeps the permissions the installer gave it).
    if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt $MaxLogSize) {
        Copy-Item -LiteralPath $LogFile -Destination "$LogFile.1" -Force -ErrorAction SilentlyContinue
        Clear-Content -LiteralPath $LogFile
    }
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Text
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

# --- When is a check due? -----------------------------------------------------

# The most recent Sunday 18:00 at or before now.
function Get-LastScheduledTime {
    $now  = Get-Date
    $back = ([int]$now.DayOfWeek - [int][DayOfWeek]::Sunday + 7) % 7
    $time = $now.Date.AddDays(-$back).AddHours(18)
    if ($time -gt $now) { $time = $time.AddDays(-7) }
    $time
}

function Read-State {
    $state = $null
    if (Test-Path -LiteralPath $StateFile) {
        $raw = Get-Content -LiteralPath $StateFile -Raw
        if ($raw -and $raw.Trim()) { $state = $raw | ConvertFrom-Json }
    }
    if (-not $state) { $state = [pscustomobject]@{ lastCheck = $null; lastResult = $null; clearStreak = 0 } }
    $state
}

# --- The check (same as part 1 of Get-PermissionReport.ps1) ---------------------

# One entry per folder that is missing SYSTEM and/or Administrators.
function Find-Problems([string]$PackagesPath) {
    $folders = @((Get-Item -LiteralPath $PackagesPath -Force)) +
               @(Get-ChildItem -LiteralPath $PackagesPath -Directory -Force -ErrorAction SilentlyContinue)
    $problems = foreach ($f in $folders) {
        $name = if ($f.FullName.TrimEnd('\') -eq $PackagesPath.TrimEnd('\')) { '(Packages folder itself)' } else { $f.Name }
        try {
            $acl   = ([System.IO.DirectoryInfo]$f.FullName).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
            $allow = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object { $_.IdentityReference.Value })
            $missing = @()
            if ($allow -notcontains $SystemSid) { $missing += 'SYSTEM' }
            if ($allow -notcontains $AdminsSid) { $missing += 'Administrators' }
            if ($missing) { [pscustomobject]@{ Name = $name; Missing = $missing -join ' and ' } }
        } catch {
            [pscustomobject]@{ Name = $name; Missing = "unknown (could not read permissions: $($_.Exception.Message))" }
        }
    }
    [pscustomobject]@{ Checked = $folders.Count; Problems = @($problems) }
}

# --- Email ------------------------------------------------------------------------

function Get-ApiKey {
    # ConvertTo-SecureString without -Key reverses ConvertFrom-SecureString's
    # DPAPI (CurrentUser) encryption. Only this Windows account can do it.
    $secure = Get-Content -LiteralPath $KeyFile -Raw | ConvertTo-SecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try     { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function New-Email($Config, $Result, [int]$Streak) {
    $computer = $env:COMPUTERNAME
    $count    = $Result.Problems.Count
    if ($count) {
        $subject = "Permission Trap: $count folder(s) missing SYSTEM/Administrators on $computer"
        $intro   = "The weekly check on $computer found $count of $($Result.Checked) folder(s) in $($Config.packagesPath) missing SYSTEM and/or Administrators. Store apps that use these folders may fail to start."
        $items   = @($Result.Problems | ForEach-Object { "$($_.Name) - missing $($_.Missing)" })
        $todo    = @(
            'To find out what did it, open PowerShell as administrator on the laptop and run:',
            '    cd C:\PermissionTrap',
            '    powershell -ExecutionPolicy Bypass -File .\Get-PermissionReport.ps1',
            'Run the report before repairing anything.')
    } else {
        $weeks   = if ($Streak -eq 1) { '1 week' } else { "$Streak weeks" }
        $subject = "Permission Trap: all clear on $computer ($weeks in a row)"
        $intro   = "All clear: all $($Result.Checked) folder(s) in $($Config.packagesPath) have SYSTEM and Administrators. That's $weeks in a row."
        $items   = @()
        $todo    = @()
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($intro); $lines.Add('')
    if ($items) { foreach ($i in $items) { $lines.Add("  - $i") }; $lines.Add('') }
    foreach ($t in $todo) { $lines.Add($t) }
    $text = $lines -join "`r`n"

    $enc  = { param($s) [System.Net.WebUtility]::HtmlEncode($s) }
    $html = "<p>$(& $enc $intro)</p>"
    if ($items) { $html += '<ul>' + (($items | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join '') + '</ul>' }
    if ($todo)  { $html += "<p>$(& $enc $todo[0])</p><pre>$(& $enc ($todo[1..2] -join "`n"))</pre><p>$(& $enc $todo[3])</p>" }

    [ordered]@{ from = $Config.from; to = @($Config.to); subject = $subject; text = $text; html = $html }
}

# Sends the email, or, if the installer was given -OutboxPath (testing),
# writes it to that folder instead. Returns a short note for the log.
function Send-Email($Config, $Email) {
    $key  = Get-ApiKey
    $json = $Email | ConvertTo-Json -Depth 4

    if ($Config.outboxPath) {
        if (-not (Test-Path -LiteralPath $Config.outboxPath)) { New-Item -ItemType Directory -Path $Config.outboxPath -Force | Out-Null }
        $file = Join-Path $Config.outboxPath ('email_{0:yyyy-MM-dd_HH-mm-ss-fff}.json' -f (Get-Date))
        # Record that the key decrypted and how long it is - never the key itself.
        [ordered]@{ keyLength = $key.Length; email = $Email } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $file -Encoding UTF8
        return "written to outbox (test mode): $file"
    }

    # Windows PowerShell 5.1 may default to TLS 1.0, which Resend rejects.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
        $response = Invoke-RestMethod -Method Post -Uri 'https://api.resend.com/emails' `
            -Headers @{ Authorization = "Bearer $key" } -ContentType 'application/json; charset=utf-8' `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($json))
    } catch {
        # Resend explains problems (bad key, unverified domain) in the response body.
        $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Resend refused the email: $detail"
    }
    "sent (Resend id $($response.id))"
}

# --- Main -----------------------------------------------------------------------

$exitCode = 0
try {
    $config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
    $state  = Read-State
    $due    = Get-LastScheduledTime
    $last   = if ($state.lastCheck -is [datetime]) { $state.lastCheck }
              elseif ($state.lastCheck)         { [datetime]::Parse($state.lastCheck, $null, 'RoundtripKind') }
              else                              { $null }

    if (-not $Force -and $last -and $last -ge $due) {
        Write-Log "SKIP     already checked $($last.ToString('yyyy-MM-dd HH:mm')) (since Sunday $($due.ToString('yyyy-MM-dd')) 18:00)"
    } elseif (-not (Test-Path -LiteralPath $config.packagesPath -PathType Container)) {
        Write-Log "ERROR    Packages folder not found: $($config.packagesPath)"
        $exitCode = 1
    } else {
        $result = Find-Problems $config.packagesPath

        # Consecutive clear weekly checks. A forced re-run in the same week
        # does not add a week.
        $newWeek = -not $last -or $last -lt $due
        $streak  = if ($result.Problems.Count) { 0 }
                   elseif ($newWeek)           { [int]$state.clearStreak + 1 }
                   else                        { [Math]::Max(1, [int]$state.clearStreak) }

        $email = New-Email $config $result $streak
        $sent  = Send-Email $config $email

        $state.lastCheck   = (Get-Date).ToString('o')
        $state.lastResult  = $(if ($result.Problems.Count) { 'problems' } else { 'clear' })
        $state.clearStreak = $streak
        $state | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding UTF8

        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator)
        $who = "as $([Security.Principal.WindowsIdentity]::GetCurrent().Name), elevated: $elevated"
        if ($result.Problems.Count) {
            Write-Log "PROBLEMS $($result.Problems.Count) of $($result.Checked) folder(s): $(($result.Problems | ForEach-Object { "$($_.Name) [$($_.Missing)]" }) -join '; ')  email $sent  ($who)"
        } else {
            Write-Log "CLEAR    $($result.Checked) folder(s) OK, $streak week(s) in a row  email $sent  ($who)"
        }
    }
} catch {
    Write-Log "ERROR    $($_.Exception.Message)  (check not counted; will retry at next logon or Sunday)"
    $exitCode = 1
}
exit $exitCode
