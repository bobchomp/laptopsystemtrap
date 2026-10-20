#Requires -Version 5.1
<#
.SYNOPSIS
    Checks %LOCALAPPDATA%\Packages and emails you via Resend. Run by the
    PermissionTrap-WeeklyCheck scheduled task (as you, not elevated) every
    Sunday at 18:00 and at every logon; you do not normally run it yourself.

.DESCRIPTION
    Every run checks Packages and every app folder in it for missing SYSTEM
    (S-1-5-18) or Administrators (S-1-5-32-544) - the same check as part 1 of
    Get-PermissionReport.ps1 - and logs the result to
    C:\ProgramData\PermissionTrap\weekly.log. What it emails depends on the run:

    WEEKLY - no weekly check has succeeded since the most recent Sunday 18:00
             (the Sunday run, or the first logon after a missed Sunday):
             always emails - the affected folders, or "all clear" with how
             many weeks in a row it has been clear. If sending fails, the week
             is not counted and the next logon tries again.
    LOGON  - any other run (every logon, or starting the task by hand):
             emails only if something is broken; an all-clear is just logged.

    Finding problems resets the clear-weeks count to 0.

    Settings come from weekly-config.json, written by Install-WeeklyCheck.ps1.
    The Resend API key is in weekly-resend.key, encrypted with DPAPI for your
    Windows account only.

.PARAMETER Force
    Treat this run as the weekly one even if this week's was already done.
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
    # Trim: the file ends with a newline, which ConvertTo-SecureString rejects.
    $secure = (Get-Content -LiteralPath $KeyFile -Raw).Trim() | ConvertTo-SecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try     { $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    # Windows refuses to put control characters in a web request header. Keys
    # saved by older installers could contain one (Ctrl+V in the hidden prompt).
    if ($key -match '[\x00-\x1F\x7F]') {
        throw ('The stored Resend API key contains invisible control characters, so no email was sent. ' +
               'Run Install-WeeklyCheck.ps1 again and paste the key with a right-click (Ctrl+V does not work in that prompt).')
    }
    $key
}

function New-Email($Config, $Result, [int]$Streak, [bool]$Weekly) {
    $computer = $env:COMPUTERNAME
    $count    = $Result.Problems.Count
    if ($count) {
        $subject = "Permission Trap: $count folder(s) missing SYSTEM/Administrators on $computer"
        $when    = if ($Weekly) { 'The weekly check' } else { 'The check at logon' }
        $intro   = "$when on $computer found $count of $($Result.Checked) folder(s) in $($Config.packagesPath) missing SYSTEM and/or Administrators. Store apps that use these folders may fail to start."
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
        # Only say "Resend refused" when Resend actually answered (bad key, unverified
        # domain - it explains in the response body). Otherwise the request never got
        # there: no network, DNS, a proxy, and so on.
        if ($_.Exception.Response) {
            $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            throw "Resend refused the email (HTTP $([int]$_.Exception.Response.StatusCode)): $detail"
        }
        throw "Could not reach Resend: $($_.Exception.Message)"
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

    if (-not (Test-Path -LiteralPath $config.packagesPath -PathType Container)) {
        Write-Log "ERROR    Packages folder not found: $($config.packagesPath)"
        $exitCode = 1
    } else {
        # WEEKLY if this week's emailed check has not happened yet, else LOGON.
        $weekly   = $Force -or -not $last -or $last -lt $due
        $kind     = if ($weekly) { 'WEEKLY' } else { 'LOGON ' }
        $result   = Find-Problems $config.packagesPath
        $problems = $result.Problems.Count

        # Consecutive clear weekly checks: +1 per clear weekly check, 0 as soon
        # as any check finds problems, unchanged by a clear logon check.
        $streak = if ($problems)  { 0 }
                  elseif ($weekly) { [int]$state.clearStreak + 1 }
                  else             { [int]$state.clearStreak }

        $sent = 'not sent (all clear at logon; only the weekly check emails an all-clear)'
        if ($weekly -or $problems) {
            $sent = 'email ' + (Send-Email $config (New-Email $config $result $streak $weekly))
        }

        if ($weekly) { $state.lastCheck = (Get-Date).ToString('o') }
        $state.lastResult  = $(if ($problems) { 'problems' } else { 'clear' })
        $state.clearStreak = $streak
        $state | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding UTF8

        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator)
        $who = "as $([Security.Principal.WindowsIdentity]::GetCurrent().Name), elevated: $elevated"
        if ($problems) {
            Write-Log "$kind PROBLEMS $problems of $($result.Checked) folder(s): $(($result.Problems | ForEach-Object { "$($_.Name) [$($_.Missing)]" }) -join '; ')  $sent  ($who)"
        } else {
            Write-Log "$kind CLEAR    $($result.Checked) folder(s) OK, $streak week(s) in a row  $sent  ($who)"
        }
    }
} catch {
    Write-Log "ERROR    $($_.Exception.Message)  (a weekly check is not counted and is retried at the next logon)"
    $exitCode = 1
}
exit $exitCode
