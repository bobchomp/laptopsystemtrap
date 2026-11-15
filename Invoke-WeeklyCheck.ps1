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

.PARAMETER TestEmail
    Only send a short test email (used by Set-WeeklyCheckApiKey.ps1). Does not
    check folders or count as a weekly check.
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$TestEmail
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

# --- Email layout -----------------------------------------------------------------
#
# Email clients ignore most modern HTML/CSS, so this sticks to what Gmail,
# Outlook and phone apps all show the same way: nested tables, inline styles,
# no images and no web fonts. Every bit of text from outside (folder names,
# paths) goes through HtmlEncode. Symbols are HTML entities, because Windows
# PowerShell 5.1 misreads non-ASCII characters in a script saved without a BOM.

$Font   = "-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
$Mono   = "Consolas,'Cascadia Mono',Menlo,monospace"
$UkDate = [Globalization.CultureInfo]::GetCultureInfo('en-GB')

function ConvertTo-Html([string]$Text) { [System.Net.WebUtility]::HtmlEncode($Text) }

function Format-When([datetime]$Time) { $Time.ToString('dddd d MMMM yyyy, HH:mm', $UkDate) }

# The next Sunday 18:00 after now (when the next weekly email is due).
function Get-NextScheduledTime { (Get-LastScheduledTime).AddDays(7) }

# Folder the scripts were installed from, for the "run the report" instructions.
function Get-ScriptsFolder($Config) {
    if ($Config.PSObject.Properties['scriptsPath'] -and $Config.scriptsPath) { $Config.scriptsPath }
    else { '<the folder you extracted Permission Trap to>' }
}

# The whole email around a body: coloured header, white card, grey footer.
function New-EmailPage {
    param([string]$Accent, [string]$Symbol, [string]$Title, [string]$Subtitle,
          [string]$Preheader, [string]$Body, [string]$Footer)
@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light only"><title>$(ConvertTo-Html $Title)</title></head>
<body style="margin:0;padding:0;background:#eef1f5;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#eef1f5;">$(ConvertTo-Html $Preheader)</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eef1f5;">
<tr><td align="center" style="padding:28px 12px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:580px;background:#ffffff;border:1px solid #dce2e9;border-radius:14px;border-collapse:separate;overflow:hidden;">
<tr><td style="background:$Accent;padding:24px 24px 22px;font-family:$Font;color:#ffffff;">
<div style="font-size:12px;font-weight:600;letter-spacing:1.5px;text-transform:uppercase;opacity:0.85;">Permission Trap</div>
<div style="font-size:26px;line-height:1.25;font-weight:700;margin-top:8px;">$Symbol&nbsp;$(ConvertTo-Html $Title)</div>
<div style="font-size:14px;line-height:1.5;margin-top:6px;opacity:0.92;">$(ConvertTo-Html $Subtitle)</div>
</td></tr>
<tr><td style="padding:26px 24px 28px;font-family:$Font;font-size:15px;line-height:1.6;color:#1f2933;">
$Body
</td></tr>
<tr><td style="padding:16px 24px 18px;background:#f6f8fa;border-top:1px solid #e3e8ee;font-family:$Font;font-size:12px;line-height:1.6;color:#6b7785;word-break:break-word;overflow-wrap:anywhere;">
$Footer
</td></tr>
</table>
</td></tr>
</table>
</body></html>
"@
}

function New-EmailFooter([string]$Extra) {
    $line = "Sent by Permission Trap on $(ConvertTo-Html $env:COMPUTERNAME) &middot; $(ConvertTo-Html (Format-When (Get-Date)))"
    if ($Extra) { "$line<br>$Extra" } else { $line }
}

# A small coloured label, e.g. the "SYSTEM" a folder is missing.
function New-Chip([string]$Text, [string]$Color = '#b42318', [string]$Background = '#fdecea') {
    "<span style=`"display:inline-block;padding:2px 9px;margin:2px 4px 2px 0;border-radius:10px;background:$Background;color:$Color;font-size:12px;font-weight:600;white-space:nowrap;`">$(ConvertTo-Html $Text)</span>"
}

# Grey box for commands to type.
function New-CodeBlock([string[]]$Lines) {
    $code = ($Lines | ForEach-Object { ConvertTo-Html $_ }) -join '<br>'
    "<div style=`"margin:8px 0 4px;padding:12px 14px;background:#f3f5f8;border:1px solid #e1e6ec;border-radius:8px;font-family:$Mono;font-size:13px;line-height:1.6;color:#1f2933;word-break:break-word;overflow-wrap:anywhere;`">$code</div>"
}

function New-Email($Config, $Result, [int]$Streak, [bool]$Weekly) {
    $computer = $env:COMPUTERNAME
    $count    = $Result.Problems.Count
    $checked  = $Result.Checked
    $path     = $Config.packagesPath
    $folder   = Get-ScriptsFolder $Config
    $next     = Format-When (Get-NextScheduledTime)
    $schedule = 'Checks run every Sunday at 18:00 and each time you log on.'

    if ($count) {
        $when     = if ($Weekly) { 'The weekly check' } else { 'The check at logon' }
        $plural   = if ($count -eq 1) { 'folder' } else { 'folders' }
        $subject  = "Permission Trap: $count folder(s) missing SYSTEM/Administrators on $computer"
        $intro    = "$when on $computer found $count of $checked folder(s) in $path missing SYSTEM and/or Administrators. Store apps that use these folders may fail to start."
        $commands = @("cd `"$folder`"", 'powershell -ExecutionPolicy Bypass -File .\Get-PermissionReport.ps1')

        # Plain-text version.
        $text = @($intro, '') +
                @($Result.Problems | ForEach-Object {
                    if ($_.Missing -like 'unknown*') { "  - $($_.Name) - could not read its permissions" }
                    else { "  - $($_.Name) - missing $($_.Missing)" } }) +
                @('', 'To find out what did it, open PowerShell as administrator on the laptop and run:') +
                @($commands | ForEach-Object { "    $_" }) +
                @('The line starting ">>> WHAT DID IT:" names the program responsible.',
                  'Run the report before you repair anything: once a folder is repaired, the report no longer lists it as broken.',
                  '', "Sent by Permission Trap on $computer. $schedule") -join "`r`n"

        # HTML version: a row per folder with what it is missing.
        $rows = foreach ($p in $Result.Problems) {
            $chips = if ($p.Missing -like 'unknown*') { New-Chip 'could not read permissions' '#6b7785' '#eef1f5' }
                     else { ($p.Missing -split ' and ' | ForEach-Object { New-Chip "no $_" }) -join '' }
            "<tr><td style=`"padding:11px 14px;border-top:1px solid #eceff3;`">" +
            "<div style=`"font-family:$Mono;font-size:13px;color:#1f2933;word-break:break-word;overflow-wrap:anywhere;`">$(ConvertTo-Html $p.Name)</div>" +
            "<div style=`"margin-top:5px;`">$chips</div></td></tr>"
        }
        $body = @"
<p style="margin:0 0 18px;">$(ConvertTo-Html $when) found <strong>$count of $checked</strong> app folders without the permissions Windows needs. Store apps that use $(if ($count -eq 1) { 'it' } else { 'them' }) may fail to start.</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #eceff3;border-radius:10px;border-collapse:separate;font-family:$Font;">
<tr><td style="padding:9px 14px;background:#fafbfc;font-size:12px;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;color:#6b7785;">Affected folders</td></tr>
$($rows -join "`n")
</table>
<div style="margin:24px 0 0;padding:18px 20px;background:#fff8e6;border:1px solid #f6dfa4;border-left:4px solid #e0a100;border-radius:8px;">
<div style="font-size:15px;font-weight:700;color:#7a5200;margin-bottom:6px;">Find out what did it</div>
<div style="font-size:14px;color:#4a3b12;">On the laptop, open PowerShell <strong>as administrator</strong> (Start &rarr; PowerShell &rarr; right-click &rarr; Run as administrator) and run:</div>
$(New-CodeBlock $commands)
<div style="font-size:14px;color:#4a3b12;margin-top:8px;">The line starting <span style="font-family:$Mono;font-size:13px;">&gt;&gt;&gt; WHAT DID IT:</span> names the program responsible. Run the report before you repair anything: once a folder is repaired, the report no longer lists it as broken.</div>
</div>
"@
        $html = New-EmailPage -Accent '#c0392b' -Symbol '&#9888;' `
            -Title "$count $plural need$(if ($count -eq 1) { 's' }) attention" `
            -Subtitle "$computer $([char]0xB7) $(if ($Weekly) { 'weekly check' } else { 'check at logon' })" `
            -Preheader "$count $plural missing SYSTEM/Administrators: $(($Result.Problems | Select-Object -First 3 | ForEach-Object { $_.Name }) -join ', ')" `
            -Body $body -Footer (New-EmailFooter (ConvertTo-Html "Packages folder: $path. $schedule"))
    } else {
        $weeks   = if ($Streak -eq 1) { '1 week' } else { "$Streak weeks" }
        $subject = "Permission Trap: all clear on $computer ($weeks in a row)"
        $intro   = "All clear for $weeks in a row: all $checked folder(s) in $path have SYSTEM and Administrators."

        $text = @($intro, '', "Next weekly email: $next.", '', "Sent by Permission Trap on $computer. $schedule") -join "`r`n"

        # A dot per clear week (up to 12) under the big number.
        $dots = ('&#9679;' * [Math]::Min($Streak, 12)) + $(if ($Streak -gt 12) { '&hellip;' } else { '' })
        $body = @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family:$Font;">
<tr><td align="center" style="padding:6px 0 20px;">
<div style="font-size:56px;line-height:1;font-weight:800;color:#1f8b4c;">$Streak</div>
<div style="font-size:15px;font-weight:600;color:#1f2933;margin-top:6px;">$(if ($Streak -eq 1) { 'week' } else { 'weeks' }) in a row all clear</div>
<div style="font-size:16px;letter-spacing:4px;color:#2fb36b;margin-top:8px;">$dots</div>
</td></tr></table>
<p style="margin:0 0 14px;">All <strong>$checked</strong> app folders have SYSTEM and Administrators, so Store apps should start normally.</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f3f8f5;border:1px solid #d6eadd;border-radius:10px;border-collapse:separate;font-family:$Font;font-size:14px;color:#1f2933;">
<tr><td style="padding:12px 16px;"><span style="color:#6b7785;">Next weekly email</span><br><strong>$(ConvertTo-Html $next)</strong></td></tr>
</table>
"@
        $html = New-EmailPage -Accent '#1f8b4c' -Symbol '&#10003;' -Title 'All clear' `
            -Subtitle "$computer $([char]0xB7) $weeks in a row" `
            -Preheader "All $checked folders OK, $weeks in a row. Next weekly email: $next." `
            -Body $body -Footer (New-EmailFooter (ConvertTo-Html "Packages folder: $path. $schedule"))
    }

    [ordered]@{ from = $Config.from; to = @($Config.to); subject = $subject; text = $text; html = $html }
}

function New-TestEmail($Config) {
    $computer = $env:COMPUTERNAME
    $text = "This is a test from Permission Trap on $computer. The Resend API key works, and the weekly emails will come to this address."
    $body = @"
<p style="margin:0 0 16px;">Your Resend API key works. Permission Trap on <strong>$(ConvertTo-Html $computer)</strong> will email this address:</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #e1e8f5;border-radius:10px;border-collapse:separate;font-family:$Font;font-size:14px;color:#1f2933;">
<tr><td style="padding:12px 16px;border-bottom:1px solid #e1e8f5;"><strong>Every Sunday at 18:00</strong><br><span style="color:#52606d;">Always: either all clear, or a list of the folders that need attention.</span></td></tr>
<tr><td style="padding:12px 16px;"><strong>Each time you log on</strong><br><span style="color:#52606d;">Only if a folder is missing SYSTEM or Administrators.</span></td></tr>
</table>
<p style="margin:16px 0 0;color:#52606d;font-size:14px;">This was only a test, so there's nothing to do.</p>
"@
    [ordered]@{
        from = $Config.from; to = @($Config.to)
        subject = "Permission Trap: test email from $computer"
        text = $text
        html = New-EmailPage -Accent '#2f6fdb' -Symbol '&#9993;' -Title 'Test email' -Subtitle "$computer $([char]0xB7) the API key works" `
                   -Preheader 'Your Resend API key works.' -Body $body -Footer (New-EmailFooter '')
    }
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
        # The HTML too, so the email can be opened and looked at in a browser.
        Set-Content -LiteralPath ($file -replace '\.json$', '.html') -Value $Email.html -Encoding UTF8
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

    if ($TestEmail) {
        Write-Log "TEST     email $(Send-Email $config (New-TestEmail $config))"
    } elseif (-not (Test-Path -LiteralPath $config.packagesPath -PathType Container)) {
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
    $note = if ($TestEmail) { '(test email)' } else { '(a weekly check is not counted and is retried at the next logon)' }
    Write-Log "ERROR    $($_.Exception.Message)  $note"
    $exitCode = 1
}
exit $exitCode
