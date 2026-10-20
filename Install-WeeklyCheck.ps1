#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers the PermissionTrap-WeeklyCheck scheduled task: it checks
    %LOCALAPPDATA%\Packages every Sunday at 18:00 and every time you log on.
    The Sunday check always emails you (problems, or all clear); a logon
    check emails only if something is broken. A missed Sunday check is done
    at your next logon instead.

.DESCRIPTION
    - Prompts for your Resend API key (input hidden) and stores it encrypted
      with DPAPI for YOUR Windows account only (CurrentUser scope) in
      C:\ProgramData\PermissionTrap\weekly-resend.key. It is never written in
      plain text and never shown.
    - Copies Invoke-WeeklyCheck.ps1 and writes weekly-config.json (Packages
      path, sender, recipient) into C:\ProgramData\PermissionTrap, where only
      administrators can change them.
    - Lets your account write weekly.log and weekly-state.json there, because
      the check runs unelevated.
    - Registers the task: runs as you, NOT elevated, only while you are logged
      on (DPAPI needs your logon to decrypt the key). Triggers: Sunday 18:00,
      and 2 minutes after every logon.

    Needs an elevated PowerShell (to write to C:\ProgramData\PermissionTrap),
    run from your own account: the task and the key belong to whoever runs this.

.PARAMETER PackagesPath
    Defaults to %LOCALAPPDATA%\Packages of the account running this script.

.PARAMETER From
    Sender. The domain must be verified in your Resend account.

.PARAMETER To
    Recipient(s).

.PARAMETER ApiKey
    The Resend API key as a SecureString, for scripted installs. If omitted
    you are prompted (press Enter to keep a key stored earlier).

.PARAMETER OutboxPath
    TESTING ONLY: write each email as a JSON file into this folder instead of
    sending it.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-WeeklyCheck.ps1
#>
[CmdletBinding()]
param(
    [string]$PackagesPath = (Join-Path $env:LOCALAPPDATA 'Packages'),
    [string]$From = 'Permission Trap <info@rossmackenzie.co.uk>',
    [string[]]$To = @('teddaharry@gmail.com'),
    [System.Security.SecureString]$ApiKey,
    [string]$OutboxPath
)

$ErrorActionPreference = 'Stop'

$TaskName     = 'PermissionTrap-WeeklyCheck'
$StateDir     = Join-Path $env:ProgramData 'PermissionTrap'
$SourceScript = Join-Path $PSScriptRoot 'Invoke-WeeklyCheck.ps1'
$TargetScript = Join-Path $StateDir 'Invoke-WeeklyCheck.ps1'
$ConfigFile   = Join-Path $StateDir 'weekly-config.json'
$KeyFile      = Join-Path $StateDir 'weekly-resend.key'
$StateFile    = Join-Path $StateDir 'weekly-state.json'
$LogFile      = Join-Path $StateDir 'weekly.log'

$Me    = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$MeSid = $Me.User.Value

function Write-Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "   WARN $Text" -ForegroundColor Yellow }

function Invoke-Icacls([string[]]$Arguments) {
    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $($Arguments -join ' ') failed (exit $LASTEXITCODE)" }
}

# --- Checks -------------------------------------------------------------------

Write-Step 'Checking'
if (-not (Test-Path -LiteralPath $PackagesPath -PathType Container)) {
    throw "Folder not found: $PackagesPath  (run this from your own account, or pass -PackagesPath)"
}
$PackagesPath = (Get-Item -LiteralPath $PackagesPath -Force).FullName.TrimEnd('\')
if (-not (Test-Path -LiteralPath $SourceScript)) { throw "Invoke-WeeklyCheck.ps1 not found next to this script ($SourceScript)" }
Write-Ok "Packages folder: $PackagesPath"
Write-Ok "Runs as: $($Me.Name) (not elevated)"
Write-Ok "Emails from $From to $($To -join ', ')"
if ($OutboxPath) { Write-Warn "TEST MODE: emails will be written to $OutboxPath, not sent" }

# --- Our folder -------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }
# SYSTEM + Administrators full control, Users read-only (same as the other installers).
Invoke-Icacls @($StateDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')

# --- API key ------------------------------------------------------------------------

Write-Step 'Resend API key'
if (-not $ApiKey) {
    # In Windows PowerShell, Ctrl+V does not paste into this hidden prompt: it
    # types an invisible ^V character instead. Right-click pastes properly.
    Write-Host '   Paste with a RIGHT-CLICK (Ctrl+V does not work in this prompt), then press Enter.'
    $prompt = if (Test-Path -LiteralPath $KeyFile) { 'Resend API key (input hidden; just press Enter to keep the stored key)' }
              else { 'Resend API key (input hidden)' }
    $ApiKey = Read-Host -Prompt $prompt -AsSecureString
}
if ($ApiKey.Length -gt 0) {
    # Check what was entered without ever showing it: drop stray spaces/line
    # breaks around it, and refuse invisible control characters (such as the
    # ^V that Ctrl+V types), which Windows will not put in a web request.
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
    try     { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($plain -match '[\x00-\x1F\x7F]') {
        throw ('The key you entered contains invisible control characters (Ctrl+V types one instead of pasting). ' +
               'Nothing was saved. Run the installer again and paste the key with a right-click.')
    }
    if (-not $plain) { throw 'The key you entered was blank. Nothing was saved.' }
    if ($plain -notmatch '^re_') { Write-Warn "That doesn't look like a Resend API key (they start with 're_'). Saving it anyway." }
    $ApiKey = ConvertTo-SecureString -String $plain -AsPlainText -Force
    Remove-Variable plain

    # ConvertFrom-SecureString without -Key encrypts with DPAPI, CurrentUser
    # scope: only this Windows account (on this PC) can decrypt it.
    $encrypted = ConvertFrom-SecureString -SecureString $ApiKey
    Set-Content -LiteralPath $KeyFile -Value $encrypted -Encoding ASCII
    # Readable only by you (to decrypt) and SYSTEM/Administrators (to manage it).
    Invoke-Icacls @($KeyFile, '/inheritance:r', '/grant:r', "*${MeSid}:R", '*S-1-5-18:F', '*S-1-5-32-544:F')
    Write-Ok "Stored encrypted (DPAPI, CurrentUser) in $KeyFile"
} elseif (Test-Path -LiteralPath $KeyFile) {
    Write-Ok "Keeping the key stored earlier in $KeyFile"
} else {
    throw 'No API key entered.'
}

# --- Script, config, log ------------------------------------------------------------

Write-Step "Copying the check and its settings to $StateDir"
Copy-Item -LiteralPath $SourceScript -Destination $TargetScript -Force
[ordered]@{
    packagesPath = $PackagesPath
    from         = $From
    to           = @($To)
    outboxPath   = $(if ($OutboxPath) { $OutboxPath } else { $null })
} | ConvertTo-Json | Set-Content -LiteralPath $ConfigFile -Encoding UTF8
Write-Ok "$TargetScript, $ConfigFile (admin-only)"

# The check runs unelevated, so your account may modify just these files
# (weekly.log.1 is where the log rotates to at 5 MB).
foreach ($f in $LogFile, "$LogFile.1", $StateFile) {
    if (-not (Test-Path -LiteralPath $f)) { New-Item -ItemType File -Path $f | Out-Null }
    Invoke-Icacls @($f, '/grant', "*${MeSid}:M")
}
Write-Ok "$LogFile and $StateFile writable by $($Me.Name)"

if ($OutboxPath -and -not (Test-Path -LiteralPath $OutboxPath)) { New-Item -ItemType Directory -Path $OutboxPath -Force | Out-Null }

# --- Register the task ----------------------------------------------------------------

Write-Step "Registering scheduled task '$TaskName'"

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetScript`"")

$weekly = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At '18:00'
# Drop the UTC offset New-ScheduledTaskTrigger adds (e.g. 18:00+01:00 in summer),
# which would make it fire at 17:00 in winter. Without it, 18:00 is local time all year.
$weekly.StartBoundary = $weekly.StartBoundary -replace '(Z|[+-]\d{2}:\d{2})$', ''
$logon  = New-ScheduledTaskTrigger -AtLogOn -User $Me.Name
$logon.Delay = 'PT2M'   # give the network a moment after logon

# Interactive = runs as you, only while you are logged on; Limited = not elevated.
$principal = New-ScheduledTaskPrincipal -UserId $Me.Name -LogonType Interactive -RunLevel Limited

# StartWhenAvailable: if the PC was asleep at 18:00 but you are logged on, run as soon as it wakes.
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($weekly, $logon) -Principal $principal -Settings $settings `
    -Description "Weekly check of $PackagesPath for missing SYSTEM/Administrators; emails $($To -join ', '). Installed by Install-WeeklyCheck.ps1; logs to $LogFile." `
    -Force | Out-Null
Write-Ok 'Registered: Sundays 18:00 (always emails) and every logon (emails only if something is broken)'

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host "Send the first check now:  Start-ScheduledTask -TaskName $TaskName"
Write-Host "See what it did:           Get-Content '$LogFile' -Tail 10"
Write-Host 'Remove it:                 .\Uninstall-WeeklyCheck.ps1'
