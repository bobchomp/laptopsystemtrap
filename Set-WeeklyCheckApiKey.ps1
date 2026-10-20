#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Changes the Resend API key used by the weekly check, then sends a test
    email to prove it works. No need to uninstall or reinstall.

.DESCRIPTION
    - Prompts for the key (input hidden). Paste it with a RIGHT-CLICK: in
      Windows PowerShell, Ctrl+V does not paste into the hidden prompt, it
      types an invisible ^V instead.
    - Trims stray spaces and line breaks, refuses keys containing invisible
      control characters (nothing is changed), and warns if the key does not
      start with re_.
    - Stores it encrypted with DPAPI for YOUR Windows account only, in
      C:\ProgramData\PermissionTrap\weekly-resend.key, readable only by you,
      SYSTEM and Administrators. It is never written in plain text or shown.
    - Updates the installed copy of Invoke-WeeklyCheck.ps1 if the one next to
      this script is newer, then sends a test email (logged as TEST in
      weekly.log). The test does not count as a weekly check.

    Needs an elevated PowerShell (the key file is admin-only to change), run
    from your own account: only the account that stores the key can decrypt it.
    Install-WeeklyCheck.ps1 uses this script to store the key too.

.PARAMETER ApiKey
    The key as a SecureString, for scripted use. If omitted you are prompted.

.PARAMETER KeepIfBlank
    If nothing is entered at the prompt and a key is already stored, keep it.

.PARAMETER SkipTest
    Do not send the test email.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Set-WeeklyCheckApiKey.ps1
#>
[CmdletBinding()]
param(
    [System.Security.SecureString]$ApiKey,
    [switch]$KeepIfBlank,
    [switch]$SkipTest
)

$ErrorActionPreference = 'Stop'

$StateDir     = Join-Path $env:ProgramData 'PermissionTrap'
$KeyFile      = Join-Path $StateDir 'weekly-resend.key'
$SourceScript = Join-Path $PSScriptRoot 'Invoke-WeeklyCheck.ps1'
$TargetScript = Join-Path $StateDir 'Invoke-WeeklyCheck.ps1'
$LogFile      = Join-Path $StateDir 'weekly.log'
$MeSid        = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Write-Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "   WARN $Text" -ForegroundColor Yellow }

if (-not (Test-Path -LiteralPath $StateDir)) { throw "$StateDir not found - run Install-WeeklyCheck.ps1 first." }

# --- Get the key ----------------------------------------------------------------

Write-Step 'Resend API key'
if (-not $ApiKey) {
    Write-Host '   Paste with a RIGHT-CLICK (Ctrl+V does not work in this prompt), then press Enter.'
    $prompt = if ($KeepIfBlank -and (Test-Path -LiteralPath $KeyFile)) { 'Resend API key (input hidden; just press Enter to keep the stored key)' }
              else { 'Resend API key (input hidden)' }
    $ApiKey = Read-Host -Prompt $prompt -AsSecureString
}

if ($ApiKey.Length -eq 0) {
    if ($KeepIfBlank -and (Test-Path -LiteralPath $KeyFile)) {
        Write-Ok "Keeping the key stored earlier in $KeyFile"
        $SkipTest = $true
    } else {
        throw 'No API key entered. Nothing was changed.'
    }
} else {
    # Check what was entered without ever showing it: drop stray spaces/line
    # breaks around it, and refuse invisible control characters (such as the
    # ^V that Ctrl+V types), which Windows will not put in a web request.
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
    try     { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($plain -match '[\x00-\x1F\x7F]') {
        throw ('The key you entered contains invisible control characters (Ctrl+V types one instead of pasting). ' +
               'Nothing was changed. Run this again and paste the key with a right-click.')
    }
    if (-not $plain) { throw 'The key you entered was blank. Nothing was changed.' }
    if ($plain -notmatch '^re_') { Write-Warn "That doesn't look like a Resend API key (they start with 're_'). Saving it anyway." }
    $clean = ConvertTo-SecureString -String $plain -AsPlainText -Force
    Remove-Variable plain

    # ConvertFrom-SecureString without -Key encrypts with DPAPI, CurrentUser
    # scope: only this Windows account (on this PC) can decrypt it.
    Set-Content -LiteralPath $KeyFile -Value (ConvertFrom-SecureString -SecureString $clean) -Encoding ASCII
    # Readable only by you (to decrypt) and SYSTEM/Administrators (to manage it).
    & icacls.exe $KeyFile /inheritance:r /grant:r "*${MeSid}:R" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set permissions on $KeyFile (icacls exit $LASTEXITCODE)" }
    Write-Ok "Stored encrypted (DPAPI, CurrentUser) in $KeyFile"
}

if ($SkipTest) { return }

# --- Make sure the installed check is this version --------------------------------

if (-not (Test-Path -LiteralPath $TargetScript)) { throw "$TargetScript not found - run Install-WeeklyCheck.ps1 first." }
if ((Test-Path -LiteralPath $SourceScript) -and
    (Get-FileHash -LiteralPath $SourceScript).Hash -ne (Get-FileHash -LiteralPath $TargetScript).Hash) {
    Copy-Item -LiteralPath $SourceScript -Destination $TargetScript -Force
    Write-Ok 'Updated the installed weekly check to the version next to this script'
}

# --- Test email -------------------------------------------------------------------

Write-Step 'Sending a test email'
& $TargetScript -TestEmail *> $null
$exit = $LASTEXITCODE
$line = Get-Content -LiteralPath $LogFile -Tail 1 -ErrorAction SilentlyContinue
if ($exit -eq 0) {
    Write-Ok $line
    Write-Host ''
    Write-Host 'Done. Check your inbox for "Permission Trap: test email".' -ForegroundColor Green
} else {
    Write-Warn $line
    Write-Host ''
    Write-Host 'The key is saved, but the test email failed (see above).' -ForegroundColor Yellow
    exit 1
}
