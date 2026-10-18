#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turns on the Windows auditing needed to catch whatever strips SYSTEM and
    Administrators from %LOCALAPPDATA%\Packages.

.DESCRIPTION
    1. Backs up the current audit policy (auditpol /backup) and records the
       other settings it is about to change, so Disable-Auditing.ps1 can put
       everything back exactly as it was.
    2. Enables "Success" auditing for three subcategories (by GUID, because the
       names are translated on non-English Windows):
         File System                 {0CCE921D-69AE-11D9-BED3-505054503030}
         Authorization Policy Change {0CCE9231-69AE-11D9-BED3-505054503030}
         Process Creation            {0CCE922B-69AE-11D9-BED3-505054503030}
    3. Turns on command lines in process-creation events (event 4688).
    4. Raises the Security log maximum size to 128 MB (never lowers it).
    5. Adds an audit rule (SACL) to the Packages folder: Everyone,
       ChangePermissions + TakeOwnership, inherited by all subfolders and
       files, Success only. The folder's permissions (DACL) are not touched;
       the script checks this before and after.

    Safe to run more than once: the original backup and "before" values are
    only recorded the first time.

.PARAMETER PackagesPath
    The folder to watch. Defaults to %LOCALAPPDATA%\Packages of the account
    running the script (run it from your own account, elevated).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Enable-Auditing.ps1
#>
[CmdletBinding()]
param(
    [string]$PackagesPath = (Join-Path $env:LOCALAPPDATA 'Packages')
)

$ErrorActionPreference = 'Stop'

# --- Settings -----------------------------------------------------------------

$StateDir      = Join-Path $env:ProgramData 'PermissionTrap'
$StateFile     = Join-Path $StateDir 'audit-state.json'
$AuditBackup   = Join-Path $StateDir 'auditpol-backup.csv'
$CmdLineKey    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$CmdLineValue  = 'ProcessCreationIncludeCmdLine_Enabled'
$LogSizeBytes  = 134217728   # 128 MB

$Subcategories = [ordered]@{
    'File System'                 = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    'Authorization Policy Change' = '{0CCE9231-69AE-11D9-BED3-505054503030}'
    'Process Creation'            = '{0CCE922B-69AE-11D9-BED3-505054503030}'
}

# The audit rule we add: Everyone (S-1-1-0), ChangePermissions + TakeOwnership,
# applies to this folder, subfolders and files, successful attempts only.
$EveryoneSid  = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$AuditRights  = [System.Security.AccessControl.FileSystemRights]'ChangePermissions, TakeOwnership'
$AuditInherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'

function New-TrapAuditRule {
    New-Object System.Security.AccessControl.FileSystemAuditRule(
        $EveryoneSid, $AuditRights, $AuditInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success)
}

# --- Helpers ------------------------------------------------------------------

function Write-Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "   WARN $Text" -ForegroundColor Yellow }
function Write-Info([string]$Text) { Write-Host "        $Text" }

# Reads only the SACL of a folder. We use .NET directly rather than
# Get-Acl/Set-Acl because Set-Acl rewrites the whole security descriptor
# (DACL included), which would re-propagate permissions through every app
# folder. Reading and writing only the Audit section leaves the DACL alone.
# .NET enables SeSecurityPrivilege for us when the Audit section is involved.
function Get-Sacl([string]$Path) {
    ([System.IO.DirectoryInfo]$Path).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
}

function Get-DaclSddl([string]$Path) {
    $sec = ([System.IO.DirectoryInfo]$Path).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $sec.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
}

# True if the SACL already has a rule that covers what we need (explicit or inherited).
function Test-HasTrapRule($Sacl, [switch]$ExplicitOnly) {
    $rules = $Sacl.GetAuditRules($true, (-not $ExplicitOnly), [System.Security.Principal.SecurityIdentifier])
    foreach ($r in $rules) {
        if ($r.IdentityReference.Value -ne 'S-1-1-0') { continue }
        if (($r.FileSystemRights -band $AuditRights) -ne $AuditRights) { continue }
        if (($r.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) -eq 0) { continue }
        if (($r.InheritanceFlags -band $AuditInherit) -ne $AuditInherit) { continue }
        if ($r.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) { continue }
        return $true
    }
    return $false
}

# Adds our rule to one folder's SACL. Returns $true if it changed anything.
function Add-TrapRule([string]$Path) {
    $sacl = Get-Sacl $Path
    if (Test-HasTrapRule $sacl -ExplicitOnly) { return $false }
    $sacl.AddAuditRule((New-TrapAuditRule))
    ([System.IO.DirectoryInfo]$Path).SetAccessControl($sacl)
    return $true
}

# --- 0. Pre-flight --------------------------------------------------------------

Write-Step 'Checking the target folder'
if (-not (Test-Path -LiteralPath $PackagesPath -PathType Container)) {
    throw "Folder not found: $PackagesPath  (run this from your own account, or pass -PackagesPath)"
}
$PackagesPath = (Get-Item -LiteralPath $PackagesPath -Force).FullName
Write-Ok "Watching $PackagesPath"

if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir | Out-Null
    # Our own new folder: SYSTEM + Administrators full control, Users read-only,
    # so nothing unelevated can tamper with the backup we restore from later.
    & icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    Write-Ok "Created $StateDir"
}

# Load the state from an earlier run, or record the "before" values now.
if (Test-Path -LiteralPath $StateFile) {
    $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    $state.saclRuleAddedTo = @($state.saclRuleAddedTo | Where-Object { $_ })
    Write-Info "Found state from an earlier run ($($state.createdAt)); keeping its original 'before' values."
} else {
    $prevCmdLine = Get-ItemProperty -Path $CmdLineKey -Name $CmdLineValue -ErrorAction SilentlyContinue
    $state = [pscustomobject]@{
        createdAt                  = (Get-Date).ToString('s')
        packagesPath               = $PackagesPath
        auditpolBackup             = $AuditBackup
        cmdLineValueExisted        = [bool]$prevCmdLine
        cmdLineValuePrevious       = $(if ($prevCmdLine) { [int]$prevCmdLine.$CmdLineValue } else { $null })
        securityLogPreviousMaxSize = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
        securityLogSizeChanged     = $false
        saclRuleAddedTo            = @()   # folders where WE added the rule (Disable removes only these)
    }
}

function Save-State { $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StateFile -Encoding UTF8 }

# Remembers that we added the rule to a folder, so Disable removes it only there.
function Add-StatePath([string]$Path) {
    $state.saclRuleAddedTo = @(@($state.saclRuleAddedTo) + $Path | Where-Object { $_ } | Select-Object -Unique)
    Save-State
}

# --- 1. Back up the audit policy ------------------------------------------------

Write-Step 'Backing up the current audit policy'
if (Test-Path -LiteralPath $AuditBackup) {
    Write-Ok "Backup already exists, not overwriting: $AuditBackup"
} else {
    & auditpol.exe /backup "/file:$AuditBackup" | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $AuditBackup)) {
        throw "auditpol /backup failed (exit code $LASTEXITCODE). Nothing has been changed."
    }
    Write-Ok "Saved $AuditBackup"
}
Save-State

# --- 2. Enable the audit subcategories ------------------------------------------

Write-Step 'Enabling audit subcategories (success)'
foreach ($name in $Subcategories.Keys) {
    $guid = $Subcategories[$name]
    & auditpol.exe /set "/subcategory:$guid" /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed for $name $guid (exit code $LASTEXITCODE)" }
    Write-Ok $name
}

# --- 3. Command lines in process-creation events --------------------------------

Write-Step 'Including command lines in process-creation events (4688)'
if (-not (Test-Path -Path $CmdLineKey)) { New-Item -Path $CmdLineKey -Force | Out-Null }
Set-ItemProperty -Path $CmdLineKey -Name $CmdLineValue -Value 1 -Type DWord
Write-Ok "$CmdLineKey\$CmdLineValue = 1"

# --- 4. Security log size -------------------------------------------------------

Write-Step 'Security log size'
$currentSize = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
if ($currentSize -ge $LogSizeBytes) {
    Write-Ok ("Already {0:N0} MB, leaving it" -f ($currentSize / 1MB))
} else {
    & wevtutil.exe sl Security "/ms:$LogSizeBytes"
    if ($LASTEXITCODE -ne 0) { throw "wevtutil failed (exit code $LASTEXITCODE)" }
    $state.securityLogSizeChanged = $true
    Save-State
    Write-Ok ("Raised from {0:N0} MB to {1:N0} MB" -f ($currentSize / 1MB), ($LogSizeBytes / 1MB))
}

# --- 5. Audit rule (SACL) on the Packages folder --------------------------------

Write-Step 'Adding the audit rule to the Packages folder'
$daclBefore = Get-DaclSddl $PackagesPath

if (Add-TrapRule $PackagesPath) {
    Add-StatePath $PackagesPath
    Write-Ok "Rule added to $PackagesPath"
} else {
    Write-Ok "Rule already present on $PackagesPath"
}

$daclAfter = Get-DaclSddl $PackagesPath
if ($daclBefore -eq $daclAfter) {
    Write-Ok 'Folder permissions (DACL) unchanged'
} else {
    Write-Warn 'The folder permissions (DACL) changed while the audit rule was set!'
    Write-Info "Before: $daclBefore"
    Write-Info "After:  $daclAfter"
}

# Subfolders normally inherit the rule. A subfolder whose SACL is "protected"
# (inheritance blocked) does not, so we add the rule to it directly.
Write-Step 'Checking that app folders inherited the audit rule'
$inherited = 0; $addedDirect = 0; $failed = @()
foreach ($dir in Get-ChildItem -LiteralPath $PackagesPath -Directory -Force -ErrorAction SilentlyContinue) {
    try {
        $sacl = Get-Sacl $dir.FullName
        if (Test-HasTrapRule $sacl) { $inherited++; continue }
        if (Add-TrapRule $dir.FullName) {
            $addedDirect++
            Add-StatePath $dir.FullName
            Write-Info "Added directly (inheritance blocked): $($dir.Name)"
        }
    } catch {
        $failed += "$($dir.Name): $($_.Exception.Message)"
    }
}
Write-Ok "$inherited folder(s) inherited the rule, $addedDirect needed it added directly"
foreach ($f in $failed) { Write-Warn "Could not check/set: $f" }

# --- Summary --------------------------------------------------------------------

Write-Step 'Current audit policy for the three subcategories'
& auditpol.exe /get "/subcategory:$($Subcategories.Values -join ',')"

Write-Host ''
Write-Host 'Auditing is on. When an app breaks, run Get-PermissionReport.ps1 (elevated).' -ForegroundColor Green
Write-Host "Undo with Disable-Auditing.ps1. State and backup are in $StateDir"
