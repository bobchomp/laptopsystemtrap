#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Undoes everything Enable-Auditing.ps1 changed.

.DESCRIPTION
    Uses the backup and "before" values Enable-Auditing.ps1 saved in
    C:\ProgramData\PermissionTrap\audit-state.json:
      1. Removes our audit rule (SACL) from the folders we added it to.
         Folder permissions (DACL) are not touched.
      2. Restores the audit policy from auditpol-backup.csv.
      3. Puts ProcessCreationIncludeCmdLine_Enabled back to its old value
         (or deletes it if it did not exist before).
      4. Puts the Security log maximum size back, if we raised it.
    The Security log's existing events are kept.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Disable-Auditing.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$StateDir     = Join-Path $env:ProgramData 'PermissionTrap'
$StateFile    = Join-Path $StateDir 'audit-state.json'
$CmdLineKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$CmdLineValue = 'ProcessCreationIncludeCmdLine_Enabled'

# Must match the rule in Enable-Auditing.ps1 exactly.
$EveryoneSid  = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$AuditRights  = [System.Security.AccessControl.FileSystemRights]'ChangePermissions, TakeOwnership'
$AuditInherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'

function New-TrapAuditRule {
    New-Object System.Security.AccessControl.FileSystemAuditRule(
        $EveryoneSid, $AuditRights, $AuditInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success)
}

function Write-Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "   WARN $Text" -ForegroundColor Yellow }

if (-not (Test-Path -LiteralPath $StateFile)) {
    throw "No saved state at $StateFile - Enable-Auditing.ps1 has not been run (or was already undone)."
}
$state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
$problems = 0

# --- 1. Remove our audit rule ---------------------------------------------------

Write-Step 'Removing the audit rule'
foreach ($path in @($state.saclRuleAddedTo | Where-Object { $_ })) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        Write-Ok "Folder no longer exists: $path"
        continue
    }
    try {
        # Only the Audit section is read and written, so the DACL is left alone.
        $dir  = [System.IO.DirectoryInfo]$path
        $sacl = $dir.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
        $sacl.RemoveAuditRuleSpecific((New-TrapAuditRule))
        $dir.SetAccessControl($sacl)
        Write-Ok $path
    } catch {
        $problems++
        Write-Warn "Could not remove rule from ${path}: $($_.Exception.Message)"
    }
}

# --- 2. Restore the audit policy ------------------------------------------------

Write-Step 'Restoring the audit policy'
if (Test-Path -LiteralPath $state.auditpolBackup) {
    & auditpol.exe /restore "/file:$($state.auditpolBackup)" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Restored from $($state.auditpolBackup)"
    } else {
        $problems++
        Write-Warn "auditpol /restore failed (exit code $LASTEXITCODE)"
    }
} else {
    $problems++
    Write-Warn "Backup file missing: $($state.auditpolBackup)"
}

# --- 3. Command-line logging registry value -------------------------------------

Write-Step 'Restoring the command-line logging setting'
try {
    if ($state.cmdLineValueExisted) {
        Set-ItemProperty -Path $CmdLineKey -Name $CmdLineValue -Value ([int]$state.cmdLineValuePrevious) -Type DWord
        Write-Ok "$CmdLineValue set back to $($state.cmdLineValuePrevious)"
    } else {
        Remove-ItemProperty -Path $CmdLineKey -Name $CmdLineValue -ErrorAction SilentlyContinue
        Write-Ok "$CmdLineValue removed (it did not exist before)"
    }
} catch {
    $problems++
    Write-Warn "Could not restore ${CmdLineValue}: $($_.Exception.Message)"
}

# --- 4. Security log size -------------------------------------------------------

Write-Step 'Security log size'
if ($state.securityLogSizeChanged) {
    & wevtutil.exe sl Security "/ms:$($state.securityLogPreviousMaxSize)"
    if ($LASTEXITCODE -eq 0) {
        Write-Ok ("Set back to {0:N0} MB" -f ($state.securityLogPreviousMaxSize / 1MB))
    } else {
        $problems++
        Write-Warn "wevtutil failed (exit code $LASTEXITCODE)"
    }
} else {
    Write-Ok 'Was not changed by Enable-Auditing.ps1, leaving it'
}

# --- Clean up -------------------------------------------------------------------

Write-Host ''
if ($problems -eq 0) {
    # Remove the state so a later Enable-Auditing.ps1 takes a fresh backup.
    Remove-Item -LiteralPath $StateFile, $state.auditpolBackup -Force -ErrorAction SilentlyContinue
    Write-Host 'Auditing settings restored.' -ForegroundColor Green
    Write-Host "Reports (if any) are still in $StateDir\reports - delete that folder when you no longer need it."
} else {
    Write-Host "$problems step(s) had problems (see WARN lines). State kept in $StateFile so you can re-run this script." -ForegroundColor Yellow
}
