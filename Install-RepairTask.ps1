#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers the PermissionTrap-Repair scheduled task, which puts SYSTEM and
    Administrators back on %LOCALAPPDATA%\Packages folders that lost them.

.DESCRIPTION
    - Copies Repair-Permissions.ps1 to C:\ProgramData\PermissionTrap\, a folder
      only SYSTEM and Administrators can change. The task runs as SYSTEM, so it
      must never run a script that ordinary programs could edit.
    - Registers the task: runs as SYSTEM with highest privileges, at every
      logon, whether or not anyone is logged on, one instance at a time.
    - With -WithAuditTrigger it ALSO runs when Windows logs a permission change
      on a file or folder (event 4670) - 30 seconds later, so the program
      doing it can finish first. This needs Enable-Auditing.ps1 to have been
      run; without the audit rule that event never fires.

    The repair only ADDS the two missing entries. It backs up permissions
    first and logs every fix to C:\ProgramData\PermissionTrap\repair.log.

    Run it from your own account (elevated): your Packages path is worked out
    now and stored in the task, because %LOCALAPPDATA% means something else
    when running as SYSTEM.

.PARAMETER PackagesPath
    Defaults to %LOCALAPPDATA%\Packages of the account running this script.

.PARAMETER WithAuditTrigger
    Also run the repair when a permission-change audit event (4670) fires.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-RepairTask.ps1 -WithAuditTrigger
#>
[CmdletBinding()]
param(
    [string]$PackagesPath = (Join-Path $env:LOCALAPPDATA 'Packages'),
    [switch]$WithAuditTrigger
)

$ErrorActionPreference = 'Stop'

$TaskName     = 'PermissionTrap-Repair'
$StateDir     = Join-Path $env:ProgramData 'PermissionTrap'
$SourceScript = Join-Path $PSScriptRoot 'Repair-Permissions.ps1'
$TargetScript = Join-Path $StateDir 'Repair-Permissions.ps1'
$EventDelay   = 'PT30S'   # ISO 8601: wait 30 seconds after the event before repairing

function Write-Step([string]$Text) { Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "   WARN $Text" -ForegroundColor Yellow }

# --- Checks -------------------------------------------------------------------

Write-Step 'Checking'
if (-not (Test-Path -LiteralPath $PackagesPath -PathType Container)) {
    throw "Folder not found: $PackagesPath  (run this from your own account, or pass -PackagesPath)"
}
$PackagesPath = (Get-Item -LiteralPath $PackagesPath -Force).FullName.TrimEnd('\')
Write-Ok "Packages folder: $PackagesPath"
if (-not (Test-Path -LiteralPath $SourceScript)) { throw "Repair-Permissions.ps1 not found next to this script ($SourceScript)" }

if ($WithAuditTrigger) {
    $sacl = ([System.IO.DirectoryInfo]$PackagesPath).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
    $hasRule = [bool]($sacl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions) })
    if ($hasRule) { Write-Ok 'Audit rule found on Packages, so the event trigger will work' }
    else          { Write-Warn 'No audit rule on Packages - run Enable-Auditing.ps1, or the event trigger will never fire' }
}

# --- Copy the script to the admin-only folder ------------------------------------

Write-Step "Copying the repair script to $StateDir"
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }
# Our own folder: SYSTEM + Administrators full control, Users read-only (same as Enable-Auditing.ps1).
& icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set permissions on $StateDir (icacls exit $LASTEXITCODE)" }
Copy-Item -LiteralPath $SourceScript -Destination $TargetScript -Force
Write-Ok $TargetScript

# --- Register the task ----------------------------------------------------------

Write-Step "Registering scheduled task '$TaskName'"

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden ' +
    "-File `"$TargetScript`" -PackagesPath `"$PackagesPath`"")

$triggers = @(New-ScheduledTaskTrigger -AtLogOn)

if ($WithAuditTrigger) {
    # Event 4670 "Permissions on an object were changed", for files/folders only
    # (4670 is also logged for other object types such as process tokens). XPath
    # cannot match a path prefix, so this fires for any audited file; the script
    # checks the real state and exits quietly if nothing under Packages is broken.
    $query = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[EventID=4670] and EventData[Data[@Name='ObjectType']='File']]</Select></Query></QueryList>
"@
    $cls = Get-CimClass -Namespace 'Root/Microsoft/Windows/TaskScheduler' -ClassName 'MSFT_TaskEventTrigger'
    $eventTrigger = New-CimInstance -CimClass $cls -ClientOnly
    $eventTrigger.Enabled      = $true
    $eventTrigger.Subscription = $query
    $eventTrigger.Delay        = $EventDelay
    $triggers += $eventTrigger
}

# S-1-5-18 = SYSTEM (by SID, so it works on non-English Windows too).
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings `
    -Description "Re-grants SYSTEM and Administrators on $PackagesPath when they go missing. Installed by Install-RepairTask.ps1; logs to $StateDir\repair.log." `
    -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName
Write-Ok "Registered (runs as $($task.Principal.UserId), triggers: $(($task.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task|Trigger$' }) -join ', '))"

Write-Host ''
Write-Host 'Done. The repair runs at every logon' -NoNewline -ForegroundColor Green
if ($WithAuditTrigger) { Write-Host ' and 30 s after a permission-change event' -NoNewline -ForegroundColor Green }
Write-Host '.' -ForegroundColor Green
Write-Host "Run it now:     Start-ScheduledTask -TaskName $TaskName"
Write-Host "What it fixed:  Get-Content '$StateDir\repair.log' -Tail 20"
Write-Host 'Remove it:      .\Uninstall-RepairTask.ps1'
