#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the PermissionTrap-Repair scheduled task and its copy of the
    repair script. Permissions it already repaired are left as they are.

.PARAMETER RemoveLogsAndBackups
    Also delete repair.log and the ACL backups in C:\ProgramData\PermissionTrap.
    By default they are kept.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Uninstall-RepairTask.ps1
#>
[CmdletBinding()]
param(
    [switch]$RemoveLogsAndBackups
)

$ErrorActionPreference = 'Stop'

$TaskName = 'PermissionTrap-Repair'
$StateDir = Join-Path $env:ProgramData 'PermissionTrap'

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
} else {
    Write-Host "Scheduled task '$TaskName' was not installed."
}

Remove-Item -LiteralPath (Join-Path $StateDir 'Repair-Permissions.ps1') -Force -ErrorAction SilentlyContinue

$kept = @(Join-Path $StateDir 'repair.log'; Join-Path $StateDir 'repair.log.1'; Join-Path $StateDir 'backups') |
    Where-Object { Test-Path -LiteralPath $_ }
if ($RemoveLogsAndBackups) {
    $kept | ForEach-Object { Remove-Item -LiteralPath $_ -Recurse -Force }
    if ($kept) { Write-Host 'Deleted repair.log and the ACL backups.' }
} elseif ($kept) {
    Write-Host "Kept repair.log and backups in $StateDir (use -RemoveLogsAndBackups to delete them)."
}
