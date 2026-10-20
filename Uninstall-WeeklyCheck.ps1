#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the PermissionTrap-WeeklyCheck scheduled task, its script, its
    settings and the stored (encrypted) Resend API key.

.PARAMETER RemoveLogs
    Also delete weekly.log and weekly-state.json (the clear-weeks count).
    By default they are kept.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Uninstall-WeeklyCheck.ps1
#>
[CmdletBinding()]
param(
    [switch]$RemoveLogs
)

$ErrorActionPreference = 'Stop'

$TaskName = 'PermissionTrap-WeeklyCheck'
$StateDir = Join-Path $env:ProgramData 'PermissionTrap'

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
} else {
    Write-Host "Scheduled task '$TaskName' was not installed."
}

# The key is always removed: no point keeping a secret nothing uses.
foreach ($name in 'Invoke-WeeklyCheck.ps1', 'weekly-config.json', 'weekly-resend.key') {
    Remove-Item -LiteralPath (Join-Path $StateDir $name) -Force -ErrorAction SilentlyContinue
}
Write-Host 'Removed the check script, its settings and the stored API key.'

$logs = @('weekly.log', 'weekly.log.1', 'weekly-state.json') | ForEach-Object { Join-Path $StateDir $_ } |
    Where-Object { Test-Path -LiteralPath $_ }
if ($RemoveLogs) {
    $logs | ForEach-Object { Remove-Item -LiteralPath $_ -Force }
    if ($logs) { Write-Host 'Deleted weekly.log and weekly-state.json.' }
} elseif ($logs) {
    Write-Host "Kept weekly.log and weekly-state.json in $StateDir (use -RemoveLogs to delete them)."
}
