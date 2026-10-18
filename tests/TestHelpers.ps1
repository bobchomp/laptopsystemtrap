# Helpers shared by the steps of .github/workflows/test-part1.yml.
# Dot-source it:  . .\tests\TestHelpers.ps1

$PackagesPath = Join-Path $env:LOCALAPPDATA 'Packages'
$TestFolder   = Join-Path $PackagesPath 'PermissionTrap.TestFolder'      # part 1: caught by the report
$RepairFolderA = Join-Path $PackagesPath 'PermissionTrap.RepairTestA'   # part 2: repaired on demand
$RepairFolderB = Join-Path $PackagesPath 'PermissionTrap.RepairTestB'   # part 2: repaired by the audit-event trigger
$RepairTask   = 'PermissionTrap-Repair'
$RepairLog    = Join-Path $env:ProgramData 'PermissionTrap\repair.log'
$StateDir     = Join-Path $env:ProgramData 'PermissionTrap'
$ArtifactDir  = Join-Path $env:RUNNER_TEMP 'part1-artifacts'
$BeforeFile   = Join-Path $ArtifactDir 'snapshot-before.json'

$Subcategories = [ordered]@{
    'File System'                 = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    'Authorization Policy Change' = '{0CCE9231-69AE-11D9-BED3-505054503030}'
    'Process Creation'            = '{0CCE922B-69AE-11D9-BED3-505054503030}'
}

if (-not (Test-Path -LiteralPath $ArtifactDir)) { New-Item -ItemType Directory -Path $ArtifactDir | Out-Null }

# Everything the scripts change, in a form that can be compared before/after.
function Get-AuditSnapshot {
    # /r gives CSV: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
    $csv = & auditpol.exe /get "/subcategory:$($Subcategories.Values -join ',')" /r | Where-Object { $_.Trim() }
    $settings = [ordered]@{}
    foreach ($row in ($csv | ConvertFrom-Csv)) { $settings[$row.'Subcategory GUID'.ToUpper()] = $row.'Inclusion Setting' }

    $cmd = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue

    [pscustomobject]@{
        AuditSettings  = [pscustomobject]$settings
        CmdLineValue   = $(if ($cmd) { [int]$cmd.ProcessCreationIncludeCmdLine_Enabled } else { $null })
        SecurityLogMax = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
        HasAuditRule   = Test-PackagesAuditRule
    }
}

# True if the Packages folder has an Everyone / ChangePermissions+TakeOwnership / Success audit rule.
function Test-PackagesAuditRule {
    $sacl  = ([System.IO.DirectoryInfo]$PackagesPath).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
    $need  = [System.Security.AccessControl.FileSystemRights]'ChangePermissions, TakeOwnership'
    $rules = $sacl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    [bool]($rules | Where-Object {
        $_.IdentityReference.Value -eq 'S-1-1-0' -and
        ($_.FileSystemRights -band $need) -eq $need -and
        ($_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)
    })
}

# Assertions are collected so one run shows every failure, then Complete-Assertions fails the step.
$script:Failures = New-Object System.Collections.Generic.List[string]
function Assert-True($Condition, [string]$Message) {
    if ([bool]$Condition) { Write-Host "PASS  $Message" -ForegroundColor Green }
    else            { Write-Host "FAIL  $Message" -ForegroundColor Red; $script:Failures.Add($Message) }
}
function Complete-Assertions {
    if ($script:Failures.Count) {
        foreach ($f in $script:Failures) { Write-Host "::error::$f" }
        throw "$($script:Failures.Count) assertion(s) failed"
    }
}

# Creates a folder (with a file in it) under Packages, then strips it to the
# current user only - like the real culprit - by running icacls from THIS
# powershell.exe. New folders here can get explicit (not inherited) SYSTEM and
# Administrators entries, which /inheritance:r leaves alone, so remove those too.
function New-StrippedTestFolder([string]$Path) {
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    New-Item -ItemType Directory -Path $Path | Out-Null
    Set-Content -LiteralPath (Join-Path $Path 'test.txt') -Value 'test'
    Write-Host 'Before:'; & icacls.exe $Path

    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $Path /inheritance:r /grant:r "${me}:(OI)(CI)F" /remove:g '*S-1-5-18' '*S-1-5-32-544'
    if ($LASTEXITCODE -ne 0) { throw "icacls failed with exit code $LASTEXITCODE" }
    Write-Host 'After:'; & icacls.exe $Path

    # The test is meaningless unless the folder really lost SYSTEM and Administrators.
    Assert-True (-not (Test-HasSid $Path 'S-1-5-18'))     "$(Split-Path $Path -Leaf) no longer has SYSTEM"
    Assert-True (-not (Test-HasSid $Path 'S-1-5-32-544')) "$(Split-Path $Path -Leaf) no longer has Administrators"
    Complete-Assertions
}

# Does the folder's DACL have an Allow entry for this SID?
function Test-HasSid([string]$Path, [string]$Sid) {
    $acl   = ([System.IO.DirectoryInfo]$Path).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    [bool]($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $Sid })
}

# Polls $Condition every 2 seconds until it is true or $Seconds have passed.
function Wait-Until([int]$Seconds, [scriptblock]$Condition) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Seconds 2
    }
    [bool](& $Condition)
}

# Waits for the repair task to finish its current run (it re-checks 30 s after a fix).
function Wait-RepairTaskIdle([int]$Seconds = 180) {
    Wait-Until $Seconds { (Get-ScheduledTask -TaskName $RepairTask).State -ne 'Running' }
}

# Checks that the repair task fixed a folder: SYSTEM + Administrators back, the
# user's own entry and the "inheritance off" setting untouched (add only),
# a backup written and the fix recorded in repair.log.
function Assert-Repaired([string]$Path) {
    $name = Split-Path $Path -Leaf
    $me   = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert-True (Test-HasSid $Path 'S-1-5-18')     "$name has SYSTEM again"
    Assert-True (Test-HasSid $Path 'S-1-5-32-544') "$name has Administrators again"
    Assert-True (Test-HasSid $Path $me)            "$name still has the current user's entry (repair only adds)"
    $acl = ([System.IO.DirectoryInfo]$Path).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    Assert-True $acl.AreAccessRulesProtected "$name inheritance still off (repair did not reset it)"

    $backup = Get-ChildItem -LiteralPath (Join-Path $StateDir 'backups') -Recurse -Filter "$name.acl" -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 0 } | Select-Object -First 1
    Assert-True $backup "ACL backup written for $name$(if ($backup) { ": $($backup.FullName)" })"

    $logged = (Test-Path -LiteralPath $RepairLog) -and (Select-String -LiteralPath $RepairLog -Pattern "FIXED\s+$([regex]::Escape($name))\s" -Quiet)
    Assert-True $logged "repair.log records the fix for $name"
}
