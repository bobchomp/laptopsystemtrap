# Helpers shared by the steps of .github/workflows/test-part1.yml.
# Dot-source it:  . .\tests\Part1Helpers.ps1

$PackagesPath = Join-Path $env:LOCALAPPDATA 'Packages'
$TestFolder   = Join-Path $PackagesPath 'PermissionTrap.TestFolder'
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
