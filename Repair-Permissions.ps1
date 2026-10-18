#Requires -Version 5.1
<#
.SYNOPSIS
    Puts SYSTEM and Administrators back on Packages folders that lost them.
    Run by the PermissionTrap-Repair scheduled task (as SYSTEM); you do not
    normally run it yourself.

.DESCRIPTION
    1. Checks the Packages folder, then every app folder in it. A folder needs
       repair if its permissions have no Allow entry for SYSTEM (S-1-5-18) or
       for Administrators (S-1-5-32-544).
    2. Backs up each folder's current permissions first:
         icacls <folder> /save backups\<time>\<folder>.acl /T /C
    3. Grants only the missing one(s), (OI)(CI) Full control - recursively for
       app folders, non-recursively for Packages itself. Only ADDS entries:
       never /reset, never /remove, never touches inheritance or the owner.
    4. Logs every fix (and any error) to C:\ProgramData\PermissionTrap\repair.log.
    5. If it fixed something, checks again after -RecheckSeconds, in case the
       program that strips permissions was still working (up to 3 rounds).

    SYSTEM is not in a stripped folder's permissions, so the script enables
    SYSTEM's backup/restore privileges, which let it read and change
    permissions regardless of what they say.

.PARAMETER PackagesPath
    Full path to the user's Packages folder. Required: when running as SYSTEM,
    %LOCALAPPDATA% points at SYSTEM's own profile, not yours.

.PARAMETER RecheckSeconds
    How long to wait before checking again after a fix. Default 30.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackagesPath,
    [int]$RecheckSeconds = 30
)

$ErrorActionPreference = 'Stop'

$SystemSid  = 'S-1-5-18'
$AdminsSid  = 'S-1-5-32-544'
$StateDir   = Join-Path $env:ProgramData 'PermissionTrap'
$LogFile    = Join-Path $StateDir 'repair.log'
$BackupRoot = Join-Path $StateDir 'backups'
$MaxLogSize = 5MB
$MaxRounds  = 3

# --- Logging ------------------------------------------------------------------

function Write-Log([string]$Text) {
    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    # Keep one old log: repair.log -> repair.log.1 at 5 MB.
    if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt $MaxLogSize) {
        Move-Item -LiteralPath $LogFile -Destination "$LogFile.1" -Force
    }
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Text
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

# --- Privileges ---------------------------------------------------------------

# Turns on a privilege in this process's token. Child processes (icacls) get a
# copy of the token, so they have it too.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PermissionTrapPrivilege {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct TokenPrivilege { public int Count; public long Luid; public int Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string system, string name, ref long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivilege state, int length, IntPtr previous, IntPtr returnLength);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

    public static bool Enable(string name) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28 /* ADJUST_PRIVILEGES | QUERY */, out token)) return false;
        try {
            TokenPrivilege tp = new TokenPrivilege { Count = 1, Luid = 0, Attributes = 2 /* ENABLED */ };
            if (!LookupPrivilegeValue(null, name, ref tp.Luid)) return false;
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
            return Marshal.GetLastWin32Error() == 0;   // 1300 = the token does not hold this privilege
        } finally { CloseHandle(token); }
    }
}
'@

# --- Checking a folder ----------------------------------------------------------

# Which of SYSTEM / Administrators the folder is missing (empty = healthy).
function Get-MissingSids([string]$Path) {
    try {
        $acl   = ([System.IO.DirectoryInfo]$Path).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $allow = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object { $_.IdentityReference.Value })
    } catch {
        # Could not even read the permissions: SYSTEM is certainly not in them.
        return @($SystemSid, $AdminsSid)
    }
    @(@($SystemSid, $AdminsSid) | Where-Object { $allow -notcontains $_ })
}

function Get-SidLabel([string[]]$Sids) {
    ($Sids | ForEach-Object { if ($_ -eq $SystemSid) { 'SYSTEM' } else { 'Administrators' } }) -join '+'
}

# Runs icacls and returns its exit code plus up to 5 error lines for the log.
function Invoke-Icacls([string[]]$Arguments) {
    # In PowerShell 5.1, redirected stderr lines from a program count as errors,
    # which 'Stop' would turn into an exception. icacls failures are handled below.
    $ErrorActionPreference = 'Continue'
    $out = @(& icacls.exe @Arguments 2>&1 | ForEach-Object { "$_" })
    [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Errors   = @($out | Where-Object { $_ -and $_ -notmatch '^(processed |Successfully processed )' } | Select-Object -First 5)
    }
}

# --- Repairing a folder ---------------------------------------------------------

# Backs up and repairs one folder. Returns $true if it is healthy afterwards.
function Repair-Folder([string]$Path, [string[]]$Missing, [string]$BackupDir, [switch]$Recurse) {
    $name   = Split-Path $Path -Leaf
    $backup = Join-Path $BackupDir "$name.acl"
    $tree   = if ($Recurse) { @('/T', '/C') } else { @('/C') }

    # 1. Backup. Restore later with:  icacls "<parent folder>" /restore "<backup file>"
    $save = Invoke-Icacls (@($Path, '/save', $backup) + $tree)
    if (-not (Test-Path -LiteralPath $backup)) {
        Write-Log "ERROR   $name  backup failed (icacls exit $($save.ExitCode)), NOT repairing: $($save.Errors -join ' | ')"
        return $false
    }

    # 2. Grant only what is missing. /grant adds; it never removes existing entries.
    $grants = @($Missing | ForEach-Object { "*${_}:(OI)(CI)F" })
    $grant  = Invoke-Icacls (@($Path, '/grant') + $grants + $tree)

    # 3. Check the result on the folder itself.
    $still = Get-MissingSids $Path
    $note  = if ($grant.ExitCode -ne 0) { "  (icacls exit $($grant.ExitCode), some items failed: $($grant.Errors -join ' | '))" } else { '' }
    if ($still.Count -eq 0) {
        Write-Log "FIXED   $name  added $(Get-SidLabel $Missing)  backup=$backup$note"
        return $true
    }
    Write-Log "FAILED  $name  still missing $(Get-SidLabel $still) after granting  backup=$backup$note"
    return $false
}

# One full check-and-repair pass. Returns @{ Fixed = n; Failed = n }.
function Invoke-RepairPass([string]$BackupDir) {
    $fixed = 0; $failed = 0

    # Packages itself first (not recursive): app folders that inherit from it
    # are then fixed by inheritance and will not show up as broken below.
    $missing = Get-MissingSids $PackagesPath
    if ($missing.Count) {
        if (-not (Test-Path -LiteralPath $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
        if (Repair-Folder $PackagesPath $missing $BackupDir) { $fixed++ } else { $failed++ }
    }

    foreach ($dir in Get-ChildItem -LiteralPath $PackagesPath -Directory -Force -ErrorAction SilentlyContinue) {
        $missing = Get-MissingSids $dir.FullName
        if (-not $missing.Count) { continue }
        if (-not (Test-Path -LiteralPath $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
        if (Repair-Folder $dir.FullName $missing $BackupDir -Recurse) { $fixed++ } else { $failed++ }
    }
    @{ Fixed = $fixed; Failed = $failed }
}

# --- Main -----------------------------------------------------------------------

# Only one repair at a time (the task can be triggered by many events at once).
$mutex = New-Object System.Threading.Mutex($false, 'Global\PermissionTrapRepair')
if (-not $mutex.WaitOne(0)) { exit 0 }

$exitCode = 0
try {
    if (-not (Test-Path -LiteralPath $PackagesPath -PathType Container)) {
        Write-Log "ERROR   Packages folder not found: $PackagesPath"
        $exitCode = 1
    } else {
        foreach ($p in 'SeBackupPrivilege', 'SeRestorePrivilege') {
            if (-not [PermissionTrapPrivilege]::Enable($p)) { Write-Log "WARN    could not enable $p (not running as SYSTEM/admin?)" }
        }

        for ($round = 1; $round -le $MaxRounds; $round++) {
            $backupDir = Join-Path $BackupRoot ('{0:yyyy-MM-dd_HH-mm-ss}' -f (Get-Date))
            $result = Invoke-RepairPass $backupDir
            if ($result.Fixed + $result.Failed -eq 0) { break }   # nothing (more) to do - also ends runs caused by our own repairs
            Write-Log "SUMMARY round $round as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name): $($result.Fixed) fixed, $($result.Failed) failed"
            if ($result.Failed) { $exitCode = 2 }
            if ($round -lt $MaxRounds) { Start-Sleep -Seconds $RecheckSeconds }
        }
    }
} catch {
    Write-Log "ERROR   $($_.Exception.Message)"
    $exitCode = 1
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
exit $exitCode
