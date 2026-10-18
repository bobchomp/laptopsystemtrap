#Requires -Version 5.1
<#
.SYNOPSIS
    Run this when a Store app breaks. Shows which Packages folders are missing
    SYSTEM / Administrators, and which process changed permissions there.

.DESCRIPTION
    Part 1 - Folder check: scans the Packages folder and every app folder in
             it. A folder is "broken" if its permissions have no entry for
             SYSTEM (S-1-5-18). Missing Administrators (S-1-5-32-544) is
             reported too.
    Part 2 - Audit check: confirms the auditing from Enable-Auditing.ps1 is
             still on, and how far back the Security log goes.
    Part 3 - Who did it: reads events 4670 (permissions changed) and 4663
             (object access with WRITE_DAC / WRITE_OWNER) under Packages,
             groups them into bursts per process, and for each burst walks the
             parent chain using process-creation events (4688), with command
             lines. Bursts that actually removed SYSTEM or Administrators are
             listed first.

    Read-only: changes nothing except writing the report file.
    Parts 2 and 3 need an elevated PowerShell (the Security log is admin-only).

.PARAMETER PackagesPath
    Defaults to %LOCALAPPDATA%\Packages of the account running the script.

.PARAMETER Hours
    Only look at events from the last N hours. Default: everything still in
    the Security log.

.PARAMETER MaxEvents
    Upper limit on permission events read (newest first). Default 50000.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-PermissionReport.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-PermissionReport.ps1 -Hours 48
#>
[CmdletBinding()]
param(
    [string]$PackagesPath = (Join-Path $env:LOCALAPPDATA 'Packages'),
    [int]$Hours = 0,
    [int]$MaxEvents = 50000
)

$ErrorActionPreference = 'Stop'

$SystemSid   = 'S-1-5-18'
$AdminsSid   = 'S-1-5-32-544'
$WriteDac    = 0x40000
$WriteOwner  = 0x80000
$BurstGapMin = 10      # events from the same process more than this many minutes apart are separate bursts
$ReportDir   = Join-Path $env:ProgramData 'PermissionTrap\reports'
$StateFile   = Join-Path $env:ProgramData 'PermissionTrap\audit-state.json'

# --- Output: everything goes to the console AND the report file -----------------

$script:Lines = New-Object System.Collections.Generic.List[string]
function Out-Report([string]$Text = '', [string]$Color = '') {
    $script:Lines.Add($Text)
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Out-Heading([string]$Text) {
    Out-Report ''
    Out-Report ('=' * 78) 'Cyan'
    Out-Report $Text 'Cyan'
    Out-Report ('=' * 78) 'Cyan'
}

if (Test-Path -LiteralPath $PackagesPath -PathType Container) {
    $PackagesPath = (Get-Item -LiteralPath $PackagesPath -Force).FullName.TrimEnd('\')
}

$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Out-Report "Permission report - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Out-Report "Packages folder: $PackagesPath"
Out-Report "Elevated: $isAdmin"

# ===============================================================================
# Part 1 - Folder check
# ===============================================================================

function Get-SidName([string]$Sid) {
    try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

# Returns what we need to know about one folder's DACL.
function Get-FolderAclInfo([string]$Path) {
    $acl   = ([System.IO.DirectoryInfo]$Path).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $allow = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' })
    [pscustomobject]@{
        Path          = $Path
        HasSystem     = [bool]($allow | Where-Object { $_.IdentityReference.Value -eq $SystemSid })
        HasAdmins     = [bool]($allow | Where-Object { $_.IdentityReference.Value -eq $AdminsSid })
        Protected     = $acl.AreAccessRulesProtected    # True = inheritance turned off
        Rules         = $rules
    }
}

function Format-Rule($Rule) {
    $flags = @()
    if ($Rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)    { $flags += '(OI)' }
    if ($Rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) { $flags += '(CI)' }
    if ($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)      { $flags += '(IO)' }
    if ($Rule.IsInherited) { $flags += '(I)' }
    '{0}: {1} {2} {3}' -f (Get-SidName $Rule.IdentityReference.Value), $Rule.AccessControlType, $Rule.FileSystemRights, ($flags -join '')
}

Out-Heading 'PART 1 - Folders missing SYSTEM / Administrators'

if (-not (Test-Path -LiteralPath $PackagesPath -PathType Container)) {
    Out-Report "Folder not found: $PackagesPath" 'Red'
    $broken = @(); $brokenNames = @{}
} else {
    $folders = @((Get-Item -LiteralPath $PackagesPath -Force)) +
               @(Get-ChildItem -LiteralPath $PackagesPath -Directory -Force -ErrorAction SilentlyContinue)
    $infos = @(); $unreadable = @()
    foreach ($f in $folders) {
        try   { $infos += Get-FolderAclInfo $f.FullName }
        catch { $unreadable += "$($f.FullName)  ($($_.Exception.Message))" }
    }

    $broken      = @($infos | Where-Object { -not $_.HasSystem })
    $noAdmins    = @($infos | Where-Object { $_.HasSystem -and -not $_.HasAdmins })
    $brokenNames = @{}
    foreach ($b in $broken) { $brokenNames[(Split-Path $b.Path -Leaf)] = $true }

    Out-Report ("Checked {0} folder(s): {1} missing SYSTEM, {2} missing only Administrators, {3} unreadable." -f `
        $infos.Count, $broken.Count, $noAdmins.Count, $unreadable.Count)

    $root = $infos | Where-Object { $_.Path -eq (Get-Item -LiteralPath $PackagesPath -Force).FullName } | Select-Object -First 1
    if ($root) {
        Out-Report ''
        Out-Report "Packages folder itself: SYSTEM=$($root.HasSystem)  Administrators=$($root.HasAdmins)  InheritanceOff=$($root.Protected)"
        foreach ($r in $root.Rules) { Out-Report "    $(Format-Rule $r)" }
    }

    if ($broken.Count) {
        Out-Report ''
        Out-Report 'Missing SYSTEM:' 'Red'
        foreach ($b in $broken) {
            $admin = if ($b.HasAdmins) { '' } else { '  [Administrators missing too]' }
            Out-Report ("  {0}{1}" -f (Split-Path $b.Path -Leaf), $admin) 'Red'
        }
        # Show the full permissions of the first broken app folder as a sample.
        $sample = $broken | Where-Object { $_.Path -ne $root.Path } | Select-Object -First 1
        if ($sample) {
            Out-Report ''
            Out-Report "Example permissions on $(Split-Path $sample.Path -Leaf) (InheritanceOff=$($sample.Protected)):"
            foreach ($r in $sample.Rules) { Out-Report "    $(Format-Rule $r)" }
        }
    } else {
        Out-Report 'All folders have SYSTEM.' 'Green'
    }
    if ($noAdmins.Count) {
        Out-Report ''
        Out-Report 'Have SYSTEM but missing Administrators:' 'Yellow'
        foreach ($n in $noAdmins) { Out-Report "  $(Split-Path $n.Path -Leaf)" 'Yellow' }
    }
    foreach ($u in $unreadable) { Out-Report "  Could not read: $u" 'Yellow' }
}

# ===============================================================================
# Part 2 - Is auditing still on?  (needs elevation)
# ===============================================================================

function Show-AuditSettings {
    Out-Heading 'PART 2 - Audit settings'

    & auditpol.exe /get '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030},{0CCE9231-69AE-11D9-BED3-505054503030},{0CCE922B-69AE-11D9-BED3-505054503030}' |
        Where-Object { $_.Trim() } | ForEach-Object { Out-Report "  $_" }

    $cmdLine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    Out-Report "  Command lines in 4688 events: $(if ($cmdLine -eq 1) { 'on' } else { 'OFF' })"

    try {
        $sacl = ([System.IO.DirectoryInfo]$PackagesPath).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
        $hasRule = [bool]($sacl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions) })
        Out-Report "  Audit rule on Packages folder: $(if ($hasRule) { 'present' } else { 'MISSING - run Enable-Auditing.ps1' })"
    } catch {
        Out-Report "  Audit rule on Packages folder: could not read ($($_.Exception.Message))" 'Yellow'
    }

    $secLog = Get-WinEvent -ListLog Security
    $oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
    Out-Report ("  Security log: {0:N0} MB max, {1:N0} events, oldest event {2}" -f `
        ($secLog.MaximumSizeInBytes / 1MB), $secLog.RecordCount, $(if ($oldest) { $oldest.TimeCreated } else { 'n/a' }))
    if (Test-Path -LiteralPath $StateFile) {
        $since = (Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json).createdAt
        Out-Report "  Enable-Auditing.ps1 first ran: $since"
    }
}

# ===============================================================================
# Part 3 - Who changed permissions?  (needs elevation)
# ===============================================================================

function Show-PermissionChanges {
    Out-Heading 'PART 3 - Processes that changed permissions under Packages'

    # Turns an event's <EventData> into a hashtable: Name -> value.
    function Get-EventFields($Record) {
        $h = @{}
        foreach ($d in ([xml]$Record.ToXml()).Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
        $h
    }

    function ConvertFrom-Hex([string]$Value) {
        if (-not $Value) { return [int64]0 }
        [Convert]::ToInt64(($Value -replace '^0x', ''), 16)
    }

    # Does an SDDL string grant (A = allow) anything to this SID? SY = SYSTEM, BA = Administrators.
    function Test-SddlAllows([string]$Sddl, [string]$Alias, [string]$Sid) {
        if (-not $Sddl) { return $null }
        $Sddl -match "\(A;[^;]*;[^;]*;[^;]*;[^;]*;($Alias|$Sid)\)"
    }

    # The app folder name an object path belongs to ("(Packages itself)" for the root).
    function Get-AppFolder([string]$ObjectName) {
        $rest = $ObjectName.Substring($PackagesPath.Length).TrimStart('\')
        if (-not $rest) { return '(Packages itself)' }
        $rest.Split('\')[0]
    }

    $filter = @{ LogName = 'Security'; Id = 4670, 4663 }
    if ($Hours -gt 0) { $filter.StartTime = (Get-Date).AddHours(-$Hours) }

    Out-Report 'Reading events 4670/4663 from the Security log...'
    $raw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
    Out-Report "  $($raw.Count) event(s) read$(if ($raw.Count -ge $MaxEvents) { ' (hit -MaxEvents limit; older ones not read)' })"

    $prefix = $PackagesPath.TrimEnd('\')
    $events = foreach ($e in $raw) {
        $f   = Get-EventFields $e
        $obj = [string]$f['ObjectName']
        if (-not ($obj -eq $prefix -or $obj.StartsWith("$prefix\", [StringComparison]::OrdinalIgnoreCase))) { continue }
        # 4663 is any access; keep only permission/owner changes.
        if ($e.Id -eq 4663 -and -not ((ConvertFrom-Hex $f['AccessMask']) -band ($WriteDac -bor $WriteOwner))) { continue }
        [pscustomobject]@{
            Time        = $e.TimeCreated
            Id          = $e.Id
            ProcessId   = ConvertFrom-Hex $f['ProcessId']
            ProcessName = [string]$f['ProcessName']
            Account     = '{0}\{1}' -f $f['SubjectDomainName'], $f['SubjectUserName']
            ObjectName  = $obj
            AppFolder   = Get-AppFolder $obj
            OldSd       = [string]$f['OldSd']
            NewSd       = [string]$f['NewSd']
        }
    }
    $events = @($events | Sort-Object Time)
    Out-Report "  $($events.Count) of them are permission/owner changes under Packages"

    # Group into bursts: same process (PID + name), no gap longer than $BurstGapMin minutes.
    $bursts = New-Object System.Collections.Generic.List[object]
    foreach ($group in ($events | Group-Object { "$($_.ProcessId)|$($_.ProcessName)" })) {
        $current = $null
        foreach ($ev in $group.Group) {
            if (-not $current -or ($ev.Time - $current.End).TotalMinutes -gt $BurstGapMin) {
                $current = [pscustomobject]@{
                    Start = $ev.Time; End = $ev.Time; ProcessId = $ev.ProcessId; ProcessName = $ev.ProcessName
                    Events = New-Object System.Collections.Generic.List[object]
                }
                $bursts.Add($current)
            }
            $current.End = $ev.Time
            $current.Events.Add($ev)
        }
    }

    # Work out what each burst did.
    foreach ($b in $bursts) {
        $removedSys = @(); $removedAdm = @()
        foreach ($ev in $b.Events | Where-Object { $_.Id -eq 4670 }) {
            if ((Test-SddlAllows $ev.OldSd 'SY' $SystemSid) -and -not (Test-SddlAllows $ev.NewSd 'SY' $SystemSid)) { $removedSys += $ev }
            if ((Test-SddlAllows $ev.OldSd 'BA' $AdminsSid) -and -not (Test-SddlAllows $ev.NewSd 'BA' $AdminsSid)) { $removedAdm += $ev }
        }
        $apps = @($b.Events | Select-Object -ExpandProperty AppFolder -Unique)
        $b | Add-Member -NotePropertyMembers @{
            RemovedSystem  = $removedSys
            RemovedAdmins  = $removedAdm
            AppFolders     = $apps
            BrokenTouched  = @($apps | Where-Object { $brokenNames.ContainsKey($_) })
            Accounts       = @($b.Events | Select-Object -ExpandProperty Account -Unique)
            Suspect        = ($removedSys.Count + $removedAdm.Count) -gt 0
        }
        # 4663 alone cannot show what changed; touching folders that are broken now is the next best clue.
        if (-not $b.Suspect -and $b.BrokenTouched.Count) { $b.Suspect = $true }
    }

    # --- Process chain via 4688 (process creation) events --------------------------

    $script:StartCache = @{}

    # Finds the 4688 event that created process $ProcessId (named $Name) at or before $Before.
    # PIDs are reused, so we take the newest matching creation before the reference time.
    function Find-ProcessStart([int64]$ProcessId, [string]$Name, [datetime]$Before) {
        $key = "$ProcessId"
        if (-not $script:StartCache.ContainsKey($key)) {
            $found = @()
            # Windows writes the PID as lowercase hex (0x1a2c); try uppercase too just in case.
            foreach ($hex in $(@(('0x{0:x}' -f $ProcessId), ('0x{0:X}' -f $ProcessId)) | Select-Object -Unique)) {
                $xp = "*[System[EventID=4688] and EventData[Data[@Name='NewProcessId']='$hex']]"
                $found += @(Get-WinEvent -LogName Security -FilterXPath $xp -ErrorAction SilentlyContinue)
                if ($found.Count) { break }
            }
            $script:StartCache[$key] = @(foreach ($e in $found) {
                $f = Get-EventFields $e
                [pscustomobject]@{
                    Time        = $e.TimeCreated
                    ProcessId   = $ProcessId
                    Name        = [string]$f['NewProcessName']
                    CommandLine = [string]$f['CommandLine']
                    Account     = '{0}\{1}' -f $f['SubjectDomainName'], $f['SubjectUserName']
                    ParentId    = ConvertFrom-Hex $f['ProcessId']
                    ParentName  = [string]$f['ParentProcessName']
                    Source      = 'event 4688'
                }
            })
        }
        $leaf = if ($Name) { Split-Path $Name -Leaf } else { '' }
        $script:StartCache[$key] |
            Where-Object { $_.Time -le $Before.AddSeconds(2) -and (-not $leaf -or (Split-Path $_.Name -Leaf) -eq $leaf) } |
            Sort-Object Time -Descending | Select-Object -First 1
    }

    # Fallback for processes started before auditing was on (e.g. a service running
    # since boot): if the same PID and name is still running, ask it directly.
    function Find-LiveProcess([int64]$ProcessId, [string]$Name, [datetime]$Before) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if (-not $p) { return $null }
        if ($Name -and $p.Name -ne (Split-Path $Name -Leaf)) { return $null }
        if ($p.CreationDate -and $p.CreationDate -gt $Before.AddSeconds(2)) { return $null }
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.ParentProcessId)" -ErrorAction SilentlyContinue
        $owner  = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Time        = $p.CreationDate
            ProcessId   = $ProcessId
            Name        = $(if ($p.ExecutablePath) { $p.ExecutablePath } else { $p.Name })
            CommandLine = [string]$p.CommandLine
            Account     = $(if ($owner -and $owner.User) { "$($owner.Domain)\$($owner.User)" } else { '' })
            ParentId    = [int64]$p.ParentProcessId
            ParentName  = $(if ($parent) { $parent.Name } else { '' })
            Source      = 'still running'
        }
    }

    # Walks up from the process that changed permissions to the oldest ancestor we can find.
    function Get-ProcessChain([int64]$ProcessId, [string]$Name, [datetime]$At) {
        $chain = @()
        $seen  = @{}
        for ($depth = 0; $depth -lt 15; $depth++) {
            $node = Find-ProcessStart $ProcessId $Name $At
            if (-not $node) { $node = Find-LiveProcess $ProcessId $Name $At }
            if (-not $node) {
                $chain += [pscustomobject]@{ ProcessId = $ProcessId; Name = $Name; Source = 'not found'; Time = $null; CommandLine = ''; Account = '' }
                break
            }
            $chain += $node
            $key = "$($node.ProcessId)|$($node.Time)"
            if ($seen.ContainsKey($key) -or $node.ParentId -le 4) { break }   # 0/4 = System/Idle: top reached
            $seen[$key] = $true
            $ProcessId = $node.ParentId; $Name = $node.ParentName
            if ($node.Time) { $At = $node.Time }
        }
        $chain
    }

    # Publisher of an executable, if the file still exists.
    function Get-Publisher([string]$Path) {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path
            if ($sig.SignerCertificate) {
                $cn = if ($sig.SignerCertificate.Subject -match 'CN="?([^",]+)') { $Matches[1] } else { $sig.SignerCertificate.Subject }
                return "signed by $cn ($($sig.Status))"
            }
            $company = (Get-Item -LiteralPath $Path).VersionInfo.CompanyName
            return "unsigned$(if ($company) { ", company: $company" })"
        } catch { return '' }
    }

    # Standard Windows processes that start other programs. With process-creation
    # auditing on, every chain runs back to smss.exe, so these are skipped when
    # picking the headline: the answer is the highest process BELOW them.
    $Launchers = 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'userinit.exe', 'services.exe',
                 'svchost.exe', 'explorer.exe', 'taskhostw.exe', 'taskeng.exe', 'wmiprvse.exe', 'sihost.exe'

    function Get-LeafName($Node) { if ($Node.Name) { (Split-Path $Node.Name -Leaf).ToLower() } else { '' } }

    # Index in the chain of the "real answer": walking up from the process that
    # changed permissions, the last one before the first Windows launcher.
    function Get-HeadlineIndex($Chain) {
        for ($i = 1; $i -lt $Chain.Count; $i++) {
            if ($Launchers -contains (Get-LeafName $Chain[$i])) { return $i - 1 }
        }
        return $Chain.Count - 1
    }

    # Plain-English hint based on the launcher that started the headline process.
    function Get-LauncherHint($Launcher) {
        if (-not $Launcher) { return '' }
        $name = Get-LeafName $Launcher
        if (($name -eq 'svchost.exe' -and $Launcher.CommandLine -match '-s\s+Schedule') -or $name -in 'taskhostw.exe', 'taskeng.exe') {
            return 'Started by a SCHEDULED TASK (Task Scheduler). Check Task Scheduler for tasks that ran at this time.'
        }
        switch ($name) {
            'services.exe' { return 'Started as a WINDOWS SERVICE (by services.exe).' }
            'svchost.exe'  { return "Started by a Windows service host (svchost.exe$(if ($Launcher.CommandLine) { ": $($Launcher.CommandLine)" }))." }
            'explorer.exe' { return 'Started from your desktop session (explorer.exe) - a program you or a startup entry launched.' }
            'wmiprvse.exe' { return 'Started via WMI (wmiprvse.exe) - often management/remote tools or WMI event subscriptions.' }
        }
        return "Started by $name."
    }

    function Out-Burst($b, [switch]$Detailed) {
        $what = @()
        if ($b.RemovedSystem.Count) { $what += "removed SYSTEM on $($b.RemovedSystem.Count) object(s)" }
        if ($b.RemovedAdmins.Count) { $what += "removed Administrators on $($b.RemovedAdmins.Count) object(s)" }
        if ($b.BrokenTouched.Count) { $what += "touched $($b.BrokenTouched.Count) folder(s) that are broken now" }
        if (-not $what) { $what += 'no SYSTEM/Administrators removal seen' }
        $color = if ($b.Suspect) { 'Red' } else { '' }

        Out-Report ''
        Out-Report ("{0:yyyy-MM-dd HH:mm:ss} -> {1:HH:mm:ss}  {2} (PID {3})" -f $b.Start, $b.End, $b.ProcessName, $b.ProcessId) $color
        Out-Report ("  {0} event(s) on {1} app folder(s), as {2}" -f $b.Events.Count, $b.AppFolders.Count, ($b.Accounts -join ', '))
        Out-Report "  Result: $($what -join '; ')" $color
        if (-not $Detailed) { return }

        $chain    = @(Get-ProcessChain $b.ProcessId $b.ProcessName $b.Start)
        $topIndex = Get-HeadlineIndex $chain
        $top      = $chain[$topIndex]
        $launcher = if ($topIndex + 1 -lt $chain.Count) { $chain[$topIndex + 1] } else { $null }
        Out-Report ''
        Out-Report "  >>> WHAT DID IT: $($top.Name) (PID $($top.ProcessId))  $(Get-Publisher $top.Name)" 'Magenta'
        if ($top.Source -eq 'not found') {
            Out-Report '      (its start was not in the log - it started before auditing was on, or the log has rolled over)'
        }
        $hint = Get-LauncherHint $launcher
        if ($hint) { Out-Report "      $hint" 'Magenta' }

        Out-Report ''
        Out-Report '  Process chain (the process that changed permissions first, then its parents):'
        for ($i = 0; $i -lt $chain.Count; $i++) {
            $n = $chain[$i]
            $indent = '    ' + ('  ' * $i) + $(if ($i) { '^ ' } else { '' })
            $started = if ($n.Time) { "started $($n.Time.ToString('yyyy-MM-dd HH:mm:ss'))" } else { 'start unknown' }
            Out-Report "$indent$($n.Name)  (PID $($n.ProcessId), $started, $($n.Source))"
            if ($n.Account)     { Out-Report "$indent  user: $($n.Account)" }
            if ($n.CommandLine) { Out-Report "$indent  cmd:  $($n.CommandLine)" }
            $pub = Get-Publisher $n.Name
            if ($pub)           { Out-Report "$indent  file: $pub" }
            if ($n.Source -eq 'still running') {
                $svcs = @(Get-CimInstance Win32_Service -Filter "ProcessId = $($n.ProcessId)" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
                if ($svcs.Count) { Out-Report "$indent  services in this process: $($svcs -join ', ')" }
            }
        }

        Out-Report ''
        $list = ($b.AppFolders | Select-Object -First 15) -join ', '
        if ($b.AppFolders.Count -gt 15) { $list += ', ...' }
        Out-Report "  App folders touched ($($b.AppFolders.Count)): $list"
        $example = if ($b.RemovedSystem.Count) { $b.RemovedSystem[0] } else { $b.Events | Where-Object { $_.Id -eq 4670 } | Select-Object -First 1 }
        if ($example) {
            Out-Report "  Example change on $($example.ObjectName):"
            Out-Report "    before: $($example.OldSd)"
            Out-Report "    after:  $($example.NewSd)"
        }
    }

    if (-not $bursts.Count) {
        Out-Report ''
        Out-Report 'No permission changes under Packages were found in the Security log.' 'Yellow'
        Out-Report 'If folders are broken anyway, the change happened before auditing was on, or the log rolled over.'
    } else {
        $suspects = @($bursts | Where-Object { $_.Suspect } | Sort-Object Start -Descending)
        $others   = @($bursts | Where-Object { -not $_.Suspect } | Sort-Object Start -Descending)

        if ($suspects.Count) {
            Out-Report ''
            Out-Report "$($suspects.Count) burst(s) removed SYSTEM/Administrators or touched broken folders (newest first):" 'Red'
            $n = 0
            foreach ($b in $suspects) {
                $n++
                Out-Report ('-' * 78)
                Out-Burst $b -Detailed:($n -le 10)   # full process chain for the 10 newest
            }
        } else {
            Out-Report ''
            Out-Report 'No burst removed SYSTEM/Administrators.' 'Green'
        }

        if ($others.Count) {
            Out-Heading "Other permission changes under Packages (probably normal, e.g. app installs/updates) - $($others.Count) burst(s)"
            foreach ($b in ($others | Select-Object -First 20)) { Out-Burst $b }
            if ($others.Count -gt 20) { Out-Report "  ...and $($others.Count - 20) older burst(s) not shown." }
        }
    }
}

if ($isAdmin) {
    Show-AuditSettings
    Show-PermissionChanges
} else {
    Out-Report ''
    Out-Report 'Not elevated: skipping the Security log. Re-run from a "Run as administrator" PowerShell to see WHO changed the permissions.' 'Yellow'
}

# --- Save the report -------------------------------------------------------------

try {
    if (-not $isAdmin) { $ReportDir = $env:TEMP }   # ProgramData\PermissionTrap is admin-only
    if (-not (Test-Path -LiteralPath $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
    $reportFile = Join-Path $ReportDir ("PermissionReport_{0:yyyy-MM-dd_HH-mm-ss}.txt" -f (Get-Date))
    $script:Lines | Set-Content -LiteralPath $reportFile -Encoding UTF8
    Write-Host ''
    Write-Host "Report saved to: $reportFile" -ForegroundColor Green
    Write-Host "Paste it with:   Get-Content '$reportFile' | Set-Clipboard"
} catch {
    Write-Host ''
    Write-Host "Could not save the report file: $($_.Exception.Message)" -ForegroundColor Yellow
}
