# Permission Trap

Finds out what keeps removing `SYSTEM` and `Administrators` from
`%LOCALAPPDATA%\Packages`, and puts them back.

- **Part 1:** sets up Windows auditing and gives you a report to run by hand.
- **Part 2:** adds a scheduled task that repairs the permissions automatically.
- **Weekly check:** checks every Sunday and at every logon. It emails you every Sunday, and straight away at logon if anything is broken.

Run all scripts from **your own account** in an **elevated** Windows PowerShell 5.1
("Run as administrator"). Each script uses `%LOCALAPPDATA%` to find the Packages
folder, so an elevated window opened by another admin account would point at the
wrong profile. To run a script without changing your execution policy:

```powershell
powershell -ExecutionPolicy Bypass -File .\Enable-Auditing.ps1
```

## Scripts

| Script | What it does |
|---|---|
| `Enable-Auditing.ps1` | Backs up the audit policy. Enables File System, Authorization Policy Change and Process Creation auditing (success only), with command lines in 4688 events. Raises the Security log to 128 MB (it never lowers it). Adds an audit rule (Everyone, ChangePermissions + TakeOwnership, inherited) to the Packages folder. Only the SACL is written; the script compares the DACL before and after to prove it was left alone. App folders that block inheritance get the rule added directly. It is safe to run again. |
| `Disable-Auditing.ps1` | Removes the audit rule from the folders that got it. Restores the audit policy from the backup, puts the command-line registry value back as it was, and sets the Security log back to its old size. Logged events are kept. |
| `Get-PermissionReport.ps1` | Run it when an app breaks. **Part 1** lists the folders that are missing SYSTEM or Administrators. **Part 2** checks that the auditing is still on and shows how far back the log goes. **Part 3** reads events 4670/4663 under Packages, groups them into bursts per process, and puts first the bursts that removed SYSTEM/Administrators or touched folders that are broken now. For each of those it walks the parent chain through 4688 events, with command lines, the publisher of each file and a hint (scheduled task / service / desktop). It changes nothing. Options: `-Hours 48` (only recent events), `-MaxEvents`. |

### Part 2 — automatic repair

| Script | What it does |
|---|---|
| `Install-RepairTask.ps1` | Registers the `PermissionTrap-Repair` scheduled task. It runs as SYSTEM with highest privileges at every logon. With `-WithAuditTrigger` it also runs 30 seconds after a permission-change audit event (4670); that needs `Enable-Auditing.ps1` to have been run. Your Packages path is worked out when you install and built into the task, because `%LOCALAPPDATA%` points at SYSTEM's own profile when running as SYSTEM. The repair script is copied into the admin-only `C:\ProgramData\PermissionTrap`, so nothing unelevated can change what SYSTEM runs. |
| `Repair-Permissions.ps1` | What the task runs. It finds folders with no SYSTEM or Administrators entry and backs up their permissions (`icacls /save`, into `backups\<time>\<folder>.acl`). Then it grants only the missing ones, `(OI)(CI)F`, recursively for app folders. It **only adds**: no `/reset`, no `/remove`, and it doesn't change inheritance or the owner. Each fix goes to `repair.log`. After a fix it checks again 30 s later, in case the culprit is still working. A run that finds nothing broken changes nothing and logs nothing, so its own permission changes can't make it loop. |
| `Uninstall-RepairTask.ps1` | Removes the task and the copied script. It keeps `repair.log` and the backups unless you pass `-RemoveLogsAndBackups`. Permissions it already repaired stay as they are. |

### Weekly check — Sunday email, plus a check at every logon

| Script | What it does |
|---|---|
| `Install-WeeklyCheck.ps1` | Registers `PermissionTrap-WeeklyCheck`. It runs as **you, not elevated**, every Sunday at 18:00 local time, and 2 minutes after every logon. It prompts for your Resend API key, with the input hidden, and stores it encrypted with DPAPI for your Windows account only (`weekly-resend.key`). The key is never written in plain text. Emails go from `info@rossmackenzie.co.uk` to `teddaharry@gmail.com`; change that with `-From` / `-To`. The installer needs an elevated window to write to `C:\ProgramData\PermissionTrap`, but run it from your own account. |
| `Invoke-WeeklyCheck.ps1` | What the task runs. It does the same check as part 1 of the report and logs each run to `weekly.log`. **Sunday check** (or the first logon after a missed Sunday): it always emails, either the affected folders with an instruction to run `Get-PermissionReport.ps1` elevated, or "all clear" with how many weeks in a row it's been clear. If sending fails, it tries again at your next logon. **Logon check**: it emails only if something is broken; an all-clear is just logged. Finding problems resets the clear-weeks count. |
| `Set-WeeklyCheckApiKey.ps1` | Changes the Resend API key without reinstalling. It prompts for the key (paste with a right-click) and checks it the same way the installer does. It stores the key encrypted, then sends you a test email to prove the key works. The test doesn't count as a weekly check. The installer uses this script to store the key too. |
| `Uninstall-WeeklyCheck.ps1` | Removes the task, its script and settings, and the stored API key. It keeps `weekly.log` and the clear-weeks count unless you pass `-RemoveLogs`. |

The task only runs while you're logged on: DPAPI can only decrypt your key while you're logged on.

**Pasting the key:** paste it with a **right-click**. In Windows PowerShell, Ctrl+V doesn't work in the hidden prompt: it types an invisible `^V` instead, which the installer now refuses. If `weekly.log` says the stored key contains invisible control characters, run `Set-WeeklyCheckApiKey.ps1` and paste with a right-click.

To restore a folder's permissions from a backup:
`icacls "%LOCALAPPDATA%\Packages" /restore "C:\ProgramData\PermissionTrap\backups\<time>\<folder>.acl"`

## Files

`C:\ProgramData\PermissionTrap\` (SYSTEM and Administrators full control, Users read):

- `auditpol-backup.csv`: the audit policy as it was before you ran Enable
- `audit-state.json`: the other "before" values, and the folders that got the audit rule
- `reports\PermissionReport_<time>.txt`: each report run. If you run the report without elevation, it goes to `%TEMP%` instead.
- `Repair-Permissions.ps1`: the copy the scheduled task runs
- `repair.log`: every fix the task made (kept as `repair.log.1` once it passes 5 MB)
- `backups\<time>\<folder>.acl`: each folder's permissions as they were before the task repaired it
- `Invoke-WeeklyCheck.ps1`, `weekly-config.json`: the weekly check and its settings (admin-only)
- `weekly-resend.key`: the Resend API key, DPAPI-encrypted for your account
- `weekly.log`, `weekly-state.json`: one line per weekly run, and the clear-weeks count

## Typical use

1. Run `Enable-Auditing.ps1` once.
2. Optional check: run `Get-PermissionReport.ps1` right away. Part 2 should show the three subcategories as "Success" and the audit rule as present.
3. When an app breaks, run `Get-PermissionReport.ps1` before you repair anything, and send the report text.
4. To repair automatically, run `Install-RepairTask.ps1 -WithAuditTrigger`. Do this after you've caught the culprit with the report: once the task fixes a folder, the report won't list it as broken any more, though the permission-change events still name the program.
5. For a weekly email, run `Install-WeeklyCheck.ps1`, then `Start-ScheduledTask -TaskName PermissionTrap-WeeklyCheck` to send the first one now.
6. To undo everything, run `Uninstall-WeeklyCheck.ps1`, `Uninstall-RepairTask.ps1`, then `Disable-Auditing.ps1`.

## Tests

`.github/workflows/test-part1.yml` runs parts 1 and 2 and the weekly check end to end on a Windows runner. For the weekly check it uses test mode (`-OutboxPath`), which writes each email to a file instead of sending it, and uploads the reports and logs as the `test-results` download.

Only changes made **after** step 1 can be attributed. A process that started before
auditing was on shows up as "start not in the log". If it is still running, the
report reads its details from the live process instead.
