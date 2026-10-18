# Permission Trap — part 1 (auditing + manual report)

Finds out what keeps removing `SYSTEM` and `Administrators` from
`%LOCALAPPDATA%\Packages`. Part 1 sets up Windows auditing and gives you a report
to run by hand. Nothing runs in the background, and nothing gets repaired.

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

## Files

`C:\ProgramData\PermissionTrap\` (SYSTEM and Administrators full control, Users read):

- `auditpol-backup.csv`: the audit policy as it was before you ran Enable
- `audit-state.json`: the other "before" values, and the folders that got the audit rule
- `reports\PermissionReport_<time>.txt`: each report run. If you run the report without elevation, it goes to `%TEMP%` instead.

## Typical use

1. Run `Enable-Auditing.ps1` once.
2. Optional check: run `Get-PermissionReport.ps1` right away. Part 2 should show the three subcategories as "Success" and the audit rule as present.
3. When an app breaks, run `Get-PermissionReport.ps1` before you repair anything, and send the report text.
4. To undo everything, run `Disable-Auditing.ps1`.

Only changes made **after** step 1 can be attributed. A process that started before
auditing was on shows up as "start not in the log". If it is still running, the
report reads its details from the live process instead.
