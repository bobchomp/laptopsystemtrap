# Permission Trap

Something on this laptop keeps removing `SYSTEM` and `Administrators` from
`%LOCALAPPDATA%\Packages`, which stops Store apps (Claude, eM Client…) from
starting. Permission Trap finds out what's doing it, repairs the damage, and
emails you about it.

| Part | What it gives you | Scripts |
|---|---|---|
| **1. Catch it** | Windows auditing, and a report that names the program that changed the permissions | `Enable-Auditing.ps1`, `Get-PermissionReport.ps1`, `Disable-Auditing.ps1` |
| **2. Repair it** | A scheduled task (as SYSTEM) that puts the permissions back automatically | `Install-RepairTask.ps1`, `Uninstall-RepairTask.ps1` |
| **3. Hear about it** | An email every Sunday, plus a check at every logon that emails you straight away if anything is broken | `Install-WeeklyCheck.ps1`, `Set-WeeklyCheckApiKey.ps1`, `Uninstall-WeeklyCheck.ps1` |

`Repair-Permissions.ps1` and `Invoke-WeeklyCheck.ps1` are what the two scheduled
tasks run; you don't run them yourself.

## Before you start

1. **Get the files.** On https://github.com/bobchomp/laptopsystemtrap click
   **Code → Download ZIP** and extract it to a folder, e.g. `C:\PermissionTrap`.
   To update later, download again and extract over the same folder.
2. **Open PowerShell as administrator, as yourself.** Start → type *PowerShell* →
   right-click **Windows PowerShell** → **Run as administrator** → **Yes**. If
   Windows asks for another account's password, cancel: the scripts use *your*
   `%LOCALAPPDATA%`, so they must run as you (`whoami` should show your account).
3. **Go to the folder:** `cd C:\PermissionTrap`

Every command below is run from that window. Each script is started with
`powershell -ExecutionPolicy Bypass -File`, so you don't need to change
Windows' script policy.

## Quick start

```powershell
# 1. Turn on auditing (once)
powershell -ExecutionPolicy Bypass -File .\Enable-Auditing.ps1

# 2. When an app breaks: find out what did it - BEFORE repairing anything
powershell -ExecutionPolicy Bypass -File .\Get-PermissionReport.ps1

# 3. Repair automatically from now on
powershell -ExecutionPolicy Bypass -File .\Install-RepairTask.ps1 -WithAuditTrigger

# 4. Weekly email (asks for your Resend API key - paste it with a RIGHT-CLICK)
powershell -ExecutionPolicy Bypass -File .\Install-WeeklyCheck.ps1
```

Do step 3 after you've run the report at least once. Once the task fixes a
folder, the report no longer lists it as broken, although the audit events still
name the program that changed it.

## Part 1 — catch it

### `Enable-Auditing.ps1`
Turns on the auditing that records who changes permissions under Packages:
- backs up the current audit policy first, so it can all be undone
- enables **File System**, **Authorization Policy Change** and **Process
  Creation** auditing (success only), with command lines in process events
- raises the Security log to 128 MB, so evidence isn't overwritten (it never
  lowers it)
- adds an audit rule to the Packages folder that logs permission and ownership
  changes; the folders' actual permissions are not touched (the script checks)

Safe to run again. At the end, all three categories should show **Success**.

### `Get-PermissionReport.ps1`
Run it when an app breaks. It changes nothing.
- **Part 1:** folders missing SYSTEM or Administrators (works without admin).
- **Part 2:** whether auditing is still on, and how far back the log goes.
- **Part 3:** which processes changed permissions under Packages. Changes that
  removed SYSTEM/Administrators, or touched folders that are broken now, come
  first. For each one it shows:
  - **`>>> WHAT DID IT:`** — the program responsible: the highest process in
    the chain below Windows' own launchers (services, Task Scheduler, Explorer…),
    with its publisher, and a hint such as *started by a scheduled task*
  - the full chain of parent processes with their command lines
  - the permissions before and after

The report is saved in `C:\ProgramData\PermissionTrap\reports\`. The last lines
print the command that copies it to the clipboard, so you can paste it.

Options: `-Hours 48` looks only at recent events; `-MaxEvents` limits how many
are read.

Only changes made **after** you ran `Enable-Auditing.ps1` can be traced. A
process that started before that shows as *start not in the log*; if it's still
running, the report reads its details from the live process instead.

### `Disable-Auditing.ps1`
Puts back everything Enable changed: the audit rule, the audit policy, the
command-line setting and the log size. Events already logged are kept.

## Part 2 — repair it

### `Install-RepairTask.ps1 [-WithAuditTrigger]`
Registers the **PermissionTrap-Repair** task. It runs as SYSTEM at every logon,
and with `-WithAuditTrigger` also 30 seconds after any permission change is
logged (needs Part 1's auditing).

Each run:
- finds folders missing SYSTEM or Administrators
- backs up their permissions to `backups\<time>\<folder>.acl`
- **adds** the missing entries — it never removes, resets or changes inheritance
- writes each fix to `repair.log`
- checks again 30 seconds later, in case the culprit is still working

```powershell
Start-ScheduledTask -TaskName PermissionTrap-Repair                     # repair now
Get-Content C:\ProgramData\PermissionTrap\repair.log -Tail 20           # what it fixed
```

To undo one repair from its backup:
`icacls "%LOCALAPPDATA%\Packages" /restore "C:\ProgramData\PermissionTrap\backups\<time>\<folder>.acl"`

### `Uninstall-RepairTask.ps1 [-RemoveLogsAndBackups]`
Removes the task. Repaired permissions stay as they are. `repair.log` and the
backups are kept unless you add `-RemoveLogsAndBackups`.

## Part 3 — hear about it

### `Install-WeeklyCheck.ps1`
Registers the **PermissionTrap-WeeklyCheck** task and stores your Resend API key.

| When | What it emails |
|---|---|
| **Sunday 18:00** (local time, all year) | Always: either the broken folders, or *"all clear (N weeks in a row)"* |
| **Every logon** (2 minutes after you sign in) | Only if something is broken. An all-clear is just logged. |
| **First logon after a missed Sunday** (laptop was off) | Does the Sunday email instead |

- Emails go **from** `info@rossmackenzie.co.uk` **to** `teddaharry@gmail.com`
  (change with `-From` / `-To` when installing).
- A problems email lists each folder and what it's missing, and tells you to
  run `Get-PermissionReport.ps1` as administrator.
- Finding a problem resets the *weeks in a row* count.
- If an email can't be sent, that Sunday doesn't count and the next logon tries again.
- The task runs as **you, not elevated**, and only while you're logged on: the
  key is encrypted for your account and can only be unlocked while you're
  signed in. You may see a window flash briefly when it runs.

**Paste the API key with a right-click.** In Windows PowerShell, Ctrl+V doesn't
work in the hidden prompt — it types an invisible `^V`, which the scripts refuse.
The key is stored encrypted for your Windows account only, and never shown or
saved in plain text.

### Everyday commands

```powershell
# Run the check now (counts as the Sunday check if this week's hasn't happened yet)
Start-ScheduledTask -TaskName PermissionTrap-WeeklyCheck

# See what it did
Get-Content C:\ProgramData\PermissionTrap\weekly.log -Tail 10

# Change the API key - or press Enter at the prompt to keep it - and send a test email
powershell -ExecutionPolicy Bypass -File .\Set-WeeklyCheckApiKey.ps1
```

`Set-WeeklyCheckApiKey.ps1` checks and stores the key, then sends a
*"Permission Trap: test email"* to prove it works. The test doesn't affect the
weekly schedule or the weeks-in-a-row count. No reinstall needed.

### Reading `weekly.log`

| Line starts with | Meaning |
|---|---|
| `WEEKLY CLEAR` | Sunday check, all fine, all-clear email sent |
| `WEEKLY PROBLEMS` | Sunday check found broken folders, email sent |
| `LOGON  CLEAR … not sent` | Logon check, all fine, no email (by design) |
| `LOGON  PROBLEMS` | Logon check found broken folders, email sent |
| `TEST` | Test email from `Set-WeeklyCheckApiKey.ps1` |
| `ERROR` | Something failed — the rest of the line says what (see below) |

### `Uninstall-WeeklyCheck.ps1 [-RemoveLogs]`
Removes the task, its settings and the stored key. `weekly.log` and the
weeks-in-a-row count are kept unless you add `-RemoveLogs`.

## Undo everything

```powershell
powershell -ExecutionPolicy Bypass -File .\Uninstall-WeeklyCheck.ps1
powershell -ExecutionPolicy Bypass -File .\Uninstall-RepairTask.ps1
powershell -ExecutionPolicy Bypass -File .\Disable-Auditing.ps1
```

## Troubleshooting

| You see | Cause and fix |
|---|---|
| *"…contains a #requires statement for running as Administrator"* | The window isn't elevated. Open PowerShell with **Run as administrator**. |
| *"Folder not found: …\Packages"* | The window is running as a different account. Check `whoami`; the scripts must run as you. |
| *"running scripts is disabled on this system"* | Start the script with `powershell -ExecutionPolicy Bypass -File .\<script>.ps1`. |
| Report: *"No permission changes … were found"* | The break happened before auditing was turned on, or the log has rolled over. Only later breaks can be traced. |
| `weekly.log`: *"stored Resend API key contains invisible control characters"* | The key was pasted with Ctrl+V. Run `Set-WeeklyCheckApiKey.ps1` and paste with a **right-click**. |
| `weekly.log`: *"Resend refused the email (HTTP …)"* | Resend rejected it; the message says why — usually a wrong key (`401`/`403`) or the sender domain not verified in Resend. |
| `weekly.log`: *"Could not reach Resend"* | No internet at the time. A Sunday check is retried at the next logon. |

## Files

Everything lives in `C:\ProgramData\PermissionTrap\`. Only SYSTEM and
Administrators can change it; Users can read it. The exceptions are
`weekly.log` and `weekly-state.json`, which your account can write (the weekly
task runs unelevated), and `weekly-resend.key`, which only you, SYSTEM and
Administrators can read.

| File | What it is |
|---|---|
| `auditpol-backup.csv`, `audit-state.json` | The settings as they were before `Enable-Auditing.ps1`, for undoing it |
| `reports\PermissionReport_<time>.txt` | Each report (in `%TEMP%` if you ran it without admin) |
| `Repair-Permissions.ps1` | The copy the repair task runs |
| `repair.log`, `backups\<time>\<folder>.acl` | Every repair, and the permissions from before it |
| `Invoke-WeeklyCheck.ps1`, `weekly-config.json` | The copy the weekly task runs, and its sender/recipient |
| `weekly-resend.key` | The Resend API key, encrypted for your account |
| `weekly.log`, `weekly-state.json` | One line per weekly/logon check, and the weeks-in-a-row count |

`repair.log` and `weekly.log` roll over to `.log.1` at 5 MB.

## Tests

`.github/workflows/test-part1.yml` runs every part end to end on a Windows
machine on each push: auditing and the report, the SYSTEM repair task
(on demand and from the audit event), the weekly/logon emails, changing the
API key, and every uninstaller. It never sends a real email — the weekly
check is installed in test mode (`-OutboxPath`), which writes each email to a
file instead. The reports, logs and test emails are uploaded as the
`test-results` download on each run.
