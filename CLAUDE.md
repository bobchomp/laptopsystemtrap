# Notes for Claude

## Branches: keep `main` up to date automatically

`main` is the default branch and what the owner downloads (Code → Download ZIP)
to run on the laptop. After making changes, without being asked:

1. Commit and push to the working branch.
2. Wait for the **Test parts 1 and 2 + weekly check** workflow
   (`.github/workflows/test-part1.yml`) to pass on that commit, and read the
   log to check that the new or changed checks actually ran.
3. Fast-forward `main` to that commit (`git push origin <sha>:refs/heads/main`).
   If `main` cannot fast-forward, stop and ask.
4. Tell the owner it is on `main`.

Never put untested script changes on `main`: if CI fails, fix it first.
Changes that touch no script, test or workflow (e.g. README only) do not
trigger CI and can go to `main` straight away.
