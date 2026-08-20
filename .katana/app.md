# Fixable app

## General

- fixable app is application written in aio framework (dep/aio) running as
  electron local client
- application is simple, yet capable, it list all issues that it can diagnose on
  computer from perspective of resource, security, settings, utilization,
  privacy, performance, etc.

## Checks

- the catalogue holds at least 2000 checks
- every check that can be fixed has a button; a check with no button is the
  exception and says why
- needing root is not a reason to have no button: a root fix may narrow a file
  mode or write a drop-in that belongs to the app, runs as one reviewed batch
  behind one password prompt, and is undoable
- a fix that takes something away — a preference, a capability in daily use, a
  policy spanning many programs — keeps its button but is filed as optional and
  is never run by a "fix all"
- a check has no button at all only when no safe change exists: it would stop
  something running, reconfigure hardware or a live service, delete data, or
  take away accessibility machinery
- every check that may not act unattended says so in one place, with its
  reason, checked against the catalogue so a rename cannot silently re-enable
  it
- adding a check is adding a data row, not writing code

## Ui

- it monitors what is to monitor and also provide "Scan" function that is more
  suitable for one-time checks
- the issue list has an "Auto" / "Sudo" / "Optional" / "Manual" / "All" switch,
  opens on "Auto", and each segment shows how many issues are behind it
- every check names exactly one category, and the ui shows it
- ui has some header where it reports find isuses (out of possible), severity
  (critical/major/minor), and buttons "Fix all" and "Fix all (sudo required)"
- "fix all (sudo required)" shows every command it will run before asking for
  the password, and asks once for the whole batch
- it reports all found issues orderd by significance (severity/priority) in this
  format for each item columns: 1) Issue description, 2) category, 3)
  priority, 4) "Fix" button, 5) explanation what will "Fix" do exactly

## Safety

- no fix issue can harm stability, data or user experience of the computer user
- nothing run as root may stop, restart, reconfigure or unload anything that is
  running; the app never edits a file it did not create, and never handles the
  password itself
