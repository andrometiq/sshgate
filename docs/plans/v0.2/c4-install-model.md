# C4 executor install/uninstall — one-page model (step-back, 2026-10-18)

## Why this page exists
Four the reviewer reviews (C4, C4-2, C4-3, C4-4) each found new systemd edge cases. Round 3 used a
narrowed ruling (one owned directory); C4-4 still found four P2s. Stop-patch-loop: re-ask the
shape and scale the bar to the real threat.

## Real threat / users
- One operator installs SSHGate's executor as a systemd --user service on their own Linux
  machine, from the README. Re-runs install to upgrade; runs uninstall to remove.
- The unit name `sshgate-executor.service` is SSHGate's. Nothing else legitimately ships a unit
  with that name. "Foreign unit with our exact name" means a previous SSHGate install (another
  checkout or XDG root) — the operator's own state, not an adversary.
- No trust boundary is crossed: the scripts run as the operator, against the operator's own
  user manager. The worst realistic failure is a confusing half-state; the executor's security
  properties come from the unit's hardening and the gate, not from the install script.

## What we actually need (acceptance)
1. Install writes the unit where the operator's user manager loads it, enables it, and starts or
   restarts it (restart when the unit changed or `--restart`; marker survives failure → retry).
2. Upgrade (re-run) restarts onto the new binary/unit.
3. Uninstall leaves no running executor and no enablement, and keeps binary + job records.
4. Clear refusal, before writing, when the manager would load the unit from somewhere else
   (another SSHGate install), naming that path — the operator removes it and re-runs.
5. Works when the unit file was deleted by hand before uninstall.

## Proposed shape (v2)
- Directory: the manager's persistent config root. Honour `XDG_CONFIG_HOME` only if it matches
  the manager's (`systemctl --user show-environment`); otherwise refuse with one clear line.
  This makes "load dir == enablement dir" true by construction (C4-4 #4).
- Install: as now (symlink/foreign-fragment refusal before writing, marker, reload, `-ef`
  verification with rollback, `enable`, start/restart).
- Uninstall: `daemon-reload` first (fresh state, C4-4 #3); refuse if the loaded fragment is a
  path other than ours (C4-4 #1); then `disable --now` (tolerant only of not-found), remove our
  file + marker, `daemon-reload`, `reset-failed`. We accept systemd's own `disable` semantics for
  links named `sshgate-executor.service` (C4-4 #2): that name is ours; docs say so instead of
  promising to preserve foreign links of the same name.
- Mock: model reload caching (state changes only on reload) and name-based disable.

## Out of scope (documented, not coded)
Units of our name from other packages; aliases; system-wide (`/etc`, `/usr/lib`) user units;
XDG roots that differ from the manager's.

## Final ruling (2026-10-18, after independent review + fresh second-review step-back reads, both ADOPT-WITH-CHANGES)
Threat model and "the name is ours" stance adopted. v2 amended:
1. **Unit directory from the manager:** take `systemctl --user show -p UnitPath --value`, find the
   leading persistent `<root>/systemd/user.control` entry, strip `.control` → `<root>/systemd/user`.
   Refuse (one clear line) if no such entry. `XDG_CONFIG_HOME` no longer chooses the unit
   directory; the unit's `Environment=XDG_CONFIG_HOME` data root stays as before.
2. **`daemon-reload` before the conflict preflight in both scripts.**
3. **Upgrade = re-run install:** every successful install ends with `restart` (starts if stopped).
   Drop `--restart` and the restart marker (nothing left to remember across failures).
   Keep post-write `-ef` verification with rollback.
4. **Uninstall:** reload → refuse if `FragmentPath` is non-empty and not ours (path compare after
   normalisation, since the file may be gone) → `stop` with confirmed absence → `disable`
   (tolerate failure) → remove our known enablement link(s) in the verified directory
   (`<dir>/*.target.wants/sshgate-executor.service` whose target normalises to our unit) →
   remove unit → reload → `reset-failed sshgate-executor.service || true`.
5. **Evidence:** one disposable real-systemd lifecycle smoke (privileged container with systemd
   as PID 1 and a user manager, opt-in like the journey rig): install, re-install (restart seen),
   uninstall, install → delete unit by hand → uninstall, conflict refusal. The Go mock keeps only
   argument/flow tests; it is not expanded.

### Ruling 2026-10-19 — UnitPath parsing (after the reviewer C4-5 and C4-6)
systemd double-quotes UnitPath entries that contain spaces. It backslash-escapes the other special characters it encodes (quotes, backslashes, `$`, backticks, newlines). The scripts decode only the double-quote wrapping, using xargs, with its exit status checked. They refuse any value containing a backslash or a single quote with an explicit "unit path" error. A general decoder for systemd's escaping is out of scale for an operator-run, same-user install. Basis: the threat model above and the stop-patch-loop rule. The flow test covers spaces, refusals, an xargs failure and a partial parse, and each case is mutation-checked.
