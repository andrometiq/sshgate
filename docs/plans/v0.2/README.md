# v0.2 detailed plans

These files are the binding detail behind `docs/BUILD-PLAN.md` for the v0.2 release. Status
and the resume procedure are in [BUILD-PLAN.md § Release v0.2](../../BUILD-PLAN.md#release-v02-paused-2026-10-20).

| File | What it is |
|---|---|
| [approval-lifecycle-spec.md](approval-lifecycle-spec.md) | The approval-lifecycle build specification (work item 2): rulings §1, the state core §1.5 (SA-1 to SA-9), errata E1 to E75, per-lane file and test lists, and the frozen-test selectors. It is binding wherever `BUILD-PLAN.md` does not override it. |
| [wave3-lanes.md](wave3-lanes.md) | The lane plan for the rest of work item 2: base strategy, the dependency graph (§2), one contract per lane (§3: base, owned files, commits, tests, acceptance), and dated rulings made during the build, appended at the end. Read those rulings before resuming. |
| [phase-a-plan.md](phase-a-plan.md) | The earlier Phase A lane plan. Its §7 holds the prepared-legacy approval obligations that later lanes cite. |
| [store-recovery-model.md](store-recovery-model.md) | Who owns v2 store recovery: one approval runtime owns generations; a failed generation is joined before the store reopens. |
| [a10-audit-model.md](a10-audit-model.md) | Hosted audit delivery: one process-lifetime blocking stderr writer, framing and acknowledgement rules, the migration-8 legacy-expiry outbox, and what commit 7 must still wire. |
| [c4-install-model.md](c4-install-model.md) | How the executor's `systemd --user` install and uninstall scripts find the unit directory, and what they refuse. |
| [journey-e2e-plan.md](journey-e2e-plan.md) | The real-use journey test: a fake Telegram Bot API taps approve and deny, and the job runs in CI. |

Some references point to working notes and review records under `local-notes/` or
`local-workspace/`. Those are not in the repository. Each ruling they support is restated in
these files.
