# v0.2 detailed plans

These files are the binding detail behind `docs/BUILD-PLAN.md` for the v0.2 release. Status
and the resume procedure are in [BUILD-PLAN.md § Release v0.2](../../BUILD-PLAN.md#release-v02-paused-2026-10-23).

| File | What it is |
|---|---|
| [approval-lifecycle-spec.md](approval-lifecycle-spec.md) | The approval-lifecycle build specification (work item 2): rulings §1, the state core §1.5 (SA-1 to SA-9), errata E1 to E75, per-lane file and test lists, and the frozen-test selectors. It is binding wherever `BUILD-PLAN.md` does not override it. |
| [wave3-lanes.md](wave3-lanes.md) | The lane plan for the rest of work item 2: base strategy, the dependency graph (§2), one contract per lane (§3: base, owned files, commits, tests, acceptance), and dated rulings made during the build, appended at the end. Read those rulings before resuming. |
| [wave3-gap-rulings.md](wave3-gap-rulings.md) | The 2026-10-22 sweep of the remaining lanes: 43 underdetermined rules with their rulings, the new lanes A1a-auth and B1f, the C2a–C2d split, DAG amendments, and the owner questions Q1–Q5 (Q1, Q2 and Q5 ruled; Q3 and Q4 open). |
| [phase-a-plan.md](phase-a-plan.md) | The earlier Phase A lane plan. Its §7 holds the prepared-legacy approval obligations that later lanes cite. |
| [store-recovery-model.md](store-recovery-model.md) | Who owns v2 store recovery: one approval runtime owns generations; a failed generation is joined before the store reopens. |
| [a10-audit-model.md](a10-audit-model.md) | Hosted audit delivery: one process-lifetime blocking stderr writer, framing and acknowledgement rules, the migration-8 legacy-expiry outbox, and what commit 7 must still wire. |
| [c4-install-model.md](c4-install-model.md) | How the executor's `systemd --user` install and uninstall scripts find the unit directory, and what they refuse. |
| [journey-e2e-plan.md](journey-e2e-plan.md) | The real-use journey test: a fake Telegram Bot API taps approve and deny, and the job runs in CI. |
| [read-jail-p5-plan.md](read-jail-p5-plan.md) | #22 Phase 5 plan v3: provisioning, capability reporting and docs. Parked on owner questions O1–O5 and two major critique findings, both listed at its top. |
| [read-jail-p6-p7-plan.md](read-jail-p6-p7-plan.md) | #22 Phases 6–7 plan v3: the full matrix and fidelity, then turning the label on. Reviewed GO; depends on Phase 5. |

Some references point to internal working notes and review records that are not in the
repository. Each ruling they support is restated in these files.
