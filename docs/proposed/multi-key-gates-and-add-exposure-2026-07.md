# Multi-key gates + provisioning exposure window (owner direction, 2026-07)

**Status: captured direction — NOT scheduled, NOT designed, NOT to be built yet.**
This document records the owner's verbatim-intent direction (2026-07-03) for two
related provisioning features, plus one decision that **rejects and supersedes**
the old roadmap item #17 ("in-place Tier-1 → Tier-2 upgrade"). When this work is
picked up, it goes through the full pipeline (research → design proposals →
adversarial critique → build); nothing here is a spec yet. Sections marked
*[design note]* are implementation observations added at capture time, kept
separate from the owner's points.

---

## 1. Decision: no in-place tier upgrade — read-only is read-only

The previously-planned "in-place Tier-1 → Tier-2 upgrade" is **rejected**.

Rationale (owner's): any upgrade path that lets the CLI flip a read-only gate to
writable without a signed operation is a path **the agent can emulate** — the
CLI runs on the same machine, as the same user, with the same dedicated key the
agent's MCP uses. If the gate would accept an unsigned "now accept writes"
change over that channel from a human, it would accept the same bytes from a
compromised agent. That is a complete failure of the tier boundary, so:

- **If a gate is read-only, it is read-only.** There is absolutely no way to
  make write changes using that key. UX is not a factor in this decision.
- Changing a box's tier remains what it is today: the operator's own
  out-of-band admin access + re-provisioning at the desired tier.

## 2. Feature A — multiple keys per gate (per-agent identity)

**The certain requirement: multiple signer keys must be installable for a
gate.** This is the whole motivation: each agent gets its **own private key**
and deploys its **own public key**; no agent has to trust another agent's key.
A shared key makes the trust story complicated — per-agent keys keep it clean.

Owner's points, verbatim intent:

- **Version-aware `sshgate add`.** When `add` runs against a host that already
  has a gate installed, it must compare gate versions and take a call:
  - installed version **lower** than ours → upgrade it in place, push the newer
    gate, and notify the user that an upgraded gate has been installed;
  - installed version **higher** than ours → leave it as-is and notify the user
    that a higher-version gate is installed there.
- **One gate vs multiple gates — open question, delegated.** First instinct:
  one gate binary per host, multiple keys for it. On second thought: why only
  one? Anybody could have their own gate changes and deploy their own gate
  binary along with their key. The decision (single shared gate binary vs
  per-user gate binaries) is delegated to the design phase — work out the best
  mechanism and report back.
- **Per-key tier.** For a given gate/key: if a signer public key is present for
  it → signed-write; if there is no key for that particular gate → read-only.
- **Possible layout sketch** (owner's, if multiple gates): per-user folders
  under the remote `~/.sshgate`-style directory, keyed by a unique username.
  Needs a deduplication story: what happens when two people or two agents with
  the same name try to install their own gate — how to detect and resolve.
- **Signer topology — open.** Both shapes must be considered: a **single
  approval server** that approves all write requests across keys, or **each
  agent with its own independent signing mechanism**. The person who holds the
  main admin SSH access to the box decides which keys/gates get installed
  anyway, so that decision naturally sits with them.

*[design note]* The version comparison interacts with the verified release
channel (update-verb spec §11): "upgrade if lower" must not become a downgrade
or unverified-binary vector — the artifact `add` pushes should be the published,
CI-verified gate, and version claims read from a remote gate are unauthenticated
input. To resolve in design.

*[design note]* Multi-key also touches: `authorized_keys` holding several
forced-command lines (one per dedicated key), the registry schema (one alias,
several identities?), host-key binding, and revoke semantics (revoke one
agent's key vs the whole gate). To resolve in design.

## 3. Feature B — `sshgate add` flow: shrink the plain-key exposure window

Today's flow (paste the plain key line by hand, then run `sshgate add`, which
eventually rewrites it into the forced-command line) leaves an **ungated plain
key line live on the server** for the whole gap between the paste and the
rewrite.

Owner's desired flow — invert the order and make the gap milliseconds:

1. The operator runs `sshgate add` **first**. It advises the operator what to
   do next.
2. The operator separately SSHes into the server **on their own terminal**
   (their own admin access) and pastes the key line.
3. Meanwhile `add` keeps **retrying** SSH with the dedicated key. The moment
   the pasted line lands and saves, the next retry catches it, and `add`
   immediately installs the gate and swaps the plain line for the restricted
   forced-command line.
4. The exposure window shrinks to the slim gap between "line saved" and "next
   retry connects" — milliseconds to seconds.

Constraints and options the owner named:

- **Absolute-security path must remain available:** the operator can copy the
  gate over and install everything entirely by hand, eliminating even that
  milliseconds gap — for hosts where they have reason to want it.
- **Retry cadence:** as short as possible **without the server blocking us**
  (sshd rate limits, fail2ban and the like) — minimizing the window within
  that constraint. Also explore whether other strategies (beyond fast retry
  and beyond full manual install) can shrink the window further.
- **This is an explicit UX-vs-security trade, chosen per host:** for a host
  under low threat, the fast-retry flow's few seconds are acceptable; for a
  sensitive host, use the manual path. Both are legitimate; the operator picks.

## 4. Status

- Nothing here is scheduled. The owner will decide after the open design
  questions (single vs multiple gates, signer topology, dedup, retry strategy)
  are worked out and presented.
- Roadmap entry #17 now points here; the old in-place-upgrade wording is
  retired.
