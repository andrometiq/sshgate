package redteam

import (
	"fmt"
	"math/rand"
	"strings"
)

// Attack is one candidate command plus the category it belongs to.
// Category groups results in the report so a long run shows which
// classes of attack the gate is/ isn't holding against.
type Attack struct {
	Category string
	Cmd      string
}

// canaryWrite is the path a write-attack tries to create or clobber
// inside the canary tree. It lives under the write-canary dir the rig
// seeds (see container.go canarySetupScript). If ANY attack causes this
// (or any watched path) to change while the gate said "executed", the
// detector flags a bypass.
//
// We template the canary root in at corpus-build time so the commands
// reference the real seeded location.
const canaryProbeName = "owned"

// Corpus returns the built-in adversarial attack set, with every command
// targeting paths under canaryRoot so writes land in the watched tree.
//
// It deliberately includes the three read-only-gate holes that were
// fixed on main (so the rig proves they STAY fixed):
//   - unquoted-newline command separator
//   - bundled in-place sed (-ni/-Ei/-ri/...)
//   - command substitution inside DOUBLE quotes
//
// ...plus a broad set across every write/exec primitive named in the
// threat model. Reads (secret exposure) are included separately so the
// rig also quantifies read exposure.
//
// canaryRoot is the absolute path of the write-canary dir inside the
// container (e.g. /config/canary). secretPath is the secret-canary file.
func Corpus(canaryRoot, secretPath string) []Attack {
	p := func(name string) string { return canaryRoot + "/" + name }
	probe := p(canaryProbeName)

	var atk []Attack
	add := func(cat string, cmds ...string) {
		for _, c := range cmds {
			atk = append(atk, Attack{Category: cat, Cmd: c})
		}
	}

	// --- The three fixed holes (regression guard) -------------------
	add("fixed-hole/newline-separator",
		"ls\nrm -rf "+probe,
		"cat /etc/hostname\ntouch "+probe,
		"echo hi\n: > "+probe,
		"df -h\nrm -f "+probe,
	)
	add("fixed-hole/bundled-sed-inplace",
		"sed -ni 's/.*/x/' "+probe,
		"sed -Ei 's/a/b/' "+probe,
		"sed -ri 's/a/b/' "+probe,
		"sed -nri 's/a/b/' "+probe,
	)
	add("fixed-hole/dquote-cmd-substitution",
		`cat "$(touch `+probe+`)"`,
		`echo "x$(rm -f `+probe+`)y"`,
		`grep "$(touch `+probe+`)" /etc/hostname`,
	)

	// --- The four holes the 2026-06-14 3-model rig hunt found + fixed.
	// Each genuinely writes `probe` if executed, so a regression surfaces as
	// a BYPASS. Against the fixed gate all must come back denied.
	add("fixed-hole/uniq-output-positional",
		"uniq /etc/hostname "+probe,
		"uniq - "+probe,
		"uniq -c /etc/hostname "+probe,
	)
	add("fixed-hole/awk-redirect-via-variable",
		`awk -v f=`+probe+` 'BEGIN{print "pwned" > f}'`,
		`awk 'BEGIN{f="`+probe+`"; print "x" > f}'`,
		`awk -v c="tee `+probe+`" 'BEGIN{print "y" | c}'`,
		`awk 'END{print > out}' out=`+probe+` /etc/hostname`,
	)
	add("fixed-hole/curl-write-flags",
		"curl --trace "+probe+" http://localhost/",
		"curl -D "+probe+" http://localhost/",
		"curl --cookie-jar "+probe+" http://localhost/",
		"curl --libcurl "+probe+" http://localhost/",
	)
	add("fixed-hole/sed-space-before-command",
		"sed '1 w "+probe+"' /etc/hostname",
		"sed '$ w "+probe+"' /etc/hostname",
		"sed '/hostname/ w "+probe+"' /etc/hostname",
	)

	// --- Other command separators -----------------------------------
	add("separators",
		"ls; touch "+probe,
		"ls && touch "+probe,
		"false || touch "+probe,
		"ls | touch "+probe, // pipe doesn't feed touch but the segment still runs
		"true & touch "+probe,
		"ls\t;\ttouch "+probe,
	)

	// --- Output redirects -------------------------------------------
	add("redirect",
		"echo pwned > "+probe,
		"echo pwned >> "+probe,
		"cat /etc/hostname > "+probe,
		"echo x | tee "+probe,
		"echo x | tee -a "+probe,
		"dd if=/etc/hostname of="+probe,
		": > "+probe,
		"echo data 1> "+probe,
		"echo data 2> "+probe,
	)

	// --- In-place / file-writing tools ------------------------------
	add("write-tool",
		"sed -i 's/a/b/' "+probe,
		"sed --in-place 's/a/b/' "+probe,
		"cp /etc/hostname "+probe,
		"mv /etc/hostname "+probe,
		"ln -s /etc/hostname "+probe,
		"ln /etc/hostname "+probe,
		"install /etc/hostname "+probe,
		"truncate -s 0 "+probe,
		"touch "+probe,
		"mkdir "+canaryRoot+"/newdir",
		"rm -f "+probe,
		"rmdir "+canaryRoot,
		"chmod 777 "+canaryRoot,
		"chown root "+probe,
		"tar -cf "+probe+" /etc/hostname",
		"split -b 1 /etc/hostname "+probe,
	)

	// --- Command / process substitution variants --------------------
	add("substitution",
		"cat `touch "+probe+"`",
		"echo $(touch "+probe+")",
		"cat <(touch "+probe+")",
		"cat >(touch "+probe+")",
		"echo ${x:=$(touch "+probe+")}",
	)

	// --- eval / decode-and-exec -------------------------------------
	add("eval-decode",
		"eval touch "+probe,
		"eval 'touch "+probe+"'",
		"echo dG91Y2g= | base64 -d | sh", // "touch" base64 (no arg, but exercises base64|sh)
		fmt.Sprintf("echo %q | base64 -d | sh", "touch "+probe),
		"printf 'touch %s' "+probe+" | sh",
		"sh -c 'touch "+probe+"'",
		"bash -c 'touch "+probe+"'",
	)

	// --- IFS / quoting tricks ---------------------------------------
	add("ifs-quoting",
		"IFS=, touch,"+probe,
		"X=touch; $X "+probe,
		`t""ouch `+probe,
		`t\ouch `+probe,
		`'touch' `+probe,
	)

	// --- Here-docs / here-strings -----------------------------------
	add("heredoc",
		"cat <<EOF > "+probe+"\nx\nEOF",
		"cat > "+probe+" <<EOF\nx\nEOF",
		"tee "+probe+" <<<x",
	)

	// --- Background & job control -----------------------------------
	add("background",
		"touch "+probe+" &",
		"{ touch "+probe+"; }",
		"( touch "+probe+" )",
	)

	// --- find -exec / xargs -----------------------------------------
	add("find-xargs",
		"find /etc/hostname -exec touch "+probe+" ;",
		"find /etc/hostname -execdir touch "+probe+" ;",
		"find /etc/hostname -delete",
		"ls /etc/hostname | xargs touch "+probe,
		"echo "+probe+" | xargs touch",
	)

	// --- awk BEGIN{system} ------------------------------------------
	add("awk-exec",
		"awk 'BEGIN{system(\"touch "+probe+"\")}'",
		"awk 'BEGIN{print \"x\" > \""+probe+"\"}'",
		"awk 'BEGIN{while((getline line < \""+secretPath+"\")>0) print line}'",
	)

	// --- ex / vi ex-commands ----------------------------------------
	add("ex-vi",
		"ex -s -c 'w "+probe+"' -c q /etc/hostname",
		"vi -es -c 'w! "+probe+"' -c 'q!' /etc/hostname",
	)

	// --- git writes -------------------------------------------------
	add("git-write",
		"git init "+canaryRoot+"/repo",
		"git -c core.pager='touch "+probe+"' log",
		"git config --global alias.x '!touch "+probe+"'",
		"git -C "+canaryRoot+" init",
		// C2 (M5): git grep -O / --open-files-in-pager runs an arbitrary
		// command via the pager over the matches. The classifier must route it
		// to WRITE, so a Tier-1 gate DENIES it (exit 77) before any unsigned
		// run — the denied verdict is the binding proof even if git/the repo is
		// absent. If it ever regressed, `touch probe` trips the canary.
		"git grep -O'touch "+probe+"' TODO",
	)

	// --- interpreter -c writes --------------------------------------
	add("interpreter",
		`python3 -c "open('`+probe+`','w').write('x')"`,
		`python -c "open('`+probe+`','w').write('x')"`,
		`perl -e "open(F,'>','`+probe+`');print F 'x'"`,
		`ruby -e "File.write('`+probe+`','x')"`,
		`node -e "require('fs').writeFileSync('`+probe+`','x')"`,
	)

	// --- env-var abuse ----------------------------------------------
	add("env-abuse",
		"env touch "+probe,
		"env X=1 touch "+probe,
		"env -i touch "+probe,
		"env LD_PRELOAD=/tmp/x cat /etc/hostname",
		"GIT_EXTERNAL_DIFF=touch git diff",
		"PAGER='touch "+probe+"' git log",
	)

	// --- The 6 classifier write/exec classes fixed 2026-06-14 -------
	// Each WRITE form below was, pre-fix, mapped to an always-READ rule
	// and so ran unsigned on a Tier-1 gate. They aim REAL write payloads
	// at the beacon dir (under the tripwire's clean zone) so BOTH the
	// canary snapshot and the tripwire would see the write IF the gate
	// let it through. Against the FIXED gate every WRITE row must come
	// back `denied` (exit 77) — 0 bypasses is the dynamic proof the
	// classifier fix holds. Each class also gets a READ control that must
	// stay `executed` with no write_alert.
	//
	// beaconWrite is a write payload landing in the beacon dir; we use a
	// distinct filename per class so a leak is attributable.
	bw := func(name string) string { return beaconDir + "/" + name }
	add("classifier-write-tools",
		// 1. sort -o / --output writes a file
		"sort -o "+bw("sort_pwned")+" /etc/hostname",
		"sort --output="+bw("sort_pwned2")+" /etc/hostname",
		// 2. date -s / --set / positional set the system clock (state
		//    mutation; no beacon file, but a denied verdict is the proof).
		"date -s '2020-01-01 00:00:00'",
		"date --set=@1",
		"date 010100002020",
		// 3. ip OBJECT {add|set|del|flush} reconfigures the host
		"ip addr add 10.99.0.1/24 dev lo",
		"ip link set lo down",
		"ip route add 10.99.0.0/24 dev lo",
		"ip addr del 10.99.0.1/24 dev lo",
		// 4. ifconfig <iface> <config> reconfigures an interface
		"ifconfig lo 127.0.0.2",
		"ifconfig lo netmask 255.0.0.0",
		// 5. awk -f opaque program FILE (can system()/redirect)
		"awk -f /etc/hostname /etc/hostname",
		"awk --file=/etc/hostname /etc/hostname",
		// 6. sed exec / write primitives (e command, s///e with alt
		//    delimiters, $-addressed w) aimed at the beacon
		"sed 'e touch "+bw("sed_e_pwned")+"' /etc/hostname",
		"sed 's|x|touch "+bw("sed_se_pwned")+"|e' /etc/hostname",
		"sed '$w "+bw("sed_w_pwned")+"' /etc/hostname",
		// C1 (M5): regex-addressed glued exec `/./e cmd` — the boundary-aware
		// /e detector must catch it. sed is present, so this lands a beacon IF
		// the gate ever regresses (tripwire proof); denied otherwise.
		"sed '/./e touch "+bw("sed_slashe_pwned")+"' /etc/hostname",
		// M2 (M5): custom-delimiter address exec `\|.|e cmd` —
		// sedCustomDelimCmdExecsOrWrites must catch it.
		"sed '\\|.|e touch "+bw("sed_customdelim_pwned")+"' /etc/hostname",
		// M1 (M5): docker compose config -o writes a file. docker is likely
		// absent in the campaign image; the binding proof is the denied verdict
		// (classification precedes exec), like the date/ip state-mutation rows.
		"docker compose config -o "+bw("compose_config_pwned"),
	)
	// READ controls for the same tools: these are legitimate diagnostics
	// the fix must NOT deny — they must come back `executed`, no write.
	add("classifier-read-control",
		"sort /etc/hostname",
		"sort -n -r /etc/hostname",
		"date",
		"date +%s",
		"date -u",
		"ip addr show",
		"ip route list",
		"ifconfig -a",
		"awk '{print $1}' /etc/hostname",
	)

	// --- 2026-07-10 triple-review read-only-gate fixes --------------
	// Five confirmed write-as-read bypasses closed on feat/v1-release-polish.
	// Every WRITE row must come back `denied` (exit 77) on the Tier-1 gate; the
	// ones that can land a real file aim at the beacon/probe so a REGRESSION
	// trips the tripwire, and the rest bind on the denied verdict (classification
	// precedes exec), like the date/ip/docker state-mutation rows.
	add("reviewfix/command-wrapping",
		// SEC-1: `command <bin> …` RUNS the wrapped binary; a -v/-V buried in the
		// WRAPPED command's args must NOT be mistaken for command's describe flag.
		"command rm -v -rf "+probe,
		"command sh -v -c 'touch "+probe+"'",
		"command touch "+probe,
		"command umount -v /mnt",
	)
	add("reviewfix/git-diff-output",
		// SEC-2: git diff/show/log --output=FILE writes/clobbers an arbitrary path.
		"git diff --output="+bw("git_diff_output_pwned"),
		"git diff --output "+bw("git_diff_output2_pwned"),
		"git show --output="+bw("git_show_output_pwned")+" HEAD",
		"git log -p --output="+bw("git_log_output_pwned"),
		"git log --output="+bw("git_log_output2_pwned"),
	)
	add("reviewfix/file-compile",
		// C1: `file -C`/`--compile` compiles a magic `.mgc` file to disk. It lands
		// in cwd (a read can't cd), so the denied verdict is the binding proof.
		"file -C",
		"file -C -m /etc/magic",
		"file --compile -m /etc/magic",
	)
	add("reviewfix/sysctl-apply",
		// SEC-3: `sysctl --system`/`-f FILE`/`-S` re-apply sysctl config to the
		// running kernel — a state mutation; the denied verdict is the proof.
		"sysctl --system",
		"sysctl -f /etc/sysctl.conf",
		"sysctl -S",
	)

	// --- Free-form locations OUTSIDE the canary tree ----------------
	// These aim REAL writes at the highest-value persistence / pivot
	// targets that the canary snapshot does NOT watch but the EXPANDED
	// tripwire now DOES: the SSH user's real home (/config), its
	// authorized_keys (self-escalation / persistence), and /tmp (stage
	// pad). Against the FIXED gate every one must come back `denied`
	// (exit 77) — 0 bypasses. The point is the SAFETY NET: if the gate
	// ever regressed and let one of these run, the tripwire (not the
	// canary diff, which never sees these paths) would catch it and flag
	// BYPASS. A runtime sshd_config drop-in is included for the same
	// reason — the directory is no longer blanket-excluded.
	//
	// home is the SSH user's real HOME (canaryRoot is <home>/canary), so
	// these stay correct if the seeded layout ever moves.
	home := strings.TrimSuffix(canaryRoot, "/canary")
	add("freeform-location",
		// authorized_keys: append a second trusted key (persistence) /
		// drop the forced command (self-escalation). The classic
		// own-the-box write.
		"echo 'ssh-ed25519 AAAAredteam attacker' >> "+home+"/.ssh/authorized_keys",
		"echo pwned > "+home+"/.ssh/authorized_keys",
		"sed -i '1i\\ssh-ed25519 AAAAredteam x' "+home+"/.ssh/authorized_keys",
		"touch "+home+"/.ssh/authorized_keys",
		// a plain file elsewhere in the real home (outside the canary tree)
		"echo owned > "+home+"/.redteam_home_pwned",
		"touch "+home+"/.bashrc_pwned",
		// /tmp staging (the bulk of /tmp is watched; only sort temps are
		// excluded, so a generic /tmp write must fire)
		"echo pwned > /tmp/redteam_tmp_pwned",
		"touch /tmp/redteam_tmp_pwned",
		"cp /etc/hostname /tmp/redteam_staged",
		// runtime sshd drop-in: /etc/ssh/sshd_config.d is no longer
		// blanket-excluded, so planting a config here must fire.
		"echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/99-redteam.conf",
	)

	// --- Secret-read exposure (allowed by design; quantified) -------
	add("secret-read",
		"cat "+secretPath,
		"head -c 200 "+secretPath,
		"grep REDTEAM "+secretPath,
		"sed -n 'p' "+secretPath,
		"awk '{print}' "+secretPath,
		"tail -n +1 "+secretPath,
		"od -c "+secretPath,
		"cat /etc/passwd",
		"cat ~/.ssh/authorized_keys",
	)

	// --- Sanity baselines (must NOT bypass) -------------------------
	add("baseline-read",
		"cat /etc/hostname",
		"ls -la "+canaryRoot,
		"whoami",
		"id",
	)

	return atk
}

// Mutate produces a batch of fuzzer-generated candidates derived from
// the corpus: it recombines write payloads with separators, quoting
// wrappers, and obfuscation transforms. The goal is to stumble onto a
// separator/quoting combination the classifier mishandles. Output is
// deterministic for a given seed so a finding is reproducible.
//
// n bounds how many mutants to emit.
func Mutate(canaryRoot string, seed int64, n int) []Attack {
	probe := canaryRoot + "/" + canaryProbeName
	rng := rand.New(rand.NewSource(seed))

	// Atomic write payloads — each, run alone, mutates state.
	payloads := []string{
		"touch " + probe,
		"rm -f " + probe,
		": > " + probe,
		"echo x > " + probe,
		"sed -i s/a/b/ " + probe,
		"truncate -s0 " + probe,
	}
	// Read heads to prepend (the classifier sees a read first).
	reads := []string{"ls", "cat /etc/hostname", "true", "echo hi", "df -h", "id"}
	// Separators that should all route the write through the gate.
	seps := []string{"\n", ";", "&&", "||", "|", "&", "\n\n", "\t;\t", " ; "}
	// Quoting / obfuscation wrappers applied to a payload.
	wrappers := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return "eval '" + s + "'" },
		func(s string) string { return "sh -c '" + s + "'" },
		func(s string) string { return "$(" + s + ")" },
		func(s string) string { return "`" + s + "`" },
		func(s string) string { return `"$(` + s + `)"` },
		func(s string) string { return "{ " + s + "; }" },
		func(s string) string { return "( " + s + " )" },
	}

	var out []Attack
	for i := 0; i < n; i++ {
		read := reads[rng.Intn(len(reads))]
		sep := seps[rng.Intn(len(seps))]
		payload := payloads[rng.Intn(len(payloads))]
		wrap := wrappers[rng.Intn(len(wrappers))]
		cmd := read + sep + wrap(payload)
		out = append(out, Attack{Category: "fuzz", Cmd: cmd})
	}
	return out
}

// dedupe removes duplicate commands while preserving order, so the
// corpus + fuzz batch don't re-test identical strings.
func dedupe(atks []Attack) []Attack {
	seen := map[string]struct{}{}
	var out []Attack
	for _, a := range atks {
		if _, ok := seen[a.Cmd]; ok {
			continue
		}
		seen[a.Cmd] = struct{}{}
		out = append(out, a)
	}
	return out
}

// summarizeCategories returns a sorted "category: count" listing for the
// human-readable report header.
func summarizeCategories(atks []Attack) string {
	counts := map[string]int{}
	for _, a := range atks {
		counts[a.Category]++
	}
	var cats []string
	for c := range counts {
		cats = append(cats, c)
	}
	// stable order
	for i := 0; i < len(cats); i++ {
		for j := i + 1; j < len(cats); j++ {
			if cats[j] < cats[i] {
				cats[i], cats[j] = cats[j], cats[i]
			}
		}
	}
	var b strings.Builder
	for _, c := range cats {
		fmt.Fprintf(&b, "  %-34s %d\n", c, counts[c])
	}
	return b.String()
}
