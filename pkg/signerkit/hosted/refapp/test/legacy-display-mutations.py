"""Run legacy display guard mutants without changing source files."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[5]
lock = os.environ["TEST_LOCK"]
source = root / "pkg/signerkit/hosted/human_handlers.go"
env = dict(os.environ, GOFLAGS="-mod=readonly", GOPROXY="off")
mutants = [
    ("redacted-label", "label = ap.LabelRedactedDisplay", 'label = ""', "TestHumanLegacyDisplayLabels"),
    ("redacted-flag", "isRedacted := display != c.Cmd", "isRedacted := false", "TestHumanLegacyDisplayLabels"),
    ("display-failed", "displayFailed = true", "displayFailed = false", "TestHumanLegacyDisplayFailure"),
    ("approve-refusal", "if !isV2 && decision == store.DecisionApprove && h.summarize(legacy).DisplayFailed {",
     "if false {", "TestHumanLegacyDisplayFailure"),
    ("inert-audit", 'h.auditLegacyVote(ctx, legacy, userID, decision, authn, "vote_refused{display_unavailable}")',
     "// audit removed", "TestHumanLegacyDisplayFailure"),
]
if "--js-only" in sys.argv:
    mutants = []
with tempfile.TemporaryDirectory(prefix="legacy-display-") as directory:
    tmp = Path(directory)
    for name, before, after, selector in mutants:
        text = source.read_text()
        assert text.count(before) == 1, name
        replacement = tmp / "human_handlers.go"
        replacement.write_text(text.replace(before, after))
        overlay = tmp / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(source): str(replacement)}}))
        result = subprocess.run(
            ["flock", lock, "go", "test", "-race", "-count=1", "-timeout", "30m",
             "-overlay", str(overlay), "-run", "^" + selector + "$", "./pkg/signerkit/hosted"],
            cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode == 0 or "--- FAIL: " + selector not in result.stdout:
            raise SystemExit(name + ": mutant not killed by assertion\n" + result.stdout)
        print(name + ": killed", flush=True)

assets = root / "pkg/signerkit/hosted/refapp/assets"
js_mutants = [
    ("browser-label", "app.js", "if (command.redacted)", "if (false)",
     "legacy redaction label"),
    ("browser-disable", "request.js", "disabled || displayFailed ||", "disabled ||",
     "legacy display failure"),
    ("browser-direct-call", "request.js", "(decision === 'approve' && displayFailed) || ", "",
     "legacy display failure"),
]
with tempfile.TemporaryDirectory(prefix="legacy-display-js-") as directory:
    tmp = Path(directory)
    for name, filename, before, after, selector in js_mutants:
        for asset in assets.glob("*.js"):
            (tmp / asset.name).write_text(asset.read_text())
        source = tmp / filename
        text = source.read_text()
        assert text.count(before) == 1, name
        source.write_text(text.replace(before, after))
        result = subprocess.run(
            ["flock", lock, "node",
             "pkg/signerkit/hosted/refapp/test/approvals.test.js"],
            cwd=root, env=dict(env, REFAPP_ASSETS=str(tmp)), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode == 0 or "AssertionError" not in result.stdout:
            raise SystemExit(name + ": mutant not killed by assertion\n" + result.stdout)
        print(name + ": killed", flush=True)
