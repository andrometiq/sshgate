#!/usr/bin/env python3
"""Exercise the runner's safety guard and cleanup with shell stubs, never Docker."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = (Path(__file__).resolve().parents[3] / 'scripts/test-journey.sh').read_text()
GUARD = SCRIPT[SCRIPT.index('cat >&2'):SCRIPT.index('docker info')]
CLEANUP = SCRIPT[SCRIPT.index('cleanup() {'):SCRIPT.index('trap cleanup EXIT')]


class RunnerChecks(unittest.TestCase):
    def test_privileged_guard(self):
        for ci, opt_in, allowed in [('', '', False), ('false', '', False),
                                    ('true', '', False), ('', '1', True), ('true', '1', True),
                                    ('', 'true', False)]:
            with self.subTest(ci=ci, opt_in=opt_in):
                result = subprocess.run(['bash', '-c', 'set -eu\n' + GUARD],
                                        env={**os.environ, 'CI': ci,
                                             'JOURNEY_ALLOW_PRIVILEGED': opt_in},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, allowed)
                self.assertIn('host devices', result.stderr)

    def test_cleanup(self):
        for case, expected in [('absent', 0), ('removed', 0), ('remove-fails', 1),
                               ('remains', 1), ('list-fails', 1),
                               ('verify-fails', 1), ('down-fails', 1),
                               ('prior-fails', 7)]:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                # A file records state because command substitutions run in subshells.
                stub = r'''
set -euo pipefail
prep="$STATE/prep"
mkdir "$prep"
JOURNEY_PROJECT=test JOURNEY_COMPOSE_FILE=unused JOURNEY_IMAGE=test-image
[[ "$CASE" = absent ]] || touch "$STATE/image"
docker() {
    if [[ "$1" = compose ]]; then
        [[ "$CASE" != down-fails ]]
    elif [[ "$1 $2" = 'image ls' ]]; then
        [[ "$CASE" != list-fails ]] || return 1
        [[ "$CASE" != verify-fails || ! -f "$STATE/removed" ]] || return 1
        if [[ -f "$STATE/image" ]]; then echo image-id; fi
    elif [[ "$1 $2" = 'image rm' ]]; then
        [[ -f "$STATE/image" ]] || exit 99
        [[ "$CASE" != remove-fails ]] || return 1
        touch "$STATE/removed"
        [[ "$CASE" = remains ]] || rm "$STATE/image"
    else
        exit 99
    fi
}
'''
                result = subprocess.run(['bash', '-c', stub + CLEANUP +
                                         '\ntrap cleanup EXIT\n'
                                         'if [[ "$CASE" = prior-fails ]]; then exit 7; fi\n'],
                                        env={**os.environ, 'STATE': directory, 'CASE': case},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertFalse((Path(directory) / 'prep').exists())


if __name__ == '__main__':
    unittest.main()
