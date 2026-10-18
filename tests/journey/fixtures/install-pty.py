#!/usr/bin/env python3
"""Drive the real installer's interactive prompts without recording token input."""
import errno
import os
import pty
import select
import signal
import time

pid, master = pty.fork()
if pid == 0:
    os.chdir('/home/sgop/src/SSHGate')
    os.execvp('sudo', ['sudo', './scripts/install.sh'])

prompts = [(b'Telegram user_id (numeric), or press Enter to skip:', b'424242\n'),
           (b'Paste the BotFather token (input hidden), or press Enter to skip:', b'123456:journey_fixture_only\n')]
buffer = b''
deadline = time.monotonic() + 120
try:
    while True:
        if time.monotonic() >= deadline:
            raise RuntimeError('installer PTY deadline exceeded')
        if not select.select([master], [], [], 0.2)[0]:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        buffer = (buffer + chunk)[-16384:]
        if prompts and prompts[0][0] in buffer:
            _, answer = prompts.pop(0)
            os.write(master, answer)
            buffer = b''
    _, status = os.waitpid(pid, 0)
    if prompts or os.waitstatus_to_exitcode(status) != 0:
        raise RuntimeError('installer failed or did not reach both Telegram prompts')
except BaseException:
    try:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    except ProcessLookupError:
        pass
    raise
finally:
    os.close(master)
