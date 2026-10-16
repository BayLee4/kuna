"""Per-child resource/status supervisor for probe.py on Darwin.

Native time(1)'s -o does not redirect its signal diagnostics. This supervisor keeps the
child's streams untouched and obtains status and RSS from the same wait4 of its exact PID.
posix_spawn avoids both a Python launcher in the measured child and shell fallback.
The private report file carries the original environment before startup can alter it.
"""
from __future__ import annotations

import json
import os
import signal
import sys


def _measure(executable, argv, environment):
    """Restore subprocess-style signals; defer group TERM only in the reaping supervisor."""
    restore = [getattr(signal, name) for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ")
               if hasattr(signal, name)]
    pid = os.posix_spawn(executable, argv, environment, setsigdef=restore)
    signal.signal(signal.SIGTERM, lambda *_: None)
    _, status, usage = os.wait4(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    return {"exit_code": code, "signal": -code if code < 0 else None,
            "max_rss_kb": usage.ru_maxrss / 1024 if sys.platform == "darwin"
            else usage.ru_maxrss}


def main():
    path, executable, *argv = sys.argv[1:]
    try:
        with open(path) as request:
            environment = json.load(request)["environment"]
        report = _measure(executable, argv, environment)
    except (OSError, AttributeError, ValueError, KeyError) as exc:
        report = {"error": "measurement failed: %s" % exc}
    try:
        with open(path, "w") as fh:
            json.dump(report, fh)
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
