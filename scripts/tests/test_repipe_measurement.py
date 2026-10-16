import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts.repipe import measurement, probe


@unittest.skipUnless(os.name == "posix", "POSIX process measurement")
class MeasurementReportTests(unittest.TestCase):
    def test_darwin_rss_bytes_are_converted_to_kibibytes(self):
        with mock.patch.object(measurement.os, "posix_spawn", return_value=123), \
                mock.patch.object(measurement.os, "wait4",
                                  return_value=(123, 0, SimpleNamespace(ru_maxrss=1536))), \
                mock.patch.object(measurement.signal, "signal"), \
                mock.patch.object(measurement.sys, "platform", "darwin"):
            report = measurement._measure("/tool", ["tool", "argument with spaces"], {})
        self.assertEqual(report["max_rss_kb"], 1.5)


@unittest.skipUnless(os.name == "posix", "POSIX process measurement")
class MeasurementProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kuna-probe-measurement-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.sources = ["wait4"]
        if probe._measurement_source() == "/usr/bin/time -v":
            self.sources.append("/usr/bin/time -v")
        self.environment = dict(os.environ, LC_ALL="C")

    def execute(self, source, program, stdin=None, timeout=5, arguments=()):
        return probe._exec_once(0, [sys.executable, "-c", program, *arguments],
                                str(self.directory), self.environment, stdin, timeout, source)

    def test_observer_preserves_exact_child_environment(self):
        for source in self.sources:
            for locale in ("LC_CTYPE", "LC_ALL"):
                environment = {"PATH": os.defpath, locale: "C",
                               "PROBE_EMPTY": "", "PROBE_TEXT": "value with spaces é"}
                with self.subTest(source=source, locale=locale):
                    run = probe._exec_once(
                        0, ["/usr/bin/env"], str(self.directory), environment, None, 5, source)
                    self.assertEqual(run["exit_code"], 0, run)
                    self.assertIsNone(run["error"], run)
                    observed = dict(line.split("=", 1) for line in run["stdout"].splitlines())
                    self.assertEqual(observed, environment)

    def test_normal_exit_stdin_bytes_truncation_and_clean_streams(self):
        payload = "input with spaces é\n"
        out = payload.encode() + b"\xff" + b"x" * 100000
        err = b"child stderr\n" + b"y" * 100000
        program = ("import os,sys; data=sys.stdin.buffer.read(); "
                   "os.write(1,data+b'\\xff'+b'x'*100000); "
                   "os.write(2,b'child stderr\\n'+b'y'*100000); sys.exit(7)")
        for source in self.sources:
            with self.subTest(source=source), mock.patch.object(probe, "CAPTURE_MAX_BYTES", 32):
                run = self.execute(source, program, payload)
                self.assertEqual(run["exit_code"], 7, run)
                self.assertIsNone(run["signal"])
                self.assertIsNone(run["error"])
                self.assertEqual(run["stdout_bytes"], len(out))
                self.assertEqual(run["stderr_bytes"], len(err))
                self.assertEqual(run["stdout"], out[:32].decode("utf-8", "replace"))
                self.assertEqual(run["stderr"], err[:32].decode("utf-8", "replace"))
                self.assertTrue(run["stdout_truncated"])
                self.assertTrue(run["stderr_truncated"])
                self.assertGreater(run["max_rss_kb"], 0)

    def test_numeric_exits_and_real_signals_are_distinct(self):
        for source in self.sources:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                for killed in (False, True):
                    with self.subTest(source=source, signal=sig, killed=killed):
                        end = ("os.kill(os.getpid(), %d)" % sig if killed
                               else "sys.exit(%d)" % (128 + sig))
                        run = self.execute(
                            source, "import os,sys; os.write(1,b'out\\n'); "
                            "os.write(2,b'err\\n'); " + end)
                        self.assertEqual(run["exit_code"], -sig if killed else 128 + sig, run)
                        self.assertEqual(run["signal"], sig if killed else None)
                        self.assertEqual(run["stdout"], "out\n")
                        self.assertEqual(run["stderr"], "err\n")
                        self.assertIsNone(run["error"])
                        self.assertGreater(run["max_rss_kb"], 0)

    def test_non_python_children_keep_default_sigpipe_behavior(self):
        for source in self.sources:
            with self.subTest(source=source):
                run = probe._exec_once(
                    0, ["/bin/sh", "-c", "kill -PIPE $$; exit 7"],
                    str(self.directory), self.environment, None, 5, source)
                self.assertEqual(run["exit_code"], -signal.SIGPIPE, run)
                self.assertEqual(run["signal"], signal.SIGPIPE)
                self.assertIsNone(run["error"])

    def test_repeated_rss_does_not_inherit_an_earlier_child_high_water_mark(self):
        for source in self.sources:
            with self.subTest(source=source):
                high = self.execute(source, "memory=bytearray(64*1024*1024); "
                                    "memory[::4096]=b'x'*(len(memory)//4096)")
                small = [self.execute(source, "pass") for _ in range(2)]
                for run in [high, *small]:
                    self.assertIsNone(run["error"], run)
                    self.assertEqual(run["exit_code"], 0, run)
                    self.assertGreater(run["max_rss_kb"], 0)
                for run in small:
                    self.assertGreater(high["max_rss_kb"] - run["max_rss_kb"], 32 * 1024)

    def test_timeout_cleans_descendants_after_the_supervisor_exits(self):
        for source in self.sources:
            with self.subTest(source=source):
                marker = self.directory / source.replace("/", "_")
                program = (
                    "import os,signal,sys,time\n"
                    "if os.fork() == 0:\n"
                    " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                    " os.write(1,b'descendant ready\\n')\n"
                    " time.sleep(1.5)\n"
                    " open(sys.argv[1],'w').write('escaped')\n"
                    "else:\n"
                    " time.sleep(60)\n")
                run = self.execute(source, program, timeout=0.5, arguments=(str(marker),))
                self.assertTrue(run["timed_out"], run)
                self.assertIsNotNone(run["error"], run)
                self.assertIn("descendant ready", run["stdout"])
                self.assertLess(run["wall_ms"], 5000)
                time.sleep(1.5)
                self.assertFalse(marker.exists(), run)

    def test_hard_timeout_does_not_misattribute_supervisor_status(self):
        run = self.execute("wait4", "import signal,time; "
                           "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)",
                           timeout=0.5)
        self.assertTrue(run["timed_out"], run)
        self.assertIsNotNone(run["error"], run)
        self.assertIsNone(run["exit_code"])
        self.assertIsNone(run["signal"])
        self.assertIsNone(run["max_rss_kb"])

    def test_spawn_failure_is_an_observation_without_supervisor_diagnostics(self):
        path = self.directory / "invalid-executable"
        path.write_bytes(b"not an executable image")
        path.chmod(0o755)
        run = probe._exec_once(0, [str(path)], str(self.directory), self.environment,
                               None, 5, "wait4")
        self.assertIsNotNone(run["error"], run)
        self.assertIsNone(run["exit_code"])
        self.assertEqual(run["stdout_bytes"], 0)
        self.assertEqual(run["stderr_bytes"], 0)

    def test_public_allowlist_still_denies_interpreters(self):
        with self.assertRaises(probe.ProbeError):
            probe.run({"schema": "re-probe/1", "kind": "cli",
                       "cmd": [sys.executable, "-c", "pass"], "timeout_s": 5,
                       "expect": {"exit_code": {"eq": 0}}})

    @unittest.skipUnless(sys.platform == "darwin", "Darwin public resource measurement")
    def test_public_memory_predicate_uses_actual_darwin_measurements(self):
        fixture = self.directory / "input.txt"
        fixture.write_text("probe fixture\n")
        document = {
            "schema": "re-probe/1", "kind": "memory",
            "cmd": [shutil.which("file"), str(fixture)],
            "timeout_s": 5, "repeat": 3,
            "expect": {"exit_code": {"eq": 0},
                       "max_rss_kb": {"stat": "max", "gt": 0, "lt": 512 * 1024}},
        }
        observation = probe.run(document, {"work": str(self.directory)})
        self.assertTrue(probe.evaluate(probe.normalize(document), observation)["passed"],
                        observation)
        document["expect"]["max_rss_kb"] = {"stat": "max", "lt": 0}
        self.assertFalse(probe.evaluate(probe.normalize(document), observation)["passed"])


if __name__ == "__main__":
    unittest.main()
