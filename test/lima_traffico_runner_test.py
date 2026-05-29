import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import lima_traffico_runner


class LimaTrafficoRunnerTest(unittest.TestCase):
    def test_guest_command_runs_default_intent_examples(self):
        command = lima_traffico_runner.build_guest_command(
            repo_in_vm="/Users/me/traffico",
            tests=[],
            configure=True,
            build=True,
        )

        self.assertIn("test -d '/Users/me/traffico'", command)
        self.assertIn("test -f '/Users/me/traffico/xmake.lua'", command)
        self.assertIn("cd '/Users/me/traffico'", command)
        self.assertIn("'xmake' 'f' '-c' '-y' '--generate-vmlinux=y' '--require-bpftool=y'", command)
        self.assertIn("'xmake' 'build' '-y'", command)
        self.assertIn("'xmake' 'run' 'test' 'test/intent_examples.bats'", command)
        self.assertNotIn("--allow", command)
        self.assertNotIn("--forbid", command)

    def test_guest_command_accepts_selected_tests(self):
        command = lima_traffico_runner.build_guest_command(
            repo_in_vm="/Users/me/traffico",
            tests=["test/intent_examples.bats", "test/intent_verifier.bats"],
            configure=False,
            build=False,
        )

        self.assertNotIn("'xmake' 'f'", command)
        self.assertNotIn("'xmake' 'build'", command)
        self.assertIn("'test/intent_examples.bats' 'test/intent_verifier.bats'", command)

    def test_lima_command_wraps_guest_command(self):
        command = lima_traffico_runner.build_lima_command(
            instance="traffico-ebpf",
            guest_command="cd /repo && xmake run test",
        )

        self.assertEqual(
            command,
            ["limactl", "shell", "traffico-ebpf", "bash", "-lc", "cd /repo && xmake run test"],
        )

    def test_dry_run_writes_runner_report_without_invoking_limactl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "runner.json"

            with mock.patch.object(lima_traffico_runner.subprocess, "run") as run:
                data = lima_traffico_runner.run_lima_tests(
                    instance="traffico-ebpf",
                    repo_in_vm="/Users/me/traffico",
                    tests=[],
                    runner_report=report,
                    configure=True,
                    build=True,
                    dry_run=True,
                )

            run.assert_not_called()
            self.assertEqual(data["status"], "dry-run")
            self.assertEqual(data["tests"], ["test/intent_examples.bats"])
            self.assertTrue(report.exists())
            written = json.loads(report.read_text())
            self.assertEqual(written["lima_command"][0], "limactl")

    def test_real_run_records_limactl_success(self):
        completed = subprocess.CompletedProcess(
            args=["limactl"],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "runner.json"
            with mock.patch.object(
                lima_traffico_runner.subprocess,
                "run",
                return_value=completed,
            ) as run:
                data = lima_traffico_runner.run_lima_tests(
                    instance="traffico-ebpf",
                    repo_in_vm="/Users/me/traffico",
                    tests=["test/intent_examples.bats"],
                    runner_report=report,
                    configure=True,
                    build=True,
                    dry_run=False,
                )

        run.assert_called_once()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["returncode"], 0)
        self.assertEqual(data["stdout"], "ok\n")

    def test_real_run_records_limactl_failure(self):
        completed = subprocess.CompletedProcess(
            args=["limactl"],
            returncode=42,
            stdout="",
            stderr="boom\n",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "runner.json"
            with mock.patch.object(
                lima_traffico_runner.subprocess,
                "run",
                return_value=completed,
            ):
                data = lima_traffico_runner.run_lima_tests(
                    instance="traffico-ebpf",
                    repo_in_vm="/Users/me/traffico",
                    tests=["test/intent_examples.bats"],
                    runner_report=report,
                    configure=True,
                    build=True,
                    dry_run=False,
                )

        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["returncode"], 42)
        self.assertEqual(data["stderr"], "boom\n")

    def test_main_returns_one_when_lima_fails(self):
        completed = subprocess.CompletedProcess(
            args=["limactl"],
            returncode=42,
            stdout="",
            stderr="boom\n",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "runner.json"
            argv = [
                "lima_traffico_runner.py",
                "--runner-report",
                str(report),
                "--test",
                "test/intent_examples.bats",
            ]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch.object(
                    lima_traffico_runner.subprocess,
                    "run",
                    return_value=completed,
                ):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(lima_traffico_runner.main(), 1)


if __name__ == "__main__":
    unittest.main()
