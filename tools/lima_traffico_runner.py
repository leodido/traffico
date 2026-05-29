#!/usr/bin/env python3
import argparse
import json
import posixpath
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Mapping


DEFAULT_TESTS = ["test/intent_examples.bats", "test/intent_verifier.bats"]
DEFAULT_REPO_IN_VM = str(Path(__file__).resolve().parents[1])


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def join_shell(argv: Iterable[str]) -> str:
    return " ".join(shell_quote(part) for part in argv)


def normalized_tests(tests: List[str]) -> List[str]:
    return tests if tests else list(DEFAULT_TESTS)


def build_guest_command(repo_in_vm: str, tests: List[str], configure: bool, build: bool) -> str:
    quoted_repo = shell_quote(repo_in_vm)
    quoted_repo_marker = shell_quote(posixpath.join(repo_in_vm, "xmake.lua"))
    commands = [
        f"test -d {quoted_repo}",
        f"test -f {quoted_repo_marker}",
        f"cd {quoted_repo}",
    ]
    if configure:
        commands.append(join_shell(["xmake", "f", "-c", "-y", "--generate-vmlinux=y", "--require-bpftool=y"]))
    if build:
        commands.append(join_shell(["xmake", "build", "-y"]))
    commands.append(join_shell(["xmake", "run", "test", *normalized_tests(tests)]))
    return " && ".join(commands)


def build_lima_command(instance: str, guest_command: str) -> List[str]:
    return ["limactl", "shell", instance, "bash", "-lc", guest_command]


def write_report(path: Path, data: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def run_lima_tests(
    instance: str,
    repo_in_vm: str,
    tests: List[str],
    runner_report: Path,
    configure: bool,
    build: bool,
    dry_run: bool,
) -> Mapping[str, object]:
    selected_tests = normalized_tests(tests)
    guest_command = build_guest_command(
        repo_in_vm=repo_in_vm,
        tests=selected_tests,
        configure=configure,
        build=build,
    )
    lima_command = build_lima_command(instance, guest_command)
    data: Dict[str, object] = {
        "status": "dry-run",
        "instance": instance,
        "repo_in_vm": repo_in_vm,
        "tests": selected_tests,
        "guest_command": guest_command,
        "lima_command": lima_command,
    }
    if not dry_run:
        completed = subprocess.run(
            lima_command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        data.update(
            {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "status": "ok" if completed.returncode == 0 else "failed",
            }
        )
    write_report(runner_report, data)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Run traffico Linux tests inside Lima.")
    parser.add_argument("--instance", default="traffico-ebpf")
    parser.add_argument("--repo-in-vm", default=DEFAULT_REPO_IN_VM)
    parser.add_argument("--runner-report", type=Path, default=Path("artifacts/lima/traffico-runner-report.json"))
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--skip-configure", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    data = run_lima_tests(
        instance=args.instance,
        repo_in_vm=args.repo_in_vm,
        tests=args.test,
        runner_report=args.runner_report,
        configure=not args.skip_configure,
        build=not args.skip_build,
        dry_run=args.dry_run,
    )
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["status"] in {"ok", "dry-run"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
