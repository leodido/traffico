---
name: running-traffico-smoke-tests
description: Use when working in the traffico repository and needing host-realistic release smoke evidence through the Lima traffico-ebpf VM, including validating the Lima config, starting the VM, running intent_examples.bats, running intent_verifier.bats, or inspecting artifacts/lima reports.
---

# Running Traffico Smoke Tests

## Overview

Use this skill for release-confidence smoke gates that need a normal Ubuntu VM kernel.
Use `running-traffico-linux-tests` for the fast/default Docker loop.

Only supported backend: Lima VM named `traffico-ebpf`.
Do not invent other smoke backends unless the repo adds them.

The Lima runner still uses traffico's xmake/BATS/Scapy tests.
It is an execution backend, not a second semantic framework.

Automated smoke tests must attach to the namespace peer interface created by BATS.
Do not attach automated tests to the VM's default network interface.

## Workflow

Run commands from the traffico repository root unless `--repo-in-vm` is passed explicitly.

Validate the VM config:

```sh
limactl validate lima/traffico-ebpf.yml
```

Inspect any existing VM before starting it:

```sh
limactl list --format '{{.Name}} {{.Status}}'
```

If `traffico-ebpf` already exists, inspect the stored Lima config before reusing it:

```sh
rg -n "ubuntu-24.04|python3-scapy|/sys/fs/bpf|xmake" "$HOME/.lima/traffico-ebpf/lima.yaml"
```

Stop if the existing VM does not look like the traffico smoke VM.
Do not silently reuse a stale instance created from a different config.

Start or create the VM:

```sh
limactl start --name=traffico-ebpf lima/traffico-ebpf.yml
```

If the VM already exists and Lima rejects `--name`, start it by instance name:

```sh
limactl start traffico-ebpf
```

Dry-run the default release smoke gate before running it in the VM:

```sh
python3 tools/lima_traffico_runner.py --dry-run
```

Run the default release smoke gate:

```sh
python3 tools/lima_traffico_runner.py
```

The default gate runs both real-world Intent examples and the verifier envelope.
Do not treat examples-only output as release-complete evidence.

Run only the examples when narrowing a failure:

```sh
python3 tools/lima_traffico_runner.py --test test/intent_examples.bats
```

Inspect the runner report:

```sh
python3 - <<'PY'
import json
from pathlib import Path

report = Path("artifacts/lima/traffico-runner-report.json")
data = json.loads(report.read_text())
assert data["status"] == "ok"
assert data["instance"] == "traffico-ebpf"
assert "limactl" in data["lima_command"][0]
assert "xmake" in data["guest_command"]
print("lima smoke report ok")
PY
```

## Failure Rules

If `limactl` is missing, stop and report that the smoke gate cannot run on this machine.
Do not use Docker results as a substitute for Lima smoke evidence.

If an existing `traffico-ebpf` VM does not match the stored config checks, stop and ask before recreating it.

If provisioning or package installation fails, report the Lima failure.
Do not weaken the smoke gate to make the VM pass.

Generated reports must stay under `artifacts/`.
They must not be committed.
