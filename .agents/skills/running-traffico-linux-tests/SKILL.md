---
name: running-traffico-linux-tests
description: Use when working in the traffico repository and needing to run or verify Linux BATS, CNI, Scapy, network namespace, veth, tc, or eBPF tests from macOS or Apple Silicon Docker Desktop
---

# Running Traffico Linux Tests

## Overview

Traffico's full BATS suite needs a privileged Linux/AMD64 container. Use the Ubuntu 24.04 runner by default; it matches CI's distro family and avoids the Arch/pacman sandbox override.

The runner still needs `--privileged` because tests create network namespaces, veth pairs, tc qdiscs, and eBPF attachments.

## Quick Reference

| Need | Command |
| --- | --- |
| Build image | `docker build --platform linux/amd64 -t traffico-ubuntu-test:latest -f /tmp/traffico-ubuntu-test.Dockerfile /tmp` |
| Create cache | `docker volume create traffico-ubuntu-xmake-cache` |
| Run tests | `docker start -ai traffico-ubuntu-test-runner` |
| Inspect runner | `docker ps -a --filter name=^/traffico-ubuntu-test-runner$` |

## Ubuntu Runner

Create `/tmp/traffico-ubuntu-test.Dockerfile`:

```Dockerfile
FROM docker.io/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV XMAKE_ROOT=y
ENV PATH=/root/.local/bin:$PATH

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        ca-certificates \
        clang llvm gcc g++ \
        make cmake ninja-build pkg-config git sudo diffutils unzip \
        m4 \
        xz-utils bzip2 \
        linux-headers-generic \
        libelf-dev libffi-dev libssl-dev zlib1g-dev \
        curl iproute2 iputils-ping \
        psmisc \
        python3-scapy python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://xmake.io/shget.text | bash

WORKDIR /workspaces/traffico
```

Build the image and create the persistent runner from the traffico repository root:

```sh
docker build \
  --platform linux/amd64 \
  -t traffico-ubuntu-test:latest \
  -f /tmp/traffico-ubuntu-test.Dockerfile \
  /tmp

docker volume create traffico-ubuntu-xmake-cache

docker create \
  --platform linux/amd64 \
  --privileged \
  --name traffico-ubuntu-test-runner \
  -v "$PWD:/workspaces/traffico" \
  -v traffico-ubuntu-xmake-cache:/root/.xmake \
  -w /workspaces/traffico \
  traffico-ubuntu-test:latest \
  bash -lc 'xmake f -c -y --generate-vmlinux=y --require-bpftool=y && xmake build -y && xmake run test'
```

Run or rerun:

```sh
docker start -ai traffico-ubuntu-test-runner
```

If the runner command, image, or mount changes, remove only the named container and recreate it. Keep `traffico-ubuntu-xmake-cache` unless intentionally forcing xmake to rebuild package dependencies.

## Troubleshooting Generated State

If the Docker build fails inside generated headers under `build/.gens` after branch switches, xmake graph changes, or partial rebuilds, suspect stale generated state before blaming CI or BPF source.

One known symptom is a generated API header expecting typed skeleton rodata while the local skeleton does not expose it:

```text
error: 'struct block_port_bpf' has no member named 'rodata'
error: 'struct block_ipv4_bpf' has no member named 'rodata'
```

Run an all-target xmake clean inside the Docker runner, then configure and rebuild:

```sh
xmake clean -a
xmake f -c -y --generate-vmlinux=y --require-bpftool=y
xmake build -y
```

Use this as a local generated-state reset, not as part of the normal happy path.

## Arch Fallback

Use [arch-runner.md](arch-runner.md) only when the Ubuntu runner cannot be built or run, an existing Arch runner/cache is already available and known good, or Arch-specific package/build behavior must be reproduced.

Do not choose Arch by default just because the fallback exists.

## Common Mistakes

| Mistake | Fix |
| --- | --- |
| Omitting `--platform linux/amd64` | Keep it on build and create, especially on Apple Silicon. |
| Omitting `--privileged` | Required for netns, veth, tc qdiscs, and eBPF attachment. |
| Dropping `psmisc` | `test/cli.bats` uses `killall`; without it the suite fails and can hang. |
| Running `bats test` directly | Use `xmake run test`. |
