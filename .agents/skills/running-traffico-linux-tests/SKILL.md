---
name: running-traffico-linux-tests
description: Use when working in the traffico repository and needing to run or verify Linux BATS, CNI, Scapy, network namespace, veth, tc, or eBPF tests from macOS or Apple Silicon Docker Desktop
---

# Running Traffico Linux Tests

## Overview

Traffico's full BATS suite needs a privileged Linux/AMD64 Arch container. Use this runner so CNI, Scapy, netns, veth, tc, and eBPF tests run with expected packages while xmake stays cached.

## When To Use

- Running `xmake run test` for traffico from macOS or Apple Silicon
- Verifying PRs touching BATS, CNI fixtures, Scapy packets, tc attachment, netns, veth, or eBPF programs
- Re-running tests without rebuilding packages

Do not substitute Ubuntu or direct `bats test`; this runner depends on Arch packages and xmake-managed dependencies.

## Quick Reference

| Need | Command |
| --- | --- |
| Build image | `docker build --platform linux/amd64 -t traffico-arch-test:latest -f /tmp/traffico-arch-test.Dockerfile /tmp` |
| Create cache | `docker volume create traffico-xmake-cache` |
| Run tests | `docker start -ai traffico-arch-test-runner` |
| Inspect runner | `docker ps -a --filter name=^/traffico-arch-test-runner$` |

## Prerequisites

- Docker must be running.
- Docker must support privileged Linux/AMD64 containers.
- On Apple Silicon, keep `--platform linux/amd64`; BPF tooling and generated artifacts are verified through the AMD64 Linux path.

## Dockerfile

Create `/tmp/traffico-arch-test.Dockerfile`:

```Dockerfile
FROM --platform=linux/amd64 docker.io/library/archlinux:latest

ENV XMAKE_ROOT=y

RUN sed -i 's/^#DisableSandbox/DisableSandbox/' /etc/pacman.conf \
    && pacman -Syy --noconfirm \
    && pacman -S --noconfirm \
        clang llvm gcc linux-headers bpf \
        make cmake xmake sudo diffutils \
        curl iproute2 iputils \
        python-scapy git base-devel unzip \
    && pacman -Scc --noconfirm

WORKDIR /workspaces/traffico
```

`DisableSandbox` avoids pacman seccomp failures under Docker Desktop AMD64 emulation. `XMAKE_ROOT=y` matches CI.

## Setup

From the traffico repository root:

```sh
docker build \
  --platform linux/amd64 \
  -t traffico-arch-test:latest \
  -f /tmp/traffico-arch-test.Dockerfile \
  /tmp

docker volume create traffico-xmake-cache

docker create \
  --platform linux/amd64 \
  --privileged \
  --name traffico-arch-test-runner \
  -v "$PWD:/workspaces/traffico" \
  -v traffico-xmake-cache:/root/.xmake \
  -w /workspaces/traffico \
  traffico-arch-test:latest \
  bash -lc 'xmake f -c -y --generate-vmlinux=y && xmake build -y && xmake run test'
```

Run or rerun:

```sh
docker start -ai traffico-arch-test-runner
```

The container is persistent. After success it should remain as `Exited (0)` and can be started again.

## Recreate Runner

If the command or mount needs to change, remove only the named container. Keep the image and `traffico-xmake-cache` volume.

```sh
docker rm traffico-arch-test-runner
docker create \
  --platform linux/amd64 \
  --privileged \
  --name traffico-arch-test-runner \
  -v "$PWD:/workspaces/traffico" \
  -v traffico-xmake-cache:/root/.xmake \
  -w /workspaces/traffico \
  traffico-arch-test:latest \
  bash -lc 'xmake f -c -y --generate-vmlinux=y && xmake build -y && xmake run test'
```

## Common Mistakes

| Mistake | Fix |
| --- | --- |
| Using Ubuntu and `apt` | Use the Arch image above. |
| Running `bats test` directly | Use `xmake run test`. |
| Omitting `--platform linux/amd64` | Keep it on build and create, especially on Apple Silicon. |
| Omitting `--privileged` | Required for netns, veth, tc qdiscs, and eBPF attachment. |
| Removing `traffico-xmake-cache` | Keep it unless intentionally forcing dependency rebuilds. |
| Skipping `xmake f -c` on a new volume | Clean configure prevents stale package metadata paths. |
