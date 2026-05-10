---
name: running-traffico-linux-tests
description: Use when working in the traffico repository and needing to run or verify Linux BATS, CNI, Scapy, network namespace, veth, tc, or eBPF tests from macOS or Apple Silicon Docker Desktop
---

# Running Traffico Linux Tests

## Overview

Traffico's full BATS suite needs a privileged Linux/AMD64 container. Use this Ubuntu 24.04 runner so CNI, Scapy, netns, veth, tc, and eBPF tests run with the same distro family as CI while xmake dependencies stay cached.

Ubuntu avoids the Arch/pacman sandbox override. The container still needs `--privileged` at runtime because the tests create network namespaces, veth pairs, tc qdiscs, and eBPF attachments.

## When To Use

- Running `xmake run test` for traffico from macOS or Apple Silicon
- Verifying PRs touching BATS, CNI fixtures, Scapy packets, tc attachment, netns, veth, or eBPF programs
- Re-running tests without rebuilding xmake packages

## Quick Reference

| Need | Command |
| --- | --- |
| Build image | `docker build --platform linux/amd64 -t traffico-ubuntu-test:latest -f /tmp/traffico-ubuntu-test.Dockerfile /tmp` |
| Create cache | `docker volume create traffico-ubuntu-xmake-cache` |
| Run tests | `docker start -ai traffico-ubuntu-test-runner` |
| Inspect runner | `docker ps -a --filter name=^/traffico-ubuntu-test-runner$` |

## Prerequisites

- Docker must be running.
- Docker must support privileged Linux/AMD64 containers.
- On Apple Silicon, keep `--platform linux/amd64`; BPF tooling and generated artifacts are verified through the AMD64 Linux path.

## Dockerfile

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

Keep the extra packages even when they look redundant with CI. A clean Ubuntu image is smaller than a GitHub-hosted runner, and xmake's dependency graph needs `g++`, archive tools, `m4`, `pkg-config`, Python build prerequisites, Scapy, and `killall` from `psmisc`.

## Setup

From the traffico repository root:

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

The container is persistent. After success it should remain as `Exited (0)` and can be started again.

## Recreate Runner

If the command, image, or mount needs to change, remove only the named container. Keep the image and `traffico-ubuntu-xmake-cache` volume unless intentionally forcing dependency rebuilds.

```sh
docker rm traffico-ubuntu-test-runner
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

## Common Mistakes

| Mistake | Fix |
| --- | --- |
| Omitting `--platform linux/amd64` | Keep it on build and create, especially on Apple Silicon. |
| Omitting `--privileged` | Required for netns, veth, tc qdiscs, and eBPF attachment. |
| Omitting `XMAKE_ROOT=y` | xmake refuses root execution without it. |
| Dropping `psmisc` | `test/cli.bats` uses `killall`; without it the suite fails and can hang. |
| Using a bare Ubuntu package set | Keep the package list above; clean Ubuntu lacks GitHub runner preinstalls. |
| Running `bats test` directly | Use `xmake run test`. |
| Reusing a failed cache after changing the image | Use a fresh volume or recreate the runner/cache deliberately. |
