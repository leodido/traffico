# Arch Runner Fallback

Use this fallback only when the Ubuntu runner in `SKILL.md` cannot be built or run, an existing Arch runner/cache is already available and known good, or Arch-specific package/build behavior must be reproduced.

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

`DisableSandbox` avoids pacman failures under Docker Desktop AMD64 emulation where pacman can fail with seccomp or `switching to sandbox user 'alpm' failed` errors. `XMAKE_ROOT=y` allows xmake to run as root inside the container.

## Build Image

From the traffico repository root:

```sh
docker build \
  --platform linux/amd64 \
  -t traffico-arch-test:latest \
  -f /tmp/traffico-arch-test.Dockerfile \
  /tmp
```

Use `--platform linux/amd64` on Apple Silicon and ARM64 Docker Desktop. The BPF tooling and generated artifacts are verified through the AMD64 Linux path; Arch may not provide the required ARM64 image path for this runner.

## Xmake Cache

Create the cache volume once:

```sh
docker volume create traffico-xmake-cache
```

Mount it at `/root/.xmake` because the runner executes as root and xmake installs package dependencies there. Keep this volume across runner recreation to avoid rebuilding BATS, mini_httpd, cJSON, elfutils, libbpf, ninja, CMake, and related packages.

## Persistent Runner

Create the runner once from the traffico repository root:

```sh
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

`--privileged` is required because the suite creates network namespaces, veth pairs, tc qdiscs, and eBPF attachments. The bind mount keeps the runner on the live working tree.

Run or rerun:

```sh
docker start -ai traffico-arch-test-runner
```

The runner is persistent. After a successful run it should remain as `Exited (0)` and can be started again.

## Recreate Runner

If the runner command, image, or mount needs to change, remove and recreate only the named container. Keep the image and cache volume unless intentionally forcing a full xmake dependency rebuild.

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
