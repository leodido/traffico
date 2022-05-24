FROM docker.io/ubuntu:22.04

ARG XMAKE_VERSION
ENV XMAKE_VERSION=${XMAKE_VERSION:-2.6.4}
ENV XMAKE_ROOT=y

RUN apt update -y
RUN apt install sudo curl wget -y
RUN apt install nodejs npm -y
RUN apt install software-properties-common build-essential -y
RUN apt install clang-12 llvm-12 -y

RUN apt install linux-tools-5.15.0-30-generic  -y
RUN ln -sf /usr/lib/linux-tools/5.15.0-30-generic/bpftool /sbin/bpftool

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 100
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-12 100

RUN apt install 7zip unzip -y

# docker
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt update -y
RUN apt install docker-ce docker-ce-cli -y

# user setup
WORKDIR /tmp
RUN useradd -m -r -u 1000 vscode -s /bin/bash
RUN echo '%vscode ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER vscode

# xmake
RUN wget "https://github.com/xmake-io/xmake/releases/download/v${XMAKE_VERSION}/xmake-v${XMAKE_VERSION}.xz.run" \
    && chmod +x "xmake-v${XMAKE_VERSION}.xz.run" \
    && "./xmake-v${XMAKE_VERSION}.xz.run" \
    && rm -rf "xmake-v${XMAKE_VERSION}.xz.run"


