FROM docker.io/archlinux:latest

RUN pacman -Syy --noconfirm
RUN pacman -S --noconfirm nodejs clang llvm gcc linux-headers bpf unzip docker vi vim

RUN pacman -S --noconfirm --needed git base-devel



# user setup
WORKDIR /tmp
RUN useradd -m -r -u 1000 vscode -s /bin/bash
RUN echo '%vscode ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER vscode

RUN git clone https://aur.archlinux.org/yay.git && cd yay && makepkg --noconfirm -si
RUN yay --noconfirm -S xmake
