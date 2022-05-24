                  _   _
                 | | | | o
 _|_  ,_    __,  | | | |     __   __
  |  /  |  /  |  |/  |/  |  /    /  \_
  |_/   |_/\_/|_/|__/|__/|_/\___/\__/
                 |\  |\
                 |/  |/

README

    traffico is ...

CONTACT

    If you have problems, question, ideas or suggestions, please contact us by
    posting to https://github.com/l13o/traffico/issues.

DOWNLOAD

    To download the very latest source do this:

    git clone https://github.com/l13o/traffico.git

BUILD

    To compile traffico from source you either provide your `vmlinux.h` in the
    `vmlinux/` directory (default option) or you configure the project to
    generate one from your current Linux kernel:

    xmake f --generate-vmlinux=y

    Now you will be able to build traffico from source by running:

    xmake

MAINTAINERS

    Leonardo Di Donato
    Lorenzo Fontana
