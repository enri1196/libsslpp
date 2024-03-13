FROM fedora:41

RUN dnf install -y clang clang-tools-extra meson wget llvm git unzip cmake zsh

RUN chsh -s /usr/bin/zsh

RUN sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --keep-zshrc

RUN wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.9.0.tar.gz \
    && tar -xf libressl-3.9.0.tar.gz && cd libressl-3.9.0 \
    && ./configure && make -j 8 && make install
