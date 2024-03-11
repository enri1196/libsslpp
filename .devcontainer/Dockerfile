FROM fedora:41

RUN dnf install -y clang clang-tools-extra meson wget llvm git unzip cmake

RUN wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.9.0.tar.gz \
    && tar -xf libressl-3.9.0.tar.gz && cd libressl-3.9.0 \
    && ./configure && make -j 8 && make install
