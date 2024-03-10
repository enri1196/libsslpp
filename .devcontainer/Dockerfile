FROM fedora:41

RUN dnf install -y clang clang-tools-extra meson wget llvm git unzip

RUN wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.7.0.tar.gz \
    && tar -xf libressl-3.7.0.tar.gz && cd libressl-3.7.0 \
    && ./configure && make -j 8 && make install
