# Cross-Compiling the MintCoin wallet for Windows 

This document explains how to build Windows binaries from a Linux
system.

# Starting system

Have a Debian or Debian-derived system, like Ubuntu or Mint Linux.

# Install MXE requirements

http://mxe.cc/#requirements-debian

```
apt-get install \
    autoconf \
    automake \
    autopoint \
    bash \
    bison \
    bzip2 \
    flex \
    g++ \
    g++-multilib \
    gettext \
    git \
    gperf \
    intltool \
    libc6-dev-i386 \
    libgdk-pixbuf2.0-dev \
    libltdl-dev \
    libssl-dev \
    libtool-bin \
    libxml-parser-perl \
    make \
    openssl \
    p7zip-full \
    patch \
    perl \
    pkg-config \
    python \
    ruby \
    scons \
    sed \
    unzip \
    wget \
    xz-utils
```

# Get MXE

Download from:

http://mxe.cc/#download

This "download" is actually just cloning a Git directory.

# Build MXE

Add `MXE_TARGETS` so that we get both 64-bit and 32-bit Windows binaries.

```
$ make MXE_TARGETS='x86_64-w64-mingw32.static i686-w64-mingw32.static' cc
$ make MXE_TARGETS='x86_64-w64-mingw32.static i686-w64-mingw32.static' openssl
$ make MXE_TARGETS='x86_64-w64-mingw32.static i686-w64-mingw32.static' db
$ make MXE_TARGETS='x86_64-w64-mingw32.static i686-w64-mingw32.static' boost
$ make MXE_TARGETS='x86_64-w64-mingw32.static i686-w64-mingw32.static' miniupnpc
$ make MXE_TARGETS='x86_64-w64-mingw32.static i686-w64-mingw32.static' qt
$ make MXE_TARGETS='x86_64-w64-mingw32.static i686-w64-mingw32.static' qttools
```

# Build Windows executables

Add the path to MXE plus `usr/bin` to your `PATH`:

`$ export PATH=$PATH:`_/your/mxe/path_`/usr/bin`

To make a 32-bit Windows executable, go to the MintCoin repository
and use the following:

```
$ cd src
$ make -f makefile.linux-mingw TARGET_PLATFORM=i686
```

To make a 64-bit Windows executable, go to the MintCoin repository
and use the following:

$ make -f makefile.linux-mingw TARGET_PLATFORM=x86_64
```

Either will create a file called `mintcoind.exe`, which should be
usable on a 32-bit or 64-bit Windows system, respectively.


# Build Windows Qt executables

To make a 32-bit Windows GUI executable, go to the MintCoin repository
and use the following:

```
$ i686-w64-mingw32.static-qmake-qt5
$ make
```

To make a 64-bit Windows GUI executable, go to the MintCoin repository
and use the following:

```
$ x86_64-w64-mingw32.static-qmake-qt5
$ make
```

Either will create a file called `release/MintCoin-Qt.exe`, which
should be usable on a 32-bit or 64-bit Windows system, respectively.
