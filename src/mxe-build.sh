#! /bin/bash

if [ $1 == "windows32" ]; then
    MXE_TARGET="i686-w64-mingw32.static"
    CPU_TARGET="i686"
    QT_BUILD="no"
elif [ $1 == "windows64" ]; then
    MXE_TARGET="x86-64-w64-mingw32.static"
    CPU_TARGET="x86_64"
    QT_BUILD="no"
elif [ $1 == "windows32-qt" ]; then
    MXE_TARGET="i686-w64-mingw32.static"
    CPU_TARGET="i686"
    QT_BUILD="yes"
elif [ $1 == "windows64-qt" ]; then
    MXE_TARGET="x86-64-w64-mingw32.static"
    CPU_TARGET="x86_64"
    QT_BUILD="yes"
else
    echo "Syntax: $0 [ windows32 | windows64 | windows32-qt | windows64-qt ]">&2
    exit 1
fi

MXEDIR=/usr/lib/mxe

NCPU=`cat /proc/cpuinfo | grep -c ^processor`

sudo apt-get update

echo "deb http://pkg.mxe.cc/repos/apt/debian wheezy main" \
    | sudo tee /etc/apt/sources.list.d/mxeapt.list
sudo apt-key adv --keyserver keyserver.ubuntu.com \
    --recv-keys D43A795B73B16ABE9643FE1AFD8FFF16DB45C6AB

sudo apt-get update

sudo apt-get --yes install mxe-${MXE_TARGET}-cc
sudo apt-get --yes install mxe-${MXE_TARGET}-openssl
sudo apt-get --yes install mxe-${MXE_TARGET}-db
sudo apt-get --yes install mxe-${MXE_TARGET}-boost
sudo apt-get --yes install mxe-${MXE_TARGET}-miniupnpc

if [ $QT_BUILD == "no" ]; then
    cd src
    export PATH=$PATH:$MXEDIR/usr/bin
    make -f makefile.linux-mingw -j $NCPU \
        DEPSDIR=$MXEDIR/usr/$MXE_TARGET TARGET_PLATFORM=$CPU_TARGET
else
    $MXEDIR/usr/bin/$CPU_TARGET-w64-mingw32.static-qmake-qt5
    sudo apt-get --yes install mxe-${MXE_TARGET}-qt
    sudo apt-get --yes install mxe-${MXE_TARGET}-qttools
    qmake
    make -j $NCPU
fi
