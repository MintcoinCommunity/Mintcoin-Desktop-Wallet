#! /bin/bash

MXE_TARGET="i686-w64-mingw32.static"

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

MXEDIR=/usr/lib/mxe
export PATH=$PATH:$MXEDIR/usr/bin
make -f makefile.linux-mingw \
    DEPSDIR=$MXEDIR/usr/$MXE_TARGET TARGET_PLATFORM=i686
