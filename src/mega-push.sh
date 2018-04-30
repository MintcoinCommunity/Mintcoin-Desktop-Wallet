#! /bin/bash

# This script pushes the binaries built to MEGA. This is useful for
# sending the result of a Travis CI build to a site where we can
# convert it into a package for release.

# Syntax:
#   bash mega-push.sh [exe_name] [name_on_mega]

# Display each command (for debugging)
set -x

# Exit on error
set -e


# Install MEGAcmd
if [ $TRAVIS_OS_NAME = linux ]; then
    if [ `lsb_release -is` = 'Ubuntu' ]; then
        if [ `lsb_release -cs` = 'trusty' ]; then
             PKG="megacmd-xUbuntu_14.04_amd64.deb"
             PKG_URL="https://mega.nz/linux/MEGAsync/xUbuntu_14.04/amd64/$PKG"
        fi
        wget $PKG_URL
        # package installation will fail because of dependencies - that's ok
        sudo dpkg -i $PKG || true
        sudo apt-get -y -f install
    fi
elif [ $TRAVIS_OS_NAME = osx ]; then
    wget https://mega.nz/MEGAcmdSetup.dmg
    sudo hdiutil attach MEGAcmdSetup.dmg
# debugging
    sudo ls -lR /Volumes/MEGAcmd
    sudo cp -R /Volumes/MEGAcmd/MEGAcmd.app /Applications/.
    sudo ls -lR /Applications/MEGAcmd.app
    export PATH=$PATH:/Applications/MEGAcmd.app/Contents/MacOS
    #export PATH=$PATH:/Volumes/MEGAcmd/MEGAcmd.app/Contents/MacOS
fi

# login to MEGA
mega-login $MEGA_EMAIL $MEGA_PASSWORD

# directory creation may fail if directory already present
mega-mkdir $TRAVIS_BRANCH || true

# removal may fail if not present
mega-rm $TRAVIS_BRANCH/$2 || true

# put our binary
mega-put $1 $TRAVIS_BRANCH/$2
