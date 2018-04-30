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
    sudo hdiattach MEGAcmdSetup.dmg
    #sudo cp -R /Volumes/MEGAcmdSetup/MEGAcmd.app /Applications
    #PATH=$PATH:/Applications/MEGAcmd.app/
    export PATH=$PATH:/Volumes/MEGAcmdSetup/MEGAcmd.app/Contents/MacOS
fi

mega-login $MEGA_EMAIL $MEGA_PASSWORD
# removal may fail if not present
mega-rm $2 || true
mega-put $1 $2
