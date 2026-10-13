#!/usr/bin/env bash

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Its a Linux, but which one
        if [[ ! -z $(which yum) ]]; then
            yum install $YUM_PACKAGE_NAME
        elif [[ ! -z $(which apt-get) ]]; then
            sudo apt-get install pre-commit
        elif [[ ! -z $(which pacman) ]]; then
            sudo pacman -S pre-commit
        elif [[ ! -z $(which dnf) ]]; then
            sudo dnf install pre-commit
        elif [[ ! -z $(which zypper) ]]; then
            sudo zypper install pre-commit
        elif [[ ! -z $(which emerge) ]]; then
            sudo emerge -av pre-commit
        elif [[ ! -z $(which apk) ]]; then
            sudo apk add pre-commit
        elif [[ ! -z $(which pip) ]]; then
            pip install pre-commit --break-system-packages
        else
            echo "error can't install package $PACKAGE"
            exit 1;
        fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
        brew install pre-commit
elif [[ "$OSTYPE" == "cygwin" ]]; then
        # POSIX compatibility layer and Linux environment emulation for Windows
        pip install pre-commit --break-system-packages
elif [[ "$OSTYPE" == "msys" ]]; then
        # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
        pip install pre-commit --break-system-packages
elif [[ "$OSTYPE" == "freebsd"* ]]; then
        # ...
        echo "you've got BSD, figure it out"
else
        # Unknown.
        echo "Unknown OS type: $OSTYPE"
fi
pre-commit install
