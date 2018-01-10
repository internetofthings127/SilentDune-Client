#!/bin/bash

# Use this bash script to set Version information in all file locations. IE: setup.py

# Version numbers for RPMs and DEBs are set when the obs_build.prepare_for_rpm_build() and
# obs_build.prepare_for_deb_build() functions called during a Jenkins build, not here.

if [ $# -ne 1 ]; then
   echo "usage: bash-version.sh VERSION"
   exit 1
fi

# setup.py

FILE=$PWD/setup.py

if [ ! -e $FILE ]; then
   echo "error: setup.py not found. aborting."
   exit 1
fi

# setup.py
sed -i "s/^__VERSION__.*/__VERSION__ = \"$1\"/g" $FILE

