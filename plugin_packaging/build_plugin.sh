#!/bin/bash

current=`pwd`
mkdir -p /tmp/linkSHARK/
cp -R ../linkSHARK /tmp/linkSHARK/
cp ../setup.py /tmp/linkSHARK/
cp ../main.py /tmp/linkSHARK/
cp * /tmp/linkSHARK/
cd /tmp/linkSHARK/

tar -cvf "$current/linkSHARK_plugin.tar" --exclude=*.tar --exclude=build_plugin.sh --exclude=*/tests --exclude=*/__pycache__ --exclude=*.pyc *
