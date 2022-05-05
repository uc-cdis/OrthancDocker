#!/bin/bash

set -e
cd

URL=https://lsb.orthanc-server.com/
VERSION=debian-bullseye-python-3.9/mainline

wget ${URL}/plugin-python/${VERSION}/libOrthancPython.so

mv ./libOrthancPython.so  /usr/local/share/orthanc/plugins/
