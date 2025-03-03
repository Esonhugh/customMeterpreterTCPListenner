#!/bin/bash

cd /opt
git clone https://github.com/keystone-engine/keystone
cd keystone
apt install cmake build-essential
mkdir build
cd build
../make-share.sh
make install
ldconfig