#!/bin/sh
#
# Copyright (c) 2016 Nest Labs, Inc.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

die() {
	echo " *** ERROR: " $*
	exit 1
}

set -x

[ $TRAVIS_OS_NAME != linux ] || {
	wget https://gist.github.com/darconeous/d1d9bc39e0758e45a1d7/raw/ef9b01ac378a9b2e92031c846c4f6b5f94abab53/connman-include.tar.bz2 || die
	sudo tar xvjf connman-include.tar.bz2 -C / || die
}

[ $BUILD_TARGET != android-build ] || {
	sudo apt-get install -y gcc-multilib g++-multilib
    (
    cd $HOME
    wget https://dl.google.com/android/repository/android-ndk-r17c-linux-x86_64.zip
    unzip android-ndk-r17c-linux-x86_64.zip > /dev/null
    mv android-ndk-r17c ndk-bundle
    )
}

[ $TRAVIS_OS_NAME != osx ] || {
	brew install d-bus
	brew install autoconf-archive
	brew install libtool
	brew install gnu-sed
}
