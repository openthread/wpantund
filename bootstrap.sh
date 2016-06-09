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

LOGFILE=`mktemp -q /tmp/bootstrap.log.XXXXXX`

die() {
	echo " ***************************** "
	cat "$LOGFILE"
	echo ""
	echo " *** $1 failed with error code $?"
	exit 1
}

cd "`dirname "$0"`"

which autoreconf 1>/dev/null 2>&1 || {
	echo " *** error: The 'autoreconf' command was not found."
	echo "Use the appropriate command for your platform to install the package:"
	echo ""
	echo "Homebrew(OS X) ....... brew install libtool autoconf autoconf-archive"
	echo "Debian/Ubuntu ........ apt-get install libtool autoconf autoconf-archive"
	exit 1
}

AUTOMAKE="automake --foreign" autoreconf --verbose --force --install 2>"$LOGFILE" || die autoreconf

grep -q AX_CHECK_ configure && {
	echo " *** error: The 'autoconf-archive' package is not installed."
	echo "Use the appropriate command for your platform to install the package:"
	echo ""
	echo "Homebrew(OS X) ....... brew install autoconf-archive"
	echo "Debian/Ubuntu ........ apt-get install autoconf-archive"
	exit 1
}

echo
echo Success. Logs in '"'$LOGFILE'"'
