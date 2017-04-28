#
# Copyright (c) 2017 Nest Labs, Inc.
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

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/ipc-dbus \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/wpanctl \
	-I$(top_srcdir)/src/wpantund \
	-I$(top_srcdir)/third_party/assert-macros \
	-I$(top_srcdir)/third_party/openthread/src/ncp \
	$(NULL)

DISTCLEANFILES = .deps Makefile

lib_LTLIBRARIES = libbap.la

libbap_la_SOURCES = \
	../wpanctl/wpanctl-utils.c \
	bap.cpp \
	bap.h \
	bap-utils.h \
	$(NULL)

libbap_la_LIBADD = \
	$(DBUS_LIBS) \
	$(NULL)

libbap_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(DBUS_CFLAGS) \
	$(LIBREADLINE_CPPFLAGS) \
	$(NULL)


SOURCE_VERSION=$(shell git describe --dirty --always --match "[0-9].*" 2> /dev/null)
BUILT_SOURCES  = version.c
CLEANFILES = version.c
.INTERMEDIATE: libbap_la-version.$(OBJEXT)
version.c: ../version.c.in Makefile
	sed 's/SOURCE_VERSION/"$(SOURCE_VERSION)"/' < $< > $@
libbap_la_SOURCES += version.c
