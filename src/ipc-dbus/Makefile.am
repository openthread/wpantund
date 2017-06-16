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

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/ipc-dbus \
	-I$(top_srcdir)/src/wpantund \
	-I$(top_srcdir)/third_party/assert-macros \
	$(NULL)

EXTRA_DIST = wpantund.conf

DISTCLEANFILES = .deps Makefile

AUTOMAKE_OPTIONS = subdir-objects

dbusconfdir = $(DBUS_CONFDIR)

dbusconf_DATA = wpantund.conf

noinst_LTLIBRARIES = libwpantund-dbus.la

libwpantund_dbus_la_SOURCES = \
	DBUSIPCServer.cpp \
	DBUSIPCServer.h \
	DBusIPCAPI_v1.cpp \
	DBusIPCAPI_v1.h \
	wpan-dbus-v1.h \
	DBusIPCAPI_v0.cpp \
	DBusIPCAPI_v0.h \
	wpan-dbus-v0.h \
	../util/DBUSHelpers.cpp \
	$(NULL)

libwpantund_dbus_la_LIBADD =  $(DBUS_LIBS)
libwpantund_dbus_la_CPPFLAGS = $(AM_CPPFLAGS) $(DBUS_CFLAGS)
libwpantund_dbus_la_CXXFLAGS = $(BOOST_CXXFLAGS)

pkginclude_HEADERS = wpan-dbus-v0.h wpan-dbus-v1.h

if USE_PCH
BUILT_SOURCES  = $(top_builddir)/$(subdir)/ipc-dbus-all$(PCH_EXT)
CLEANFILES     = $(top_builddir)/$(subdir)/ipc-dbus-all$(PCH_EXT) $(top_builddir)/$(subdir)/ipc-dbus-all.h
$(top_builddir)/$(subdir)/ipc-dbus-all.h: Makefile
	find `dirname $@` -name '*.cpp' \
		| xargs -n 1 grep '^#include' \
		| grep -v -e 'version' -e 'sigcontext' -e 'wpantund\.cpp' \
		| awk '{printf "%s\t%d\n", $$0, NR }' \
		| sort -t'	' -k1,1 -u \
		| sort -t'	' -k2,2 -n \
		| cut -d'	' -f 1 > $@

$(top_builddir)/$(subdir)/ipc-dbus-all$(PCH_EXT): $(top_builddir)/$(subdir)/ipc-dbus-all.h Makefile
	$(AM_V_CXX)$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(libwpantund_dbus_la_CPPFLAGS) $(CPPFLAGS) $(BOOST_CXXFLAGS) $(CODE_COVERAGE_CXXFLAGS) $(CXXFLAGS) -fPIC -DPIC $(CXX_PCH_INPUT_FLAG) $< -o $@

libwpantund_dbus_la_CXXFLAGS += $(CXX_PCH_INCLUDE_FLAG) $(top_builddir)/$(subdir)/ipc-dbus-all$(PCH_INCLUDE_EXT)
endif # if USE_PCH
