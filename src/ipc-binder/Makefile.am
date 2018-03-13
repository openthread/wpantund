#
# Copyright (C) 2017 Nest Labs, Inc.
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
	-I$(top_srcdir)/src/ipc-binder \
	-I$(top_builddir)/src/ipc-binder \
	-I$(top_srcdir)/src/wpantund \
	-I$(top_srcdir)/third_party/assert-macros \
	$(NULL)

DISTCLEANFILES = .deps Makefile

AUTOMAKE_OPTIONS = subdir-objects

.aidl.cpp:
	$(AIDL_CPP) $(AIDL_CPP_FLAGS) $< $(builddir) $@

if BUILD_IPC_BINDER

noinst_LTLIBRARIES = libwpantund-binder.la libwpantund-binder-rtti.la

libwpantund_binder_la_SOURCES = \
	BinderIPCServer.cpp \
	BinderIPCServer.h \
	BinderILowpanInterface.cpp \
	BinderILowpanInterface.h \
	$(NULL)

libwpantund_binder_rtti_la_SOURCES = \
	BinderTypeGlue.cpp \
	BinderTypeGlue.h \
	$(NULL)

# We break this up into two convenience libraries
# because some files need to be compiled with RTTI
# and others not.
libwpantund_binder_la_CPPFLAGS = $(AM_CPPFLAGS) $(BINDER_CPPFLAGS) -Iframeworks/base/lowpan
libwpantund_binder_la_CXXFLAGS = $(BOOST_CXXFLAGS) $(BINDER_CXXFLAGS)
libwpantund_binder_la_LDFLAGS = -landroid_net_lowpan

libwpantund_binder_rtti_la_CPPFLAGS = $(AM_CPPFLAGS) $(BINDER_CPPFLAGS) -Iframeworks/base/lowpan
libwpantund_binder_rtti_la_CXXFLAGS = $(BOOST_CXXFLAGS) $(BINDER_CXXFLAGS) $(RTTI_CXXFLAGS)
libwpantund_binder_rtti_la_LDFLAGS = -landroid_net_lowpan

endif
