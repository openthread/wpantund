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
	-I$(top_srcdir)/src/ncp-spinel \
	-I$(top_srcdir)/src/wpantund \
	-I$(top_srcdir)/third_party/pt \
	-I$(top_srcdir)/third_party/assert-macros \
	-I$(top_srcdir)/third_party/openthread/src/ncp \
	$(NULL)

DISTCLEANFILES = \
	.deps \
	Makefile \
	$(NULL)

EXTRA_DIST =                                         \
	../../third_party/openthread/CONTRIBUTING.md     \
	../../third_party/openthread/LICENSE             \
	../../third_party/openthread/NOTICE              \
	../../third_party/openthread/README.google       \
	../../third_party/openthread/README.md           \
	../../third_party/openthread/src/ncp/PROTOCOL.md \
	../../third_party/openthread/src/ncp/spinel.c    \
	../../third_party/openthread/src/ncp/spinel.h    \
	../../third_party/openthread/tools/spi-hdlc-adapter/README.md          \
	../../third_party/openthread/tools/spi-hdlc-adapter/spi-hdlc-adapter.c \
	$(NULL)

if BUILD_PLUGIN_NCP_SPINEL

if HOST_IS_LINUX
bin_PROGRAMS = spi-hdlc-adapter
spi_hdlc_adapter_SOURCES = ../../third_party/openthread/tools/spi-hdlc-adapter/spi-hdlc-adapter.c
endif

# Work around the omnipotent automake nanny-state.
mypkglibexecdir = $(pkglibexecdir)

NCP_SOURCES = \
	SpinelNCPControlInterface.cpp \
	SpinelNCPControlInterface.h \
	SpinelNCPInstance.cpp \
	SpinelNCPInstance.h \
	SpinelNCPInstance-DataPump.cpp \
	SpinelNCPInstance-Protothreads.cpp \
	SpinelNCPTask.cpp \
	SpinelNCPTask.h \
	SpinelNCPTaskDeepSleep.cpp \
	SpinelNCPTaskGetNetworkTopology.h \
	SpinelNCPTaskGetNetworkTopology.cpp \
	SpinelNCPTaskGetMsgBufferCounters.h \
	SpinelNCPTaskGetMsgBufferCounters.cpp \
	SpinelNCPTaskDeepSleep.h \
	SpinelNCPTaskForm.cpp \
	SpinelNCPTaskForm.h \
	SpinelNCPTaskJoin.cpp \
	SpinelNCPTaskJoin.h \
	SpinelNCPTaskLeave.cpp \
	SpinelNCPTaskLeave.h \
	SpinelNCPTaskScan.cpp \
	SpinelNCPTaskScan.h \
	SpinelNCPTaskSendCommand.cpp \
	SpinelNCPTaskSendCommand.h \
	SpinelNCPTaskWake.cpp \
	SpinelNCPTaskWake.h \
	$(top_srcdir)/third_party/openthread/src/ncp/spinel.c \
	spinel-extra.c \
	spinel-extra.h \
	$(NULL)


if STATIC_LINK_NCP_PLUGIN
noinst_LTLIBRARIES = libncp-spinel.la
libncp_spinel_la_SOURCES = $(NCP_SOURCES)
libncp_spinel_la_CXXFLAGS = @BOOST_CXXFLAGS@
else
mypkglibexec_LTLIBRARIES = ncp-spinel.la
ncp_spinel_la_LDFLAGS = -module -avoid-version -shared
ncp_spinel_la_SOURCES = $(NCP_SOURCES)
ncp_spinel_la_CXXFLAGS = @BOOST_CXXFLAGS@
endif


if USE_PCH
BUILT_SOURCES  = $(top_builddir)/$(subdir)/ncp-spinel-all$(PCH_EXT)
CLEANFILES     = $(top_builddir)/$(subdir)/ncp-spinel-all$(PCH_EXT) $(top_builddir)/$(subdir)/ncp-spinel-all.h
$(top_builddir)/$(subdir)/ncp-spinel-all.h: Makefile
	find `dirname $@` -name '*.cpp' \
		| xargs -n 1 grep '^#include' \
		| grep -v -e 'version' -e 'sigcontext' -e 'wpantund\.cpp' \
		| awk '{printf "%s\t%d\n", $$0, NR }' \
		| sort -t'	' -k1,1 -u \
		| sort -t'	' -k2,2 -n \
		| cut -d'	' -f 1 > $@

$(top_builddir)/$(subdir)/ncp-spinel-all$(PCH_EXT): $(top_builddir)/$(subdir)/ncp-spinel-all.h Makefile
	$(AM_V_CXX)$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(BOOST_CXXFLAGS) $(CODE_COVERAGE_CXXFLAGS) $(CODE_COVERAGE_CPPFLAGS) -fPIC -DPIC $(CXX_PCH_INPUT_FLAG) $< -o $@

if STATIC_LINK_NCP_PLUGIN
libncp_spinel_la_CXXFLAGS += $(CXX_PCH_INCLUDE_FLAG) $(top_builddir)/$(subdir)/ncp-spinel-all$(PCH_INCLUDE_EXT)
else
ncp_spinel_la_CXXFLAGS += $(CXX_PCH_INCLUDE_FLAG) $(top_builddir)/$(subdir)/ncp-spinel-all$(PCH_INCLUDE_EXT)
endif
endif # if USE_PCH


endif #BUILD_PLUGIN_NCP_SPINEL
