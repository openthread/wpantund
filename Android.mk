#
# Copyright (c) 2018 Nest Labs, Inc.
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

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= wpantund
LOCAL_MODULE_TAGS := eng

LOCAL_C_INCLUDES                                         := \
	$(LOCAL_PATH)/include                                   \
	$(LOCAL_PATH)/src                                       \
	$(LOCAL_PATH)/src/util                                  \
	$(LOCAL_PATH)/src/ipc-dbus                              \
	$(LOCAL_PATH)/src/wpantund \
	$(LOCAL_PATH)/third_party/boost/ \
	$(LOCAL_PATH)/third_party/fgetln \
	$(LOCAL_PATH)/third_party/pt \
	$(LOCAL_PATH)/third_party/assert-macros \
	$(LOCAL_PATH)/third_party/openthread/src/ncp \
	$(NULL)

LOCAL_DEFAULT_VERSION := $(shell cat $(LOCAL_PATH)/.default-version)
LOCAL_PRIVATE_SOURCE_VERSION := $(shell git -C $(LOCAL_PATH) describe --always --match "[0-9].*" 2> /dev/null)
LOCAL_CFLAGS := \
	-DTUNNEL_TUNTAP_DEVICE=\"/dev/tun\" \
	-D_GNU_SOURCE \
	-D_XOPEN_SOURCE \
	-D_POSIX_C_SOURCE \
	-DHAVE_CLOCK_GETTIME=1 \
	-DHAVE_SYS_WAIT_H=1 \
	-DOPENTHREAD_ENABLE_NCP_SPINEL_ENCRYPTER=0 \
	-DPACKAGE=\"wpantund\" \
	-DPACKAGE_BUGREPORT=\"wpantund-devel@googlegroups.com\" \
	-DPACKAGE_NAME=\"wpantund\" \
	-DPACKAGE_STRING=\"wpantund\ $(LOCAL_DEFAULT_VERSION)\" \
	-DPACKAGE_TARNAME=\"wpantund\" \
	-DPACKAGE_URL=\"https://github.com/openthread/wpantund/\" \
	-DPACKAGE_VERSION=\"$(LOCAL_DEFAULT_VERSION)\" \
	-DPKGLIBEXECDIR=\"/usr/libexec/wpantund\" \
	-DPREFIX="" \
	-DSOURCE_VERSION=\"$(LOCAL_PRIVATE_SOURCE_VERSION)\" \
	-DSYSCONFDIR=\"/etc\" \
	-DTIME_WITH_SYS_TIME=1 \
	-DVERSION=\"$(LOCAL_DEFAULT_VERSION)\" \
	-DWPANTUND_DEFAULT_NCP_PLUGIN=\"spinel\" \
	-DWPANTUND_PLUGIN_STATICLY_LINKED=1 \
	-DWPANTUND_NCP_RESET_EXPECTED_ON_START=1 \
	$(NULL)

LOCAL_CPP_FEATURES := exceptions rtti

LOCAL_CPPFLAGS := \
	-DBOOST_NO_CXX11_VARIADIC_TEMPLATES -DBOOST_NO_CXX11_HDR_ARRAY -DBOOST_NO_CXX11_HDR_CODECVT -DBOOST_NO_CXX11_HDR_CONDITION_VARIABLE -DBOOST_NO_CXX11_HDR_FORWARD_LIST -DBOOST_NO_CXX11_HDR_INITIALIZER_LIST -DBOOST_NO_CXX11_HDR_MUTEX -DBOOST_NO_CXX11_HDR_RANDOM -DBOOST_NO_CXX11_HDR_RATIO -DBOOST_NO_CXX11_HDR_REGEX -DBOOST_NO_CXX11_HDR_SYSTEM_ERROR -DBOOST_NO_CXX11_HDR_THREAD -DBOOST_NO_CXX11_HDR_TUPLE -DBOOST_NO_CXX11_HDR_TYPEINDEX -DBOOST_NO_CXX11_HDR_UNORDERED_MAP -DBOOST_NO_CXX11_HDR_UNORDERED_SET -DBOOST_NO_CXX11_NUMERIC_LIMITS -DBOOST_NO_CXX11_ALLOCATOR -DBOOST_NO_CXX11_SMART_PTR -DBOOST_NO_CXX11_HDR_FUNCTIONAL -DBOOST_NO_CXX11_STD_ALIGN -DBOOST_NO_CXX11_ADDRESSOF -DBOOST_NO_CXX11_DECLTYPE_N3276 -Wp,-w \
	-fexceptions \
	-frtti \
	$(NULL)

LOCAL_LDFLAGS := \
	$(NULL)

$(LOCAL_PATH)/src/version.c: $(LOCAL_PATH)/src/version.c.in
	sed 's/SOURCE_VERSION/"$(LOCAL_PRIVATE_SOURCE_VERSION)"/' < $< > $@

NCP_SPINEL_SRC_FILES := $(wildcard $(LOCAL_PATH)/src/ncp-spinel/*.cpp) $(wildcard $(LOCAL_PATH)/src/ncp-spinel/*.c)

LOCAL_SRC_FILES := \
	src/ipc-dbus/DBUSIPCServer.cpp \
	src/ipc-dbus/DBusIPCAPI_v0.cpp \
	src/ipc-dbus/DBusIPCAPI_v1.cpp \
	src/util/DBUSHelpers.cpp \
	src/version.c \
	src/wpantund/wpantund.cpp \
	src/wpantund/NCPControlInterface.cpp \
	src/wpantund/NCPInstance.cpp \
	src/wpantund/NCPInstanceBase.cpp \
	src/wpantund/FirmwareUpgrade.cpp \
	src/wpantund/StatCollector.cpp \
	src/wpantund/RunawayResetBackoffManager.cpp \
	src/wpantund/NCPInstanceBase-NetInterface.cpp \
	src/wpantund/NCPInstanceBase-Addresses.cpp \
	src/wpantund/NCPInstanceBase-AsyncIO.cpp \
	src/wpantund/NCPTypes.cpp \
	src/wpantund/NetworkRetain.cpp \
	src/wpantund/Pcap.cpp \
	src/wpantund/wpan-error.c \
	src/util/IPv6PacketMatcher.cpp \
	src/util/IPv6Helpers.cpp \
	src/util/tunnel.c \
	src/util/netif-mgmt.c \
	src/util/config-file.c \
	src/util/socket-utils.c \
	src/util/any-to.cpp \
	src/util/string-utils.c \
	src/util/time-utils.c \
	src/util/nlpt-select.c \
	src/util/Data.cpp \
	src/util/SocketWrapper.cpp \
	src/util/SocketAdapter.cpp \
	src/util/UnixSocket.cpp \
	src/util/SuperSocket.cpp \
	src/util/EventHandler.cpp \
	src/util/TunnelIPv6Interface.cpp \
	src/util/ValueMap.cpp \
	src/util/Timer.cpp \
	src/util/sec-random.c \
	src/missing/strlcpy/strlcpy.c \
	$(NCP_SPINEL_SRC_FILES:$(LOCAL_PATH)/%=%) \
	third_party/openthread/src/ncp/spinel.c \
	$(NULL)

LOCAL_SHARED_LIBRARIES := libdbus

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE:= wpanctl
LOCAL_MODULE_TAGS := eng

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/src \
	$(LOCAL_PATH)/src/ipc-dbus \
	$(LOCAL_PATH)/src/util \
	$(LOCAL_PATH)/src/wpanctl \
	$(LOCAL_PATH)/src/wpantund \
	$(LOCAL_PATH)/third_party/fgetln \
	$(LOCAL_PATH)/third_party/assert-macros \
	$(NULL)

LOCAL_DEFAULT_VERSION := $(shell cat $(LOCAL_PATH)/.default-version)
LOCAL_PRIVATE_SOURCE_VERSION := $(shell git -C $(LOCAL_PATH) describe --always --match "[0-9].*" 2> /dev/null)

LOCAL_CFLAGS := \
	-D_GNU_SOURCE \
	-D_XOPEN_SOURCE \
	-D_POSIX_C_SOURCE \
	-DHAVE_SYS_WAIT_H=1 \
	-DOPENTHREAD_ENABLE_NCP_SPINEL_ENCRYPTER=0 \
	-DPACKAGE=\"wpantund\" \
	-DPACKAGE_BUGREPORT=\"wpantund-devel@googlegroups.com\" \
	-DPACKAGE_NAME=\"wpantund\" \
	-DPACKAGE_STRING=\"wpantund\ $(LOCAL_DEFAULT_VERSION)\" \
	-DPACKAGE_TARNAME=\"wpantund\" \
	-DPACKAGE_URL=\"https://github.com/openthread/wpantund/\" \
	-DPACKAGE_VERSION=\"$(LOCAL_DEFAULT_VERSION)\" \
	-DPKGLIBEXECDIR=\"/usr/libexec/wpantund\" \
	-DPREFIX="" \
	-DSOURCE_VERSION=\"$(LOCAL_PRIVATE_SOURCE_VERSION)\" \
	-DSYSCONFDIR=\"/etc\" \
	-DTIME_WITH_SYS_TIME=1 \
	-DVERSION=\"$(LOCAL_DEFAULT_VERSION)\" \
	-DWPANTUND_DEFAULT_NCP_PLUGIN=\"spinel\" \
	-DWPANTUND_PLUGIN_STATICLY_LINKED=1 \
	$(NULL)

LOCAL_CPP_FEATURES := exceptions

LOCAL_CPPFLAGS := \
	-DBOOST_NO_CXX11_VARIADIC_TEMPLATES -DBOOST_NO_CXX11_HDR_ARRAY -DBOOST_NO_CXX11_HDR_CODECVT -DBOOST_NO_CXX11_HDR_CONDITION_VARIABLE -DBOOST_NO_CXX11_HDR_FORWARD_LIST -DBOOST_NO_CXX11_HDR_INITIALIZER_LIST -DBOOST_NO_CXX11_HDR_MUTEX -DBOOST_NO_CXX11_HDR_RANDOM -DBOOST_NO_CXX11_HDR_RATIO -DBOOST_NO_CXX11_HDR_REGEX -DBOOST_NO_CXX11_HDR_SYSTEM_ERROR -DBOOST_NO_CXX11_HDR_THREAD -DBOOST_NO_CXX11_HDR_TUPLE -DBOOST_NO_CXX11_HDR_TYPEINDEX -DBOOST_NO_CXX11_HDR_UNORDERED_MAP -DBOOST_NO_CXX11_HDR_UNORDERED_SET -DBOOST_NO_CXX11_NUMERIC_LIMITS -DBOOST_NO_CXX11_ALLOCATOR -DBOOST_NO_CXX11_SMART_PTR -DBOOST_NO_CXX11_HDR_FUNCTIONAL -DBOOST_NO_CXX11_STD_ALIGN -DBOOST_NO_CXX11_ADDRESSOF -DBOOST_NO_CXX11_DECLTYPE_N3276 -Wp,-w \
	-fexceptions \
	-frtti \
	$(NULL)

WPANCTL_SRC_FILES := $(wildcard $(LOCAL_PATH)/src/wpanctl/*.c)
LOCAL_SRC_FILES := \
	src/version.c \
	src/util/config-file.c \
	src/util/string-utils.c \
	src/wpantund/wpan-error.c \
	$(WPANCTL_SRC_FILES:$(LOCAL_PATH)/%=%) \
	$(NULL)

LOCAL_SHARED_LIBRARIES := libdbus
include $(BUILD_EXECUTABLE)
