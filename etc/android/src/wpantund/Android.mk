# File automatically generated by autoandr 0.00.01
# "src/wpantund"
#

LOCAL_PATH := $(call my-dir)

#### BEGIN wpantund ####
include $(CLEAR_VARS)
LOCAL_MODULE := wpantund
LOCAL_STATIC_LIBRARIES += libwpantund-binder
LOCAL_STATIC_LIBRARIES += libwpantund-binder-rtti
LOCAL_STATIC_LIBRARIES += libncp-spinel
LOCAL_CFLAGS += -DHAVE_CONFIG_H
LOCAL_CFLAGS += -O2
LOCAL_CFLAGS += -Wno-date-time
LOCAL_CFLAGS += -Wno-missing-field-initializers
LOCAL_CFLAGS += -Wno-sign-compare
LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_ADDRESSOF
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_ALLOCATOR
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_DECLTYPE_N3276
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_ARRAY
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_CODECVT
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_CONDITION_VARIABLE
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_FORWARD_LIST
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_FUNCTIONAL
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_INITIALIZER_LIST
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_MUTEX
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_RANDOM
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_RATIO
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_REGEX
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_SYSTEM_ERROR
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_THREAD
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_TUPLE
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_TYPEINDEX
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_UNORDERED_MAP
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_HDR_UNORDERED_SET
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_NUMERIC_LIMITS
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_SMART_PTR
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_STD_ALIGN
LOCAL_CPPFLAGS += -DBOOST_NO_CXX11_VARIADIC_TEMPLATES
LOCAL_CPPFLAGS += -DHAVE_CONFIG_H
LOCAL_CPPFLAGS += -Wno-c++11-narrowing
LOCAL_CPPFLAGS += -Wno-date-time
LOCAL_CPPFLAGS += -Wno-missing-field-initializers
LOCAL_CPPFLAGS += -Wno-non-virtual-dtor
LOCAL_CPPFLAGS += -Wno-sign-compare
LOCAL_CPPFLAGS += -Wno-unused-parameter
LOCAL_CPPFLAGS += -Wp,-w
LOCAL_CPPFLAGS += -fexceptions
LOCAL_CPPFLAGS += -frtti
LOCAL_CPPFLAGS += -std=gnu++11
LOCAL_CPP_FEATURES +=
LOCAL_C_INCLUDES += $(LOCAL_PATH)/.
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../src
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../src/ipc-binder
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../src/ipc-dbus
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../src/util
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../src/wpantund
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../third_party/assert-macros
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../third_party/boost
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../third_party/fgetln
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../../third_party/pt
LOCAL_C_INCLUDES += system/core/base/include
LOCAL_MODULE_TAGS += optional
LOCAL_SHARED_LIBRARIES += libandroid_net_lowpan
LOCAL_SHARED_LIBRARIES += libbase
LOCAL_SHARED_LIBRARIES += libbinder
LOCAL_SHARED_LIBRARIES += liblog
LOCAL_SHARED_LIBRARIES += libutils
LOCAL_SRC_FILES += ../../../../src/util/Data.cpp
LOCAL_SRC_FILES += ../../../../src/util/EventHandler.cpp
LOCAL_SRC_FILES += ../../../../src/util/IPv6Helpers.cpp
LOCAL_SRC_FILES += ../../../../src/util/IPv6PacketMatcher.cpp
LOCAL_SRC_FILES += ../../../../src/util/SocketAdapter.cpp
LOCAL_SRC_FILES += ../../../../src/util/SocketWrapper.cpp
LOCAL_SRC_FILES += ../../../../src/util/SuperSocket.cpp
LOCAL_SRC_FILES += ../../../../src/util/Timer.cpp
LOCAL_SRC_FILES += ../../../../src/util/TunnelIPv6Interface.cpp
LOCAL_SRC_FILES += ../../../../src/util/UnixSocket.cpp
LOCAL_SRC_FILES += ../../../../src/util/ValueMap.cpp
LOCAL_SRC_FILES += ../../../../src/util/any-to.cpp
LOCAL_SRC_FILES += ../../../../src/util/config-file.c
LOCAL_SRC_FILES += ../../../../src/util/netif-mgmt.c
LOCAL_SRC_FILES += ../../../../src/util/nlpt-select.c
LOCAL_SRC_FILES += ../../../../src/util/sec-random.c
LOCAL_SRC_FILES += ../../../../src/util/socket-utils.c
LOCAL_SRC_FILES += ../../../../src/util/string-utils.c
LOCAL_SRC_FILES += ../../../../src/util/time-utils.c
LOCAL_SRC_FILES += ../../../../src/util/tunnel.c
LOCAL_SRC_FILES += ../../../../src/wpantund/FirmwareUpgrade.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPControlInterface.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPInstance.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPInstanceBase-Addresses.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPInstanceBase-AsyncIO.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPInstanceBase-NetInterface.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPInstanceBase-Prefixes.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPInstanceBase.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NCPTypes.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/NetworkRetain.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/Pcap.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/RunawayResetBackoffManager.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/StatCollector.cpp
LOCAL_SRC_FILES += ../../../../src/wpantund/wpan-error.c
LOCAL_SRC_FILES += ../../../../src/wpantund/wpantund.cpp
LOCAL_SRC_FILES += version.c
include $(BUILD_EXECUTABLE)
#### END wpantund ####
