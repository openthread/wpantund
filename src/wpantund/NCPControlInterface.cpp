/*
 *
 * Copyright (c) 2016 Nest Labs, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *    Description:
 *		Abstract base class for NCP implementations.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include "NCPControlInterface.h"
#include "NCPInstance.h"
#include "tunnel.h"
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <boost/bind.hpp>
#include "version.h"
#include "any-to.h"
#include "wpan-error.h"

#ifndef SOURCE_VERSION
#define SOURCE_VERSION		PACKAGE_VERSION
#endif

using namespace nl;
using namespace wpantund;

std::string
NCPControlInterface::external_route_priority_to_string(ExternalRoutePriority route_priority)
{
	const char *ret = "unknown";

	switch(route_priority) {
		case ROUTE_LOW_PREFRENCE:
			ret = "low";
			break;

		case ROUTE_MEDIUM_PREFERENCE:
			ret = "medium";
			break;

		case ROUTE_HIGH_PREFERENCE:
			ret = "high";
			break;
	}

	return ret;
}

NCPControlInterface::~NCPControlInterface() {
}

struct GetPropertyHelper {
	boost::any *dest;
	bool *          didFire;

	void operator()(
	    int status, const boost::any& value
	    ) const
	{
		if (dest) {
			if (status == 0)
				*dest = value;
			*didFire = true;
		}
		delete this;
	}
};

boost::any
NCPControlInterface::property_get_value(const std::string& key)
{
	// In this function, we want to immediately return the value
	// for the given key. Since the actual property_get_value()
	// function returns the value as a callback, we may not
	// actually be able to do this. What we do here is give a
	// callback object that contains a pointer to our return value.
	// After we call property_get_value(), we then zero out that
	// pointer. For properties which get updated immediately, our
	// return value will be updated automatically. For properties
	// which can't be fetched immediately, we return an empty value.
	// The "GetPropertyHelper" class makes sure that when the
	// callback eventually does fire that it doesn't break anything.

	boost::any ret;
	bool didFire = false;
	struct GetPropertyHelper *helper = new GetPropertyHelper;

	helper->dest = &ret;
	helper->didFire = &didFire;
	property_get_value(key, boost::bind(&GetPropertyHelper::operator(),
	                              helper,
	                              _1,
	                              _2));
	if (!didFire) {
		helper->dest = 0;
		helper->didFire = 0;
	}
	return ret;
}

std::string
NCPControlInterface::get_name() {
	return boost::any_cast<std::string>(property_get_value(kWPANTUNDProperty_ConfigTUNInterfaceName));
}


struct SetPropertyHelper {
	int* dest;
	bool* didFire;

	void operator()(int status) const
	{
		if (dest) {
			*dest = status;
			*didFire = true;
		}
		delete this;
	}
};

#define kWPANTUNDPropertyNCPSocketName             "NCPSocketName"
#define kWPANTUNDPropertyNCPSocketBaud             "NCPSocketBaud"
#define kWPANTUNDPropertyNCPDriverName             "NCPDriverName"
#define kWPANTUNDPropertyNCPHardResetPath          "NCPHardResetPath"
#define kWPANTUNDPropertyNCPPowerPath              "NCPPowerPath"
#define kWPANTUNDPropertyWPANInterfaceName         "WPANInterfaceName"
#define kWPANTUNDPropertyPIDFile                   "PIDFile"
#define kWPANTUNDPropertyFirmwareCheckCommand      "FirmwareCheckCommand"
#define kWPANTUNDPropertyFirmwareUpgradeCommand    "FirmwareUpgradeCommand"
#define kWPANTUNDPropertyTerminateOnFault          "TerminateOnFault"
#define kWPANTUNDPropertyPrivDropToUser            "PrivDropToUser"
#define kWPANTUNDPropertyChroot                    "Chroot"
#define kWPANTUNDPropertyNCPReliabilityLayer       "NCPReliabilityLayer"

// Version Properties
#define kWPANTUNDPropertyNCPVersion                "NCPVersion"
#define kWPANTUNDPropertyDriverVersion             "DriverVersion"

// Driver State Properties
#define kWPANTUNDPropertyAssociationState          "AssociationState"    // [RO]
#define kWPANTUNDPropertyEnabled                   "Enabled"             // [RW]
#define kWPANTUNDPropertyAutoresume                "AutoResume"          // [RW]
#define kWPANTUNDPropertyAutoUpdateFirmware        "AutoUpdateFirmware"  // [RW]

// PHY-layer parameters
#define kWPANTUNDPropertyHWAddr                    "HWAddr"
#define kWPANTUNDPropertyChannel                   "Channel"
#define kWPANTUNDPropertyTXPower                   "TXPower"
#define kWPANTUNDPropertyNCPTXPowerLimit           "NCPTXPowerLimit"
#define kWPANTUNDPropertyCCAThreshold              "CCAThreshold"
#define kWPANTUNDPropertyDefaultChannelMask        "DefaultChannelMask"

// MAC-layer (and higher) parameters
#define kWPANTUNDPropertyNetworkName               "NetworkName"         // [RO]
#define kWPANTUNDPropertyXPANID                    "XPANID"              // [RO]
#define kWPANTUNDPropertyPANID                     "PANID"               // [RO]
#define kWPANTUNDPropertyNodeType                  "NodeType"            // [RW]
#define kWPANTUNDPropertyNetworkKey                "NetworkKey"          // [RW]
#define kWPANTUNDPropertyNetworkKeyIndex           "NetworkKeyIndex"     // [RW]
#define kWPANTUNDPropertyMeshLocalPrefix           "MeshLocalPrefix"     // [RO]
#define kWPANTUNDPropertyAllowingJoin              "AllowingJoin"        // [RO]
#define kWPANTUNDPropertyIsAssociated              "IsAssociated"        // [RO]

// Power Management Properties
#define kWPANTUNDPropertyIsOKToSleep               "IsOKToSleep"
#define kWPANTUNDPropertyUseDeepSleepOnLowPower    "UseDeepSleepOnLowPower"
#define kWPANTUNDPropertyAlwaysResetToWake         "AlwaysResetToWake"
#define kWPANTUNDPropertyAutoDeepSleep             "AutoDeepSleep"
#define kWPANTUNDPropertySleepPollInterval         "SleepPollInterval"

// Debugging and logging
#define kWPANTUNDPropertySyslogMask                "SyslogMask"
#define kWPANTUNDPropertyNCPDebug                  "NCPDebug"

// Properties related to manufacturing test commands
#define kWPANTUNDPropertyMfgTestMode               "MfgTestMode"
#define kWPANTUNDPropertyMfgSYNOffset              "MfgSYNOffset"
#define kWPANTUNDPropertyMfgRepeatRandomTXInterval "MfgRepeatRandomTXInterval"
#define kWPANTUNDPropertyMfgRepeatRandomTXLen      "MfgRepeatRandomTXLen"
#define kWPANTUNDPropertyMfgFirstPacketRSSI        "MfgFirstPacketRSSI"
#define kWPANTUNDPropertyMfgFirstPacketLQI         "MfgFirstPacketLQI"


// Nest-Specific Properties
#define kWPANTUNDPropertyPassthruPort              "PassthruPort"
#define kWPANTUNDPropertyTransmitHookActive        "TransmitHookActive"
#define kWPANTUNDPropertyUseLegacyChannel          "UseLegacyChannel"
#define kWPANTUNDPropertyLegacyPrefix              "LegacyPrefix"
#define kWPANTUNDPropertyNetWakeData               "NetWakeData"
#define kWPANTUNDPropertyNetWakeRemaining          "NetWakeRemaining"
#define kWPANTUNDPropertyActiveWakeupDenylist     "ActiveWakeupDenylist"
#define kWPANTUNDPropertyActiveWakeupMask          "ActiveWakeupMask"
#define kWPANTUNDPropertyLegacyInterfaceEnabled    "LegacyInterfaceEnabled"
#define kWPANTUNDPropertyPrefix                    "Prefix"

#define kWPANTUNDPropertyGlobalIPAddresses         "GlobalIPAddresses"
#define kWPANTUNDPropertyGlobalIPAddressList       "GlobalIPAddressList"

int
NCPControlInterface::property_set_value(const std::string& key, const boost::any& value)
{
	// In this function, we want to immediately return the status
	// of the set operation. Since the actual property_set_value()
	// function returns the status as a callback, we may not
	// actually be able to do this. What we do here is give a
	// callback object that contains a pointer to our return value.
	// After we call property_set_value(), we then zero out that
	// pointer. For properties which get updated immediately, our
	// return value will be updated automatically. For properties
	// which can't be fetched immediately, we return -EINPROGRESS.
	// The "SetPropertyHelper" class makes sure that when the
	// callback eventually does fire that it doesn't break anything.

	int ret = kWPANTUNDStatus_InProgress;
	bool didFire = false;
	struct SetPropertyHelper *helper = new SetPropertyHelper;

	helper->dest = &ret;
	helper->didFire = &didFire;
	property_set_value(key, value, boost::bind(&SetPropertyHelper::operator(),
	                              helper,
	                              _1));
	if (!didFire) {
		helper->dest = 0;
		helper->didFire = 0;
	}
	return ret;
}

std::string
NCPControlInterface::to_upper(const std::string &str)
{
	std::string new_str = str;

	for (size_t i = 0; i < str.length(); i++) {
		new_str[i] = std::toupper(new_str[i]);
	}

	return new_str;
}

bool
NCPControlInterface::translate_deprecated_property(std::string& key, boost::any& value)
{
	static std::map<std::string, std::string> prop_map;
	static bool initialized = false;

	std::map<std::string, std::string>::iterator iter;
	bool ret = false;

	if (!initialized) {
		prop_map[to_upper(kWPANTUNDPropertyPrefix)]                 = kWPANTUNDProperty_IPv6MeshLocalPrefix;
		prop_map[to_upper(kWPANTUNDPropertyNCPSocketName)]          = kWPANTUNDProperty_ConfigNCPSocketPath;
		prop_map[to_upper(kWPANTUNDPropertyNCPSocketBaud)]          = kWPANTUNDProperty_ConfigNCPSocketBaud;
		prop_map[to_upper(kWPANTUNDPropertyNCPDriverName)]          = kWPANTUNDProperty_ConfigNCPDriverName;
		prop_map[to_upper(kWPANTUNDPropertyNCPHardResetPath)]       = kWPANTUNDProperty_ConfigNCPHardResetPath;
		prop_map[to_upper(kWPANTUNDPropertyNCPPowerPath)]           = kWPANTUNDProperty_ConfigNCPPowerPath;
		prop_map[to_upper(kWPANTUNDPropertyWPANInterfaceName)]      = kWPANTUNDProperty_ConfigTUNInterfaceName;
		prop_map[to_upper(kWPANTUNDPropertyPIDFile)]                = kWPANTUNDProperty_ConfigDaemonPIDFile;
		prop_map[to_upper(kWPANTUNDPropertyFirmwareCheckCommand)]   = kWPANTUNDProperty_ConfigNCPFirmwareCheckCommand;
		prop_map[to_upper(kWPANTUNDPropertyFirmwareUpgradeCommand)] = kWPANTUNDProperty_ConfigNCPFirmwareUpgradeCommand;
		prop_map[to_upper(kWPANTUNDPropertyTerminateOnFault)]       = kWPANTUNDProperty_DaemonTerminateOnFault;
		prop_map[to_upper(kWPANTUNDPropertyPrivDropToUser)]         = kWPANTUNDProperty_ConfigDaemonPrivDropToUser;
		prop_map[to_upper(kWPANTUNDPropertyChroot)]                 = kWPANTUNDProperty_ConfigDaemonChroot;
		prop_map[to_upper(kWPANTUNDPropertyNCPReliabilityLayer)]    = kWPANTUNDProperty_ConfigNCPReliabilityLayer;
		prop_map[to_upper(kWPANTUNDPropertyNCPVersion)]             = kWPANTUNDProperty_NCPVersion;
		prop_map[to_upper(kWPANTUNDPropertyDriverVersion)]          = kWPANTUNDProperty_DaemonVersion;
		prop_map[to_upper(kWPANTUNDPropertyAssociationState)]       = kWPANTUNDProperty_NCPState;
		prop_map[to_upper(kWPANTUNDPropertyEnabled)]                = kWPANTUNDProperty_DaemonEnabled;
		prop_map[to_upper(kWPANTUNDPropertyAutoresume)]             = kWPANTUNDProperty_DaemonAutoAssociateAfterReset;
		prop_map[to_upper(kWPANTUNDPropertyAutoUpdateFirmware)]     = kWPANTUNDProperty_DaemonAutoFirmwareUpdate;
		prop_map[to_upper(kWPANTUNDPropertyHWAddr)]                 = kWPANTUNDProperty_NCPHardwareAddress;
		prop_map[to_upper(kWPANTUNDPropertyChannel)]                = kWPANTUNDProperty_NCPChannel;
		prop_map[to_upper(kWPANTUNDPropertyTXPower)]                = kWPANTUNDProperty_NCPTXPower;
		prop_map[to_upper(kWPANTUNDPropertyNCPTXPowerLimit)]        = kWPANTUNDProperty_NCPTXPowerLimit;
		prop_map[to_upper(kWPANTUNDPropertyCCAThreshold)]           = kWPANTUNDProperty_NCPCCAThreshold;
		prop_map[to_upper(kWPANTUNDPropertyDefaultChannelMask)]     = kWPANTUNDProperty_NCPChannelMask;
		prop_map[to_upper(kWPANTUNDPropertyNetworkName)]            = kWPANTUNDProperty_NetworkName;
		prop_map[to_upper(kWPANTUNDPropertyXPANID)]                 = kWPANTUNDProperty_NetworkXPANID;
		prop_map[to_upper(kWPANTUNDPropertyPANID)]                  = kWPANTUNDProperty_NetworkPANID;
		prop_map[to_upper(kWPANTUNDPropertyNodeType)]               = kWPANTUNDProperty_NetworkNodeType;
		prop_map[to_upper(kWPANTUNDPropertyNetworkKey)]             = kWPANTUNDProperty_NetworkKey;
		prop_map[to_upper(kWPANTUNDPropertyNetworkKeyIndex)]        = kWPANTUNDProperty_NetworkKeyIndex;
		prop_map[to_upper(kWPANTUNDPropertyMeshLocalPrefix)]        = kWPANTUNDProperty_IPv6MeshLocalPrefix;
		prop_map[to_upper(kWPANTUNDPropertyAllowingJoin)]           = kWPANTUNDProperty_NestLabs_NetworkAllowingJoin;
		prop_map[to_upper(kWPANTUNDPropertyIsAssociated)]           = kWPANTUNDProperty_NetworkIsCommissioned;
		prop_map[to_upper(kWPANTUNDPropertyIsOKToSleep)]            = kWPANTUNDProperty_DaemonReadyForHostSleep;
		prop_map[to_upper(kWPANTUNDPropertyUseDeepSleepOnLowPower)] = kWPANTUNDProperty_NestLabs_HackUseDeepSleepOnLowPower;
		prop_map[to_upper(kWPANTUNDPropertyAlwaysResetToWake)]      = kWPANTUNDProperty_NestLabs_HackAlwaysResetToWake;
		prop_map[to_upper(kWPANTUNDPropertyAutoDeepSleep)]          = kWPANTUNDProperty_DaemonAutoDeepSleep;
		prop_map[to_upper(kWPANTUNDPropertySleepPollInterval)]      = kWPANTUNDProperty_NCPSleepyPollInterval;
		prop_map[to_upper(kWPANTUNDPropertySyslogMask)]             = kWPANTUNDProperty_DaemonSyslogMask;
		prop_map[to_upper(kWPANTUNDPropertyPassthruPort)]           = kWPANTUNDProperty_NestLabs_NetworkPassthruPort;
		prop_map[to_upper(kWPANTUNDPropertyTransmitHookActive)]     = kWPANTUNDProperty_NestLabs_NCPTransmitHookActive;
		prop_map[to_upper(kWPANTUNDPropertyLegacyPrefix)]           = kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix;
		prop_map[to_upper(kWPANTUNDPropertyNetWakeData)]            = kWPANTUNDProperty_NestLabs_NetworkWakeData;
		prop_map[to_upper(kWPANTUNDPropertyNetWakeRemaining)]       = kWPANTUNDProperty_NestLabs_NetworkWakeRemaining;
		prop_map[to_upper(kWPANTUNDPropertyActiveWakeupDenylist)]  = kWPANTUNDProperty_NestLabs_NetworkWakeDenylist;
		prop_map[to_upper(kWPANTUNDPropertyActiveWakeupMask)]       = kWPANTUNDProperty_NestLabs_NetworkWakeDenylist;
		prop_map[to_upper(kWPANTUNDPropertyLegacyInterfaceEnabled)] = kWPANTUNDProperty_NestLabs_LegacyEnabled;
		prop_map[to_upper(kWPANTUNDPropertyUseLegacyChannel)]       = kWPANTUNDProperty_NestLabs_LegacyPreferInterface;
		prop_map[to_upper(kWPANTUNDPropertyGlobalIPAddresses)]      = kWPANTUNDProperty_IPv6AllAddresses;
		prop_map[to_upper(kWPANTUNDPropertyGlobalIPAddressList)]    = kWPANTUNDProperty_DebugIPv6GlobalIPAddressList;
		initialized = true;
	}

	iter = prop_map.find(to_upper(key));

	if (iter != prop_map.end()) {
		key = iter->second;
		ret = true;
	}

	return ret;
}

bool
NCPControlInterface::translate_deprecated_property(std::string& key)
{
	boost::any unused;
	return translate_deprecated_property(key, unused);
}
