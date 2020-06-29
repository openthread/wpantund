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
 */

#ifndef wpantund_WPAN_NCPControlInterface_h
#define wpantund_WPAN_NCPControlInterface_h

#ifndef __STDC_CONSTANT_MACROS
#define __STDC_CONSTANT_MACROS 1
#endif

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS 1
#endif

#include <stdint.h>
#include <string>
#include <vector>
#include <boost/signals2/signal.hpp>
#include <boost/any.hpp>
#include <list>
#include <set>
#include <arpa/inet.h>
#include "time-utils.h"

#include <pthread.h>

#include "NetworkInstance.h"
#include "NCPTypes.h"
#include <cstring>
#include "IPv6PacketMatcher.h"
#include "Data.h"
#include "NilReturn.h"
#include "NCPConstants.h"
#include "Callbacks.h"
#include "wpan-properties.h"
#include "ValueMap.h"

namespace nl {
namespace wpantund {

#define USE_DEFAULT_TX_POWER               INT32_MIN
#define USE_DEFAULT_CCA_THRESHOLD          INT32_MIN
#define USE_DEFAULT_TX_POWER_MODE          INT32_MIN
#define USE_DEFAULT_TRANSMIT_HOOK_ACTIVE   INT32_MIN

typedef std::set<int> IntegerSet;

class NCPInstance;

class NCPControlInterface {
public:

	struct XPANId
	{
		uint8_t m8[NCP_XPANID_SIZE];
	};

	typedef uint32_t ChannelMask;

	enum ExternalRoutePriority {
		ROUTE_LOW_PREFRENCE = -1,
		ROUTE_MEDIUM_PREFERENCE = 0,
		ROUTE_HIGH_PREFERENCE = 1,
	};

	enum OnMeshPrefixPriority {
		PREFIX_LOW_PREFRENCE = -1,
		PREFIX_MEDIUM_PREFERENCE = 0,
		PREFIX_HIGH_PREFERENCE = 1,
	};

	enum PrefixFlag {
		PREFIX_FLAG_PREFERRED,
		PREFIX_FLAG_SLAAC,
		PREFIX_FLAG_DHCP,
		PREFIX_FLAG_CONFIGURE,
		PREFIX_FLAG_DEFAULT_ROUTE,
		PREFIX_FLAG_ON_MESH,
	};

	typedef std::set<PrefixFlag> OnMeshPrefixFlags;

	struct JoinerInfo
	{
		enum Type
		{
			kAny,
			kEui64,
			kDiscerner,
		};


		Type    mType;
		uint8_t mEui64[NCP_EUI64_SIZE];
		struct Discerner
		{
			uint64_t mValue;
			uint8_t  mBitLength;
		}            mDiscerner;
	};

public:
	// ========================================================================
	// Static Functions

	static std::string external_route_priority_to_string(ExternalRoutePriority route_priority);

public:
	// ========================================================================
	// Public Virtual Member Functions

	//! Returns the network instance currently associated with the NCP.
	virtual const WPAN::NetworkInstance& get_current_network_instance(void)const = 0;

public:
	// ========================================================================
	// NCP Command Virtual Member Functions

	virtual void join(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void form(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void leave(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	//! Deprecated. Set kWPANTUNDProperty_InterfaceUp to true instead.
	virtual void attach(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void reset(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void refresh_state(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void property_get_value(
		const std::string& key,
		CallbackWithStatusArg1 cb
	) = 0;

	virtual void property_set_value(
		const std::string& key,
		const boost::any& value,
		CallbackWithStatus cb
	) = 0;

	virtual void property_insert_value(
		const std::string& key,
		const boost::any& value,
		CallbackWithStatus cb
	) = 0;

	virtual void property_remove_value(
		const std::string& key,
		const boost::any& value,
		CallbackWithStatus cb
	) = 0;

	virtual void add_on_mesh_prefix(
		const struct in6_addr& prefix,
		uint8_t prefix_len,
		OnMeshPrefixFlags flags,
		OnMeshPrefixPriority priority,
		bool stable,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void remove_on_mesh_prefix(
		const struct in6_addr& prefix,
		uint8_t prefix_len,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void add_external_route(
		const struct in6_addr *prefix,
		int prefix_len_in_bits,
		int domain_id,
		ExternalRoutePriority priority,
		bool stable,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void remove_external_route(
		const struct in6_addr *prefix,
		int prefix_len_in_bits,
		int domain_id,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void add_service(
		uint32_t enterprise_number,
		const Data &service_data,
		bool stable,
		const Data &server_data,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void remove_service(
		uint32_t enterprise_number,
		const Data &service_data,
		CallbackWithStatus cb = NilReturn()
	) = 0;

public:
	// ========================================================================
	// Thread Mesh Commissioning Protocol (MeshCoP) Member Functions

	virtual void joiner_attach(
		const ValueMap &options,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void joiner_commissioning(
		bool action,
		const ValueMap &options,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void commissioner_add_joiner(
		const JoinerInfo &joiner,
		uint32_t timeout,
		const char *psk,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void commissioner_remove_joiner(
		const JoinerInfo &joiner,
		uint32_t timeout,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void commissioner_send_announce_begin(
		uint32_t channel_mask,
		uint8_t count,
		uint16_t period,         // in milliseconds
		const struct in6_addr& dest,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void commissioner_send_energy_scan_query(
		uint32_t channel_mask,
		uint8_t count,
		uint16_t period,         // in milliseconds
		uint16_t scan_duration,  // in milliseconds
		const struct in6_addr& dest,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void commissioner_send_pan_id_query(
		uint16_t pan_id,
		uint32_t channel_mask,
		const struct in6_addr& dest,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void commissioner_generate_pskc(
		const char *pass_phrase,
		const char *network_name,
		const XPANId &xpanid,
		CallbackWithStatusArg1 cb = NilReturn()
	) = 0;

public:
	// ========================================================================
	// Packet Capture (pcap) Member Functions

	virtual void pcap_to_fd(
		int fd,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void pcap_terminate(
		CallbackWithStatus cb = NilReturn()
	) = 0;

public:
	// ========================================================================
	// Scan-related Member Functions

	virtual void netscan_start(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void netscan_stop(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	boost::signals2::signal<void(const WPAN::NetworkInstance&)> mOnNetScanBeacon;

public:
	// ========================================================================
	// EnergyScan-related Member Functions

	virtual void energyscan_start(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void energyscan_stop(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	boost::signals2::signal<void(const EnergyScanResultEntry&)> mOnEnergyScanResult;

public:
	// ========================================================================
	// Network time-related Member Functions

	boost::signals2::signal<void(const ValueMap&)> mOnNetworkTimeUpdate;

public:
	// ========================================================================
	// Power-related Member Functions

	virtual void begin_low_power(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void host_did_wake(
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void data_poll(
		CallbackWithStatus cb = NilReturn()
	) = 0;


public:
	// ========================================================================
	// Debug-related Member Functions

	virtual void peek(
		uint32_t address,
		uint16_t count,
		CallbackWithStatusArg1 cb = NilReturn()
	) = 0;

	virtual void poke(
		uint32_t address,
		Data bytes,
		CallbackWithStatus cb = NilReturn()
	) = 0;

public:
	// ========================================================================
	// Nest-Specific Member Functions

	virtual void begin_net_wake(
		uint8_t data = 0,
		uint32_t flags = 0,
		CallbackWithStatus cb = NilReturn()
	) = 0;

	virtual void permit_join(
		int seconds = 15 * 60,
		uint8_t commissioning_traffic_type = 0xFF,
		in_port_t commissioning_traffic_port = 0,
		bool network_wide = false,
		CallbackWithStatus cb = NilReturn()
	) = 0;

public:
	// ========================================================================
	// Convenience methods

	boost::any property_get_value(const std::string& key);

	int property_set_value(const std::string& key, const boost::any& value);

	virtual std::string get_name(void);

public:
	// ========================================================================
	// Other

	static bool translate_deprecated_property(std::string& key, boost::any& value);

	static bool translate_deprecated_property(std::string& key);

public:
	// ========================================================================
	// Signals

	//! Fires whenever value of certain properties changed (e.g. NodeType).
	boost::signals2::signal<void(const std::string& key, const boost::any& value)> mOnPropertyChanged;

public:
	// ========================================================================
	// Nest-Specific Signals

	//! Fires when the network wake state has changed or been updated.
	boost::signals2::signal<void(uint8_t data, cms_t ms_remaining)> mOnNetWake;

protected:
	// ========================================================================
	// Protected Virtual Member Functions

	virtual ~NCPControlInterface();

	//! Returns the associated NCP instance.
	virtual NCPInstance& get_ncp_instance(void) = 0;

private:
	static std::string to_upper(const std::string &str);
};

}; // namespace wpantund
}; // namespace nl

#endif
