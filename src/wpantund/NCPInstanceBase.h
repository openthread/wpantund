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

#ifndef __wpantund__NCPInstanceBase__
#define __wpantund__NCPInstanceBase__

#include "NCPInstance.h"
#include <set>
#include <map>
#include <string>
#include "FirmwareUpgrade.h"
#include "EventHandler.h"
#include "NCPTypes.h"
#include "StatCollector.h"
#include "NetworkRetain.h"
#include "RunawayResetBackoffManager.h"
#include "Pcap.h"

namespace nl {
namespace wpantund {

class NCPInstanceBase : public NCPInstance, public EventHandler {
public:

	enum {
		FRAME_TYPE_DATA = 2,
		FRAME_TYPE_INSECURE_DATA = 3,
		FRAME_TYPE_LEGACY_DATA = 4
	};

protected:
	NCPInstanceBase(const Settings& settings = Settings());

public:
	virtual ~NCPInstanceBase();

	virtual const std::string &get_name();

	virtual void set_socket_adapter(const boost::shared_ptr<SocketAdapter> &adapter);

public:
	// ========================================================================
	// Static Functions

	static bool setup_property_supported_by_class(const std::string& prop_name);


public:
	// ========================================================================
	// MARK: ASync I/O

	virtual cms_t get_ms_to_next_event(void);

	virtual int update_fd_set(
		fd_set *read_fd_set,
		fd_set *write_fd_set,
		fd_set *error_fd_set,
		int *max_fd,
		cms_t *timeout
	);

	virtual void process(void);

	// Helpful for use with callbacks.
	int process_event_helper(int event);

	virtual StatCollector& get_stat_collector(void);

protected:
	virtual char ncp_to_driver_pump() = 0;
	virtual char driver_to_ncp_pump() = 0;

public:
	// ========================================================================
	// MARK: NCP Behavior

	virtual void hard_reset_ncp(void);

	virtual int set_ncp_power(bool power);

	virtual bool can_set_ncp_power(void);

public:
	// ========================================================================
	// MARK: Other

	virtual void reinitialize_ncp(void);

	virtual void reset_tasks(wpantund_status_t status = kWPANTUNDStatus_Canceled);

	NCPState get_ncp_state()const;

	bool is_state_change_valid(NCPState new_ncp_state)const;

	//! Handles transitioning from state-to-state.
	/*! This is the ONLY WAY to change mNCPState. */
	void change_ncp_state(NCPState new_ncp_state);

	virtual void handle_ncp_state_change(NCPState new_ncp_state, NCPState old_ncp_state);

	virtual void ncp_is_misbehaving();

	virtual void set_initializing_ncp(bool x);

	virtual bool is_initializing_ncp()const;

public:
	// ========================================================================
	// MARK: Network Interface Methods

	int set_online(bool is_online);

	void set_mac_address(const uint8_t addr[8]);

	void set_mac_hardware_address(const uint8_t addr[8]);

	void reset_interface(void);

	const WPAN::NetworkInstance& get_current_network_instance(void)const;

public:
	// ========================================================================
	// MARK: Global address/prefix/route management

	enum Origin {
		kOriginThreadNCP,
		kOriginPrimaryInterface,
		kOriginUser,
	};

	typedef NCPControlInterface::ExternalRoutePriority  RoutePreference;

	void unicast_address_was_added(Origin origin, const struct in6_addr &address,
			uint8_t prefix_len = 64, uint32_t valid_lifetime = UINT32_MAX, uint32_t preferred_lifetime = UINT32_MAX);

	void unicast_address_was_removed(Origin origin, const struct in6_addr &address);

	void multicast_address_was_joined(Origin origin, const struct in6_addr &address, CallbackWithStatus cb = NilReturn());

	void multicast_address_was_left(Origin origin, const struct in6_addr &address, CallbackWithStatus cb = NilReturn());

	int join_multicast_group(const std::string &group_name);

	void on_mesh_prefix_was_added(Origin origin, const struct in6_addr &prefix, uint8_t prefix_len = 64,
			uint8_t flags = 0, bool stable = true, CallbackWithStatus cb = NilReturn());

	void on_mesh_prefix_was_removed(Origin origin, const struct in6_addr &prefix, uint8_t prefix_len = 64,
			CallbackWithStatus cb = NilReturn());

	void route_was_added(Origin origin, const struct in6_addr &route, uint8_t prefix_len = 64,
			RoutePreference preference = NCPControlInterface::ROUTE_MEDIUM_PREFERENCE,  bool stable = true,
			uint16_t rloc16 = 0, bool next_hop_is_host = true, CallbackWithStatus cb = NilReturn());

	void route_was_removed(Origin origin, const struct in6_addr &route, uint8_t prefix_len = 64,
			RoutePreference preference = NCPControlInterface::ROUTE_MEDIUM_PREFERENCE,  bool stable = true,
			uint16_t rloc16 = 0, CallbackWithStatus cb = NilReturn());

	bool lookup_address_for_prefix(struct in6_addr *address, const struct in6_addr &prefix, int prefix_len = 64);

	static std::string on_mesh_prefix_flags_to_string(uint8_t flags, bool detailed = false);

protected:
	void refresh_address_route_prefix_entries(void);

	void remove_all_address_prefix_route_entries(void);

	void remove_ncp_originated_address_prefix_route_entries(void);

	void restore_address_prefix_route_entries_on_ncp(void);

protected:
	// ========================================================================
	// MARK: Subclass hooks related to address/prefix/route management

	virtual void add_unicast_address_on_ncp(const struct in6_addr &addr, uint8_t prefix_len, CallbackWithStatus cb) = 0;

	virtual void remove_unicast_address_on_ncp(const struct in6_addr &addr, uint8_t prefix_len,
					CallbackWithStatus cb) = 0;

	virtual void add_multicast_address_on_ncp(const struct in6_addr &addr, CallbackWithStatus cb) = 0;

	virtual void remove_multicast_address_on_ncp(const struct in6_addr &addr, CallbackWithStatus cb) = 0;

	virtual void add_on_mesh_prefix_on_ncp(const struct in6_addr &addr, uint8_t prefix_len, uint8_t flags, bool stable,
					CallbackWithStatus cb) = 0;

	virtual void remove_on_mesh_prefix_on_ncp(const struct in6_addr &addr, uint8_t prefix_len, uint8_t flags,
					bool stable, CallbackWithStatus cb) = 0;

	virtual void add_route_on_ncp(const struct in6_addr &route, uint8_t prefix_len, RoutePreference preference,
					bool stable, CallbackWithStatus cb) = 0;

	virtual void remove_route_on_ncp(const struct in6_addr &route, uint8_t prefix_len, RoutePreference preference,
					bool stable, CallbackWithStatus cb) = 0;

protected:
	//========================================================================
	// MARK: Tunnel/Legacy Interface Signal Callbacks

	virtual void link_state_changed(bool is_up, bool is_running);

	virtual void legacy_link_state_changed(bool is_up, bool is_running);

public:
	// ========================================================================
	// MARK: Firmware Upgrade

	virtual bool is_firmware_upgrade_required(const std::string& version);

	virtual void upgrade_firmware(void);

	virtual int get_upgrade_status(void);

	virtual bool can_upgrade_firmware(void);

public:
	// ========================================================================
	// MARK: Busy/OkToSleep

	virtual bool is_busy(void);

	virtual void update_busy_indication(void);

public:
	// ========================================================================
	// MARK: IPv6 data path helpers

	bool should_forward_hostbound_frame(uint8_t* type, const uint8_t* packet, size_t packet_length);

	bool should_forward_ncpbound_frame(uint8_t* type, const uint8_t* packet, size_t packet_length);

	void handle_normal_ipv6_from_ncp(const uint8_t* packet, size_t packet_length);

	int set_commissioniner(int seconds, uint8_t traffic_type, in_port_t traffic_port);

public:
	// ========================================================================
	// MARK: Legacy Interface Methods

	void enable_legacy_interface(void);

	bool is_legacy_interface_enabled(void);

	void handle_alt_ipv6_from_ncp(const uint8_t* packet, size_t packet_length);

public:

	virtual std::set<std::string> get_supported_property_keys()const;

	virtual void property_get_value(const std::string& key, CallbackWithStatusArg1 cb);

	virtual void property_set_value(const std::string& key, const boost::any& value, CallbackWithStatus cb = NilReturn());

	virtual void property_insert_value(const std::string& key, const boost::any& value, CallbackWithStatus cb = NilReturn());

	virtual void property_remove_value(const std::string& key, const boost::any& value, CallbackWithStatus cb = NilReturn());

	virtual void signal_property_changed(const std::string& key, const boost::any& value = boost::any());

	wpantund_status_t set_ncp_version_string(const std::string& version_string);

protected:
	// ========================================================================
	// MARK: Protected Data

	boost::shared_ptr<TunnelIPv6Interface> mPrimaryInterface;

	boost::shared_ptr<SocketWrapper> mRawSerialAdapter;
	boost::shared_ptr<SocketWrapper> mSerialAdapter;

	struct nlpt mNCPToDriverPumpPT;
	struct nlpt mDriverToNCPPumpPT;

protected:
	//==========================================================================
	// MARK: Global entries: Unicast IPv6 addresses, multicast IPv6 addresses,
	// on-mesh prefixes, routes.

	class IPv6Prefix {
	public:
		IPv6Prefix(const in6_addr &prefix, uint8_t prefix_len);

		const struct in6_addr &get_prefix(void) const { return mPrefix; }
		uint8_t get_length(void) const { return mLength; }

		bool operator==(const IPv6Prefix &another_prefix) const;
		bool operator!=(const IPv6Prefix &another_prefix) const { return !(*this == another_prefix); }
		bool operator<(const IPv6Prefix &another_prefix) const;

		std::string to_string(void) const;

	private:
		struct in6_addr mPrefix;
		uint8_t mLength;
	};

	class EntryBase {
	public:
		EntryBase(Origin origin = kOriginThreadNCP) : mOrigin(origin) { }

		Origin get_origin(void) const { return mOrigin; }
		bool is_from_interface(void) const { return (mOrigin == kOriginPrimaryInterface); }
		bool is_from_ncp(void) const { return (mOrigin == kOriginThreadNCP); }
		bool is_from_user(void) const { return (mOrigin == kOriginUser); }

	protected:
		std::string get_origin_as_string(void) const;

	private:
		Origin mOrigin;
	};

	class UnicastAddressEntry : public EntryBase {
	public:
		UnicastAddressEntry(
			Origin origin = kOriginThreadNCP,
			uint8_t prefix_len = 64,
			uint32_t valid_lifetime = UINT32_MAX,
			uint32_t preferred_lifetime = UINT32_MAX
		);

		uint8_t get_prefix_len(void) const { return mPrefixLen; }
		uint32_t get_valid_lifetime(void) const { return mValidLifetime; }
		uint32_t get_preferred_lifetime(void) const { return mPreferredLifetime; }
		void set_valid_lifetime(uint32_t valid_lifetime) { mValidLifetime = valid_lifetime; }
		void set_preferred_lifetime(uint32_t preferred_lifetime) { mPreferredLifetime = preferred_lifetime; }

		std::string get_description(const struct in6_addr &address, bool align = false) const;

	private:
		uint8_t mPrefixLen;
		uint32_t mValidLifetime;
		uint32_t mPreferredLifetime;
	};

	class MulticastAddressEntry : public EntryBase {
	public:
		MulticastAddressEntry(Origin origin = kOriginThreadNCP) : EntryBase(origin) { }
		std::string get_description(const struct in6_addr &address, bool align = false) const;
	};

	class OnMeshPrefixEntry : public EntryBase {
	public:

		enum {
			kFlagOnMesh              = (1 << 0),
			kFlagDefaultRoute        = (1 << 1),
			kFlagConfigure           = (1 << 2),
			kFlagDHCP                = (1 << 3),
			kFlagSLAAC               = (1 << 4),
			kFlagPreferred           = (1 << 5),

			kPreferenceOffset        = 6,
			kPreferenceMask          = (3 << kPreferenceOffset),

			kPreferenceHigh          = (1 << kPreferenceOffset),
			kPreferenceMedium        = (0 << kPreferenceOffset),
			kPreferenceLow           = (3 << kPreferenceOffset),
		};

		OnMeshPrefixEntry(Origin origin = kOriginThreadNCP, uint8_t flags = 0, uint8_t prefix_len = 64, bool stable = true)
			: EntryBase(origin), mFlags(flags), mPrefixLen(prefix_len), mStable(stable) { }

		uint8_t get_prefix_len(void) const { return mPrefixLen; }
		uint8_t is_stable(void) const { return mStable; }

		uint8_t get_flags(void) const { return mFlags; }
		void set_flags(uint8_t flags) { mFlags = flags; }

		bool is_on_mesh(void) const { return (mFlags & kFlagOnMesh) == kFlagOnMesh; }
		bool is_slaac(void) const { return (mFlags & kFlagSLAAC) == kFlagSLAAC; }

		std::string get_description(const struct in6_addr &preifx, bool align = false) const;

		static uint8_t encode_flag_set(
			NCPControlInterface::OnMeshPrefixFlags prefix_flags,
			NCPControlInterface::OnMeshPrefixPriority priority
		);

	private:
		uint8_t mFlags;
		uint8_t mPrefixLen;
		bool mStable;
	};

	class OffMeshRouteEntry : public EntryBase {
	public:
		OffMeshRouteEntry(Origin origin, RoutePreference preference = NCPControlInterface::ROUTE_MEDIUM_PREFERENCE,
			bool stable = true, uint16_t rloc16 = 0, bool next_hop_is_host = false)
			: EntryBase(origin), mPreference(preference), mStable(stable), mRloc(rloc16)
			, mNextHopIsHost(next_hop_is_host) { }

		uint8_t is_stable(void) const { return mStable; }
		RoutePreference get_preference(void) const { return mPreference; }
		uint16_t get_rloc(void) const { return mRloc; }
		bool is_next_hop_host(void) const { return mNextHopIsHost; }

		bool operator==(const OffMeshRouteEntry &entry);

		std::string get_description(const IPv6Prefix &route, bool align = false) const;

	private:
		RoutePreference mPreference;
		bool mStable;
		uint16_t mRloc;
		bool mNextHopIsHost;
	};

	class InterfaceRouteEntry
	{
	public:
		// Mapping the 3 route preference values to Linux route metric (note that larger metric means lower priority)
		enum {
			kRouteMetricHigh     = 1,
			kRouteMetricMedium   = 256,
			kRouteMetricLow      = 512,
		};

		InterfaceRouteEntry(uint32_t metric = 512)
			: mMetric(metric) { }

		uint32_t get_metric(void) const { return mMetric; }

		std::string get_description(const IPv6Prefix &route, bool align = false) const;

	private:
		uint32_t mMetric;
	};

private:
	void add_address_on_ncp_and_update_prefixes(const in6_addr &address, const UnicastAddressEntry &entry);
	void remove_address_on_ncp_and_update_prefixes(const in6_addr &address, const UnicastAddressEntry &entry);
	std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator find_route_entry(const IPv6Prefix &route, const OffMeshRouteEntry &entry);
	void refresh_routes_on_interface(void);
	bool should_add_route_on_interface(const IPv6Prefix &route, uint32_t &metric);
	void check_ncp_entry_update_status(int status, std::string operation, CallbackWithStatus cb);
	void check_multicast_address_add_status(int status, const struct in6_addr address, CallbackWithStatus cb);

protected:

	std::map<struct in6_addr, UnicastAddressEntry> mUnicastAddresses;
	std::map<struct in6_addr, MulticastAddressEntry> mMulticastAddresses;
	std::map<struct in6_addr, OnMeshPrefixEntry> mOnMeshPrefixes;

	std::multimap<IPv6Prefix, OffMeshRouteEntry> mOffMeshRoutes;
	std::map<IPv6Prefix, InterfaceRouteEntry> mInterfaceRoutes;

protected:

	IPv6PacketMatcherRule mCommissioningRule;
	IPv6PacketMatcher mInsecureFirewall;
	IPv6PacketMatcher mDropFirewall;

	time_t mCommissioningExpiration;

	std::string mNCPVersionString;

	bool mEnabled;
	bool mTerminateOnFault;
	bool mAutoUpdateFirmware;
	bool mAutoResume;
	bool mAutoDeepSleep;
	int mAutoDeepSleepTimeout; // In seconds
	uint16_t mCommissionerPort;

	// This boolean flag indicates whether wpantund would listen for
	// unicast IPv6 address-added/removed events from the interface and
	// then update the addresses on the NCP. By default this feature
	// is enabled. It can be changed using a configuration wpantund
	// property "Daemon:IPv6:AutoUpdateInterfaceAddrsOnNCP"
	//
	bool mAutoUpdateInterfaceIPv6AddrsOnNCP;

	// This boolean flag indicates whether wpantund should skip adding
	// user (or interface) originated link-local IPv6 addresses on NCP.
	// By default this is enabled. It can be changed using a configuration
	// wpantund property "Daemon:IPv6:FilterUserAddedLinkLocal"
	bool mFilterUserAddedLinkLocalIPv6Address;

	// When an unicast address is added on interface, the related on-mesh prefix
	// is updated on NCP if `mDefaultRouteForAutoAddedPrefix` is true the prefix
	// is added with flag "DefaultRoute" set.
	bool mSetDefaultRouteForAutoAddedPrefix;
	bool mSetSLAACForAutoAddedPrefix;

	// This boolean flag determines whether wpantund should manage the routes
	// on the primary interface. When set to `true` wpantund will add/remove
	// off-mesh routes provided by devices within the network on the host
	// interface. By default it is enabled (`true`).
	//
	bool mAutoAddOffMeshRoutesOnInterface;

	// This boolean flag controls how the off-mesh-routes are managed
	// on the primary interface (this is applicable only if the
	// `mAutoAddOffMeshRoutesOnInterface` is enabled).
	//
	// This impacts the behavior where the same off-mesh route is provided
	// by multiple devices within the network including the device itself.
	//
	// When set to `true`, self-added off-mesh-routes are always filtered
	// and never added on the host interface (independent of the priority
	// levels at which they are added).
	//
	// If it is set to `false`, then the priority of routes are considered
	// and the off-mesh-route is added on the interface if another device
	// within the network provides the same route at a higher preference
	// level than the self added one.
	//
	// By default this is enabled (`true`).
	//
	bool mFilterSelfAutoAddedOffMeshRoutes;

private:
	NCPState mNCPState;
	bool mIsInitializingNCP;
	bool mIsInterfaceOnline;
	bool mRequestRouteRefresh;

protected:
	//! This is set to the currently used MAC address (EUI64).
	uint8_t mMACAddress[8];

	//! This is set to the manufacturer-assigned permanent EUI64 address.
	uint8_t mMACHardwareAddress[8];
	union {
		uint8_t mNCPV6Prefix[8];
		struct in6_addr mNCPMeshLocalAddress;
	};
	struct in6_addr mNCPLinkLocalAddress;

	WPAN::NetworkInstance mCurrentNetworkInstance;

	NodeType mNodeType;

	int mFailureCount;
	int mFailureThreshold;

	RunawayResetBackoffManager mRunawayResetBackoffManager;

protected:
	// ========================================================================
	// MARK: Legacy Interface Support

	boost::shared_ptr<TunnelIPv6Interface> mLegacyInterface;
	IPv6PacketMatcher mLegacyCommissioningMatcher;
	uint8_t mNCPV6LegacyPrefix[8];
	bool mLegacyInterfaceEnabled;
	bool mNodeTypeSupportsLegacy;

	PcapManager mPcapManager;

private:
	// ========================================================================
	// MARK: Private Data

	boost::shared_ptr<SocketWrapper> mResetSocket;
	char mResetSocket_BeginReset; //!^ Value for entering reset
	char mResetSocket_EndReset; //!^ Value for leaving reset

	boost::shared_ptr<SocketWrapper> mPowerSocket;
	char mPowerSocket_PowerOn; //!^ Value for the power being on.
	char mPowerSocket_PowerOff; //!^ Value for the power being off.

	bool mWasBusy;
	cms_t mLastChangedBusy;

	bool mNCPIsMisbehaving;

	FirmwareUpgrade mFirmwareUpgrade;

	NetworkRetain mNetworkRetain;

	StatCollector mStatCollector;  // Statistic collector
}; // class NCPInstance

}; // namespace wpantund

}; // namespace nl

// This callback is not sent from the NCP. It is a fake NCP
// callback sent from the processing thread to indicate that
// the NCP is in deep sleep.
#define EVENT_NCP_DISABLED                 0x78C9

#define EVENT_NCP_CONN_RESET               0x78CB

// Extracts a pointer and length from argument list and
// returns a `nl::Data` object.
static inline nl::Data
va_arg_as_Data(va_list args)
{
	const uint8_t* data = NULL;
	size_t data_len = 0;

	data = va_arg(args, const uint8_t*);
	data_len = va_arg(args, size_t);

	// Sanity check
	assert(data_len < 1024*1024);

	return nl::Data(data, data_len);
}

#define va_arg_small(args, type)		static_cast<type>(va_arg(args, int))

#endif /* defined(__wpantund__NCPInstanceBase__) */
