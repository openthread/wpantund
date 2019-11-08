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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <utility>
#include "assert-macros.h"
#include "NCPInstanceBase.h"
#include "tunnel.h"
#include <syslog.h>
#include <errno.h>
#include "nlpt.h"
#include <algorithm>
#include "socket-utils.h"
#include "SuperSocket.h"
#include "IPv6Helpers.h"

using namespace nl;
using namespace wpantund;

NCPInstanceBase::IPv6Prefix::IPv6Prefix(const in6_addr &prefix, uint8_t len):
	mPrefix(prefix), mLength(len)
{
	in6_addr_apply_mask(mPrefix, mLength);
}

bool
NCPInstanceBase::IPv6Prefix::operator==(const IPv6Prefix &another_prefix) const
{
	return (mPrefix == another_prefix.mPrefix) && (mLength == another_prefix.mLength);
}

bool
NCPInstanceBase::IPv6Prefix::operator<(const IPv6Prefix &another_prefix) const
{
	bool is_less = false;

	if (mLength < another_prefix.mLength) {
		is_less = true;
	} else if (mLength == another_prefix.mLength) {
		is_less = (memcmp(&mPrefix, &another_prefix.mPrefix, sizeof(mPrefix)) < 0);
	}

	return is_less;
}

std::string
NCPInstanceBase::IPv6Prefix::to_string(void) const
{
	char c_string[100];
	snprintf(c_string, sizeof(c_string), "%s/%d", in6_addr_to_string(mPrefix).c_str(), mLength);
	return std::string(c_string);
}

std::string
NCPInstanceBase::EntryBase::get_origin_as_string(void) const
{
	const char *ret = "unknown";

	switch (mOrigin) {
	case kOriginThreadNCP:
		ret =  "ncp";
		break;

	case kOriginPrimaryInterface:
		ret =  "intface";
		break;

	case kOriginUser:
		ret = "user";
		break;
	}

	return ret;
}

NCPInstanceBase::UnicastAddressEntry::UnicastAddressEntry(
	Origin origin,
	uint8_t prefix_len,
	uint32_t valid_lifetime,
	uint32_t preferred_lifetime
) :	EntryBase(origin)
{
	mPrefixLen = prefix_len;
	mValidLifetime = valid_lifetime;
	mPreferredLifetime = preferred_lifetime;
}

std::string
NCPInstanceBase::UnicastAddressEntry::get_description(const struct in6_addr &address, bool align) const
{
	char c_string[300];

	if (align) {
		if ((mValidLifetime == UINT32_MAX) && (mPreferredLifetime == UINT32_MAX)) {
			snprintf(c_string, sizeof(c_string),
				"%-40s prefix_len:%-4d origin:%-8s valid:forever   preferred:forever",
				in6_addr_to_string(address).c_str(), get_prefix_len(), get_origin_as_string().c_str());
		} else {
			snprintf(c_string, sizeof(c_string),
				"%-40s prefix_len:%-4d origin:%-8s valid:%-10u preferred:%-10u",
				in6_addr_to_string(address).c_str(), get_prefix_len(), get_origin_as_string().c_str(),
				mValidLifetime, mPreferredLifetime);
		}
	} else {
		if ((mValidLifetime == UINT32_MAX) && (mPreferredLifetime == UINT32_MAX)) {
			snprintf(c_string, sizeof(c_string),
				"\"%s/%d\", origin:%s, valid:forever, preferred:forever",
				in6_addr_to_string(address).c_str(), get_prefix_len(), get_origin_as_string().c_str());
		} else {
			snprintf(c_string, sizeof(c_string),
				"\"%s/%d\", origin:%s, valid:%u, preferred:%u",
				in6_addr_to_string(address).c_str(), get_prefix_len(), get_origin_as_string().c_str(),
				mValidLifetime, mPreferredLifetime);
		}
	}

	return std::string(c_string);
}

std::string
NCPInstanceBase::MulticastAddressEntry::get_description(const struct in6_addr &address, bool align) const
{
	char c_string[300];

	if (align) {
		snprintf(c_string, sizeof(c_string), "%-40s origin:%s", in6_addr_to_string(address).c_str(),
			get_origin_as_string().c_str());
	} else {
		snprintf(c_string, sizeof(c_string), "\"%s\", origin:%s", in6_addr_to_string(address).c_str(),
			get_origin_as_string().c_str());
	}

	return std::string(c_string);
}

std::string
NCPInstanceBase::on_mesh_prefix_flags_to_string(uint8_t flags, bool detailed)
{
	char c_string[300];

	if (detailed) {
		uint8_t preferece = flags & OnMeshPrefixEntry::kPreferenceMask;
		const char *prio = "none";

		switch (preferece) {
		case OnMeshPrefixEntry::kPreferenceHigh:
			prio = "high";
			break;

		case OnMeshPrefixEntry::kPreferenceLow:
			prio = "low";
			break;

		case OnMeshPrefixEntry::kPreferenceMedium:
			prio = "med";
			break;
		}

		snprintf(c_string, sizeof(c_string), "flags:0x%02x [on-mesh:%s def-route:%s config:%s dhcp:%s slaac:%s pref:%s prio:%s]",
			flags,
			(flags & OnMeshPrefixEntry::kFlagOnMesh) ? "1" : "0",
			(flags & OnMeshPrefixEntry::kFlagDefaultRoute) ? "1" : "0",
			(flags & OnMeshPrefixEntry::kFlagConfigure) ? "1" : "0",
			(flags & OnMeshPrefixEntry::kFlagDHCP) ? "1" : "0",
			(flags & OnMeshPrefixEntry::kFlagSLAAC) ? "1" : "0",
			(flags & OnMeshPrefixEntry::kFlagPreferred) ? "1" : "0",
			prio
		);
	} else {
		snprintf(c_string, sizeof(c_string), "%s(0x%02x)", flags_to_string(flags, "ppPSDCRM").c_str(), flags);
	}

	return c_string;
}

uint8_t
NCPInstanceBase::OnMeshPrefixEntry::encode_flag_set(
	NCPControlInterface::OnMeshPrefixFlags prefix_flag_set,
	NCPControlInterface::OnMeshPrefixPriority priority
) {
	uint8_t flags = 0;

	switch (priority) {
	case NCPControlInterface::PREFIX_HIGH_PREFERENCE:
		flags |= kPreferenceHigh;
		break;

	case NCPControlInterface::PREFIX_MEDIUM_PREFERENCE:
		flags |= kPreferenceMedium;
		break;

	case NCPControlInterface::PREFIX_LOW_PREFRENCE:
		flags |= kPreferenceLow;
		break;
	}

	if (prefix_flag_set.count(NCPControlInterface::PREFIX_FLAG_ON_MESH)) {
		flags |= kFlagOnMesh;
	}

	if (prefix_flag_set.count(NCPControlInterface::PREFIX_FLAG_DEFAULT_ROUTE)) {
		flags |= kFlagDefaultRoute;
	}

	if (prefix_flag_set.count(NCPControlInterface::PREFIX_FLAG_CONFIGURE)) {
		flags |= kFlagConfigure;
	}

	if (prefix_flag_set.count(NCPControlInterface::PREFIX_FLAG_DHCP)) {
		flags |= kFlagDHCP;
	}

	if (prefix_flag_set.count(NCPControlInterface::PREFIX_FLAG_SLAAC)) {
		flags |= kFlagSLAAC;
	}

	if (prefix_flag_set.count(NCPControlInterface::PREFIX_FLAG_PREFERRED)) {
		flags |= kFlagPreferred;
	}

	return flags;
}

bool
NCPInstanceBase::OnMeshPrefixEntry::operator==(const OnMeshPrefixEntry &entry) const
{
	bool retval = true;

	// Check the originator first.
	if (get_origin() != entry.get_origin()) {
		retval = false;
		goto bail;
	}

	// If the entry is from NCP then ensure other fields also match.
	if (is_from_ncp()) {
		if ((mFlags != entry.mFlags) || (mStable != entry.mStable) || (mRloc != entry.mRloc)) {
			retval = false;
			goto bail;
		}
	}

bail:
	return retval;
}

std::string
NCPInstanceBase::OnMeshPrefixEntry::get_description(const IPv6Prefix &prefix, bool align) const
{
	char c_string[300];

	if (align) {
		snprintf(
			c_string,
			sizeof(c_string),
			"%-22s prefix_len:%-4d origin:%-8s stable:%s %s rloc:0x%04x",
			in6_addr_to_string(prefix.get_prefix()).c_str(),
			prefix.get_length(),
			get_origin_as_string().c_str(),
			is_stable() ? "yes" : "no ",
			on_mesh_prefix_flags_to_string(get_flags(), true).c_str(),
			get_rloc()
		);

	} else {
		snprintf(
			c_string,
			sizeof(c_string),
			"\"%s\", origin:%s, stable:%s, flags:%s, rloc:0x%04x",
			prefix.to_string().c_str(),
			get_origin_as_string().c_str(),
			is_stable() ? "yes" : "no",
			on_mesh_prefix_flags_to_string(get_flags()).c_str(),
			get_rloc()
		);
	}

	return std::string(c_string);
}

bool
NCPInstanceBase::OffMeshRouteEntry::operator==(const OffMeshRouteEntry &entry) const
{
	bool retval = true;

	// Check the originator first.
	if (get_origin() != entry.get_origin()) {
		retval = false;
		goto bail;
	}

	// If the entry is from NCP then ensure other fields also match.
	if (is_from_ncp()) {

		// Note that we intentionally don't check `mNextHopIsHost` as the RLOC16 value
		// assigned to the node can be changed (e.g., after a re-attach) causing the
		// `mNextHopIsHost` value to also change.

		if ((mPreference != entry.mPreference) || (mStable != entry.mStable) || (mRloc != entry.mRloc)) {
			retval = false;
			goto bail;
		}
	}

bail:
	return retval;
}

std::string
NCPInstanceBase::OffMeshRouteEntry::get_description(const IPv6Prefix &route, bool align) const
{
	char c_string[300];

	if (align) {
		snprintf(c_string, sizeof(c_string), "%-26s origin:%-8s stable:%s preference:%-7s rloc:0x%04x next_hop_is_host:%s",
			route.to_string().c_str(), get_origin_as_string().c_str(), is_stable() ? "yes" : "no ",
			NCPControlInterface::external_route_priority_to_string(get_preference()).c_str(), get_rloc(),
			is_next_hop_host() ? "yes" : "no ");

	} else {
		snprintf(c_string, sizeof(c_string), "\"%s\", origin:%s, stable:%s, preference:%s, rloc:0x%04x, next_hop_is_host:%s",
			route.to_string().c_str(), get_origin_as_string().c_str(), is_stable() ? "yes" : "no",
			NCPControlInterface::external_route_priority_to_string(get_preference()).c_str(), get_rloc(),
			is_next_hop_host() ? "yes" : "no");
	}

	return std::string(c_string);
}

bool
NCPInstanceBase::ServiceEntryBase::operator==(const ServiceEntryBase &entry) const
{
	return (mEnterpriseNumber == entry.mEnterpriseNumber &&
		mServiceData == entry.mServiceData);

}

std::string
NCPInstanceBase::ServiceEntryBase::get_description(void) const
{
	char c_string[100];

	snprintf(c_string, sizeof(c_string), "EnterpriseNumber:%u", mEnterpriseNumber);

	return std::string(c_string);
}

std::string
NCPInstanceBase::ServiceEntry::get_description(void) const
{
	char c_string[100];
	const std::string base_string = ServiceEntryBase::get_description();

	snprintf(c_string, sizeof(c_string), "%s, Stable:%d", base_string.c_str(), mStable);

	return std::string(c_string);
}

std::string
NCPInstanceBase::InterfaceRouteEntry::get_description(const IPv6Prefix &route, bool align) const
{
	char c_string[300];

	if (align) {
		snprintf(c_string, sizeof(c_string), "%-26s metric:%-6d", route.to_string().c_str(), mMetric);
	} else {
		snprintf(c_string, sizeof(c_string), "\"%s\", metric:%d", route.to_string().c_str(), mMetric);
	}

	return std::string(c_string);
}

// ========================================================================
// MARK: Global Entries Management

void
NCPInstanceBase::refresh_address_route_prefix_entries(void)
{
	if (mRequestRouteRefresh) {
		mRequestRouteRefresh = false;
		refresh_routes_on_interface();
	}
}

void
NCPInstanceBase::remove_all_address_prefix_route_entries(void)
{
	syslog(LOG_INFO, "Removing all address/prefix/route entries");

	// Unicast addresses
	for (
		std::map<struct in6_addr, UnicastAddressEntry>::iterator iter = mUnicastAddresses.begin();
		iter != mUnicastAddresses.end();
		++iter
	) {
		mPrimaryInterface->remove_address(&iter->first, iter->second.get_prefix_len());
	}

	// Multicast addresses
	for (
		std::map<struct in6_addr, MulticastAddressEntry>::iterator iter = mMulticastAddresses.begin();
		iter != mMulticastAddresses.end();
		++iter
	) {
		mPrimaryInterface->leave_multicast_address(&iter->first);
	}

	// Routes
	for (
		std::map<IPv6Prefix, InterfaceRouteEntry>::iterator iter = mInterfaceRoutes.begin();
		iter != mInterfaceRoutes.end();
		++iter
	) {
		mPrimaryInterface->remove_route(&iter->first.get_prefix(), iter->first.get_length(), iter->second.get_metric());
	}

	memset(&mNCPLinkLocalAddress, 0, sizeof(mNCPLinkLocalAddress));
	memset(&mNCPMeshLocalAddress, 0, sizeof(mNCPMeshLocalAddress));

	mUnicastAddresses.clear();
	mMulticastAddresses.clear();
	mOnMeshPrefixes.clear();
	mOffMeshRoutes.clear();
	mInterfaceRoutes.clear();
	mServiceEntries.clear();
}

void
NCPInstanceBase::remove_ncp_originated_address_prefix_route_entries(void)
{
	bool did_remove = false;

	// We remove all of the addresses/prefixes/routes that originated from the NCP.

	syslog(LOG_INFO, "Removing all NCP originated addresses");

	// Unicast addresses
	do {
		std::map<struct in6_addr, UnicastAddressEntry>::iterator iter;

		did_remove = false;

		for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); iter++) {
			if (!iter->second.is_from_ncp()) {
				continue;
			}

			syslog(LOG_INFO, "UnicastAddresses: Removing %s", iter->second.get_description(iter->first).c_str());
			mPrimaryInterface->remove_address(&iter->first, iter->second.get_prefix_len());

			mUnicastAddresses.erase(iter);
			did_remove = true;
			break;
		}
	} while (did_remove);

	// Multicast addresses
	do {
		std::map<struct in6_addr, MulticastAddressEntry>::iterator iter;

		did_remove = false;

		for (iter = mMulticastAddresses.begin(); iter != mMulticastAddresses.end(); iter++) {
			if (!iter->second.is_from_ncp()) {
				continue;
			}

			syslog(LOG_INFO, "MulticastAddresses: Removing %s", iter->second.get_description(iter->first).c_str());
			mPrimaryInterface->leave_multicast_address(&iter->first);
			mMulticastAddresses.erase(iter);
			did_remove = true;
			break;
		}
	} while (did_remove);

	// On-Mesh Prefixes
	do {
		std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;

		did_remove = false;

		for (iter = mOnMeshPrefixes.begin(); iter != mOnMeshPrefixes.end(); iter++) {
			if (!iter->second.is_from_ncp()) {
				continue;
			}

			syslog(LOG_INFO, "OnMeshPrefixes: Removing %s", iter->second.get_description(iter->first).c_str());
			mOnMeshPrefixes.erase(iter);
			did_remove = true;
			break;
		}
	} while (did_remove);

	// Off-Mesh Routes
	do {
		std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter;

		did_remove = false;

		for (iter = mOffMeshRoutes.begin(); iter != mOffMeshRoutes.end(); iter++) {
			if (!iter->second.is_from_ncp()) {
				continue;
			}

			syslog(LOG_INFO, "OffMeshRoutes: Removing %s", iter->second.get_description(iter->first).c_str());
			mOffMeshRoutes.erase(iter);
			did_remove = true;
			mRequestRouteRefresh = true;
			break;
		}
	} while (did_remove);

	// Services
	do {
		std::vector<ServiceEntry>::iterator iter;

		did_remove = false;

		for (iter = mServiceEntries.begin(); iter != mServiceEntries.end(); ++iter) {
			if (!iter->is_from_ncp()) {
				continue;
			}

			syslog(LOG_INFO, "Services: Removing %s", iter->get_description().c_str());
			mServiceEntries.erase(iter);
			did_remove = true;
			break;
		}
	} while (did_remove);
}

void
NCPInstanceBase::restore_address_prefix_route_entries_on_ncp(void)
{
	syslog(LOG_INFO, "Restoring interface/user originated address/prefix/route entries on NCP");

	// Unicast addresses
	for (
		std::map<struct in6_addr, UnicastAddressEntry>::iterator iter = mUnicastAddresses.begin();
		iter != mUnicastAddresses.end();
		++iter
	) {
		if (iter->second.is_from_interface() || iter->second.is_from_user()) {
			add_address_on_ncp_and_update_prefixes(iter->first, iter->second);
		}
	}

	// Multicast addresses
	for (
		std::map<struct in6_addr, MulticastAddressEntry>::iterator iter = mMulticastAddresses.begin();
		iter != mMulticastAddresses.end();
		++iter
	) {
		if (iter->second.is_from_interface() || iter->second.is_from_user()) {
			add_multicast_address_on_ncp(iter->first,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "restoring multicast address", NilReturn()));
		}
	}

	// On-mesh prefixes
	for (
		std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter = mOnMeshPrefixes.begin();
		iter != mOnMeshPrefixes.end();
		++iter
	) {
		if (iter->second.is_from_interface() || iter->second.is_from_user()) {
			add_on_mesh_prefix_on_ncp(iter->first.get_prefix(), iter->first.get_length(),
				iter->second.get_flags(), iter->second.is_stable(),
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "restoring on-mesh prefix", NilReturn()));
		}
	}

	// Off-mesh-routes
	for (
		std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter = mOffMeshRoutes.begin();
		iter != mOffMeshRoutes.end();
		++iter
	) {
		if (iter->second.is_from_interface() || iter->second.is_from_user()) {
			add_route_on_ncp(iter->first.get_prefix(), iter->first.get_length(), iter->second.get_preference(), iter->second.is_stable(),
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "restoring off-mesh route", NilReturn()));
		}
	}

	// Services
	for (
		std::vector<ServiceEntry>::iterator iter = mServiceEntries.begin();
		iter != mServiceEntries.end();
		++iter
	) {
		if (iter->is_from_interface() || iter->is_from_user()) {
			add_service_on_ncp(iter->get_enterprise_number(), iter->get_service_data(), iter->is_stable(), iter->get_server_data(),
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "restoring service", NilReturn()));
		}
	}
}

void
NCPInstanceBase::check_ncp_entry_update_status(int status, std::string operation, CallbackWithStatus cb)
{
	if (status != kWPANTUNDStatus_Ok)
	{
		syslog(LOG_ERR, "Error %s (%d) while performing \"%s\" on NCP - Resetting NCP.", wpantund_status_to_cstr(status),
			status, operation.c_str());

		ncp_is_misbehaving();
	}

	cb(status);
}

// ========================================================================
// MARK: Unicast IPv6 Address Management

void
NCPInstanceBase::unicast_address_was_added(Origin origin, const struct in6_addr &address, uint8_t prefix_len,
	uint32_t valid_lifetime, uint32_t preferred_lifetime)
{
	if (((origin == kOriginPrimaryInterface) || (origin == kOriginUser))
	    && mFilterUserAddedLinkLocalIPv6Address
	    && IN6_IS_ADDR_LINKLOCAL(&address)) {

		syslog(LOG_INFO, "UnicastAddresses: Skipping user/interface added link-local IPv6 address %s",
		       in6_addr_to_string(address).c_str());

		goto bail;
	}

	if (!mUnicastAddresses.count(address)) {
		UnicastAddressEntry entry(origin, prefix_len, valid_lifetime, preferred_lifetime);

		mUnicastAddresses[address] = entry;
		syslog(LOG_INFO, "UnicastAddresses: Adding %s", entry.get_description(address).c_str());

		// Add the address on NCP or primary interface (depending on origin).

		if ((origin == kOriginThreadNCP) || (origin == kOriginUser)) {
			mPrimaryInterface->add_address(&address, prefix_len);
		}

		if (((origin == kOriginPrimaryInterface) && mAutoUpdateInterfaceIPv6AddrsOnNCP) || (origin == kOriginUser)) {
			add_address_on_ncp_and_update_prefixes(address, entry);
		}
	}

bail:
	return;
}

void
NCPInstanceBase::unicast_address_was_removed(Origin origin, const struct in6_addr &address)
{
	if (mUnicastAddresses.count(address)) {
		UnicastAddressEntry entry = mUnicastAddresses[address];

		// Allow address remove if origin is user, or if it matches the
		// originator of the entry (when it was previously added).

		if ((origin == kOriginUser) || (origin == entry.get_origin())) {
			syslog(LOG_INFO, "UnicastAddresses: Removing %s", entry.get_description(address).c_str());
			mUnicastAddresses.erase(address);

			if ((origin == kOriginThreadNCP) || (origin == kOriginUser)) {
				mPrimaryInterface->remove_address(&address, entry.get_prefix_len());
			}

			if ((origin == kOriginPrimaryInterface) || (origin == kOriginUser)) {
				remove_address_on_ncp_and_update_prefixes(address, entry);
			}
		}
	}
}

void
NCPInstanceBase::add_address_on_ncp_and_update_prefixes(const in6_addr &address, const UnicastAddressEntry &entry)
{
	add_unicast_address_on_ncp(address, entry.get_prefix_len(),
		boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding unicast address", NilReturn()));

	// Update the prefix if entry is not from NCP and
	// if address is not link-local and prefix does not
	// match mesh-local prefix.

	if (!entry.is_from_ncp()
	   && !IN6_IS_ADDR_LINKLOCAL(&address)
	   && (!buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix)) || (0 != memcmp(mNCPV6Prefix, &address, sizeof(mNCPV6Prefix))))
	) {
		struct in6_addr prefix = address;
		uint8_t flags = OnMeshPrefixEntry::kFlagOnMesh
		              | OnMeshPrefixEntry::kFlagPreferred;

		if (mSetDefaultRouteForAutoAddedPrefix) {
			flags |= OnMeshPrefixEntry::kFlagDefaultRoute;
		}

		if (mSetSLAACForAutoAddedPrefix) {
			flags |= OnMeshPrefixEntry::kFlagSLAAC;
		}

		in6_addr_apply_mask(prefix, entry.get_prefix_len());
		on_mesh_prefix_was_added(entry.get_origin(), address, entry.get_prefix_len(), flags);
	}
}

void
NCPInstanceBase::remove_address_on_ncp_and_update_prefixes(const in6_addr &address, const UnicastAddressEntry &entry)
{
	remove_unicast_address_on_ncp(address, entry.get_prefix_len(),
		boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "removing unicast address", NilReturn()));

	if (!entry.is_from_ncp()
	   && !IN6_IS_ADDR_LINKLOCAL(&address)
	   && (!buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix)) || (0 != memcmp(mNCPV6Prefix, &address, sizeof(mNCPV6Prefix))))
	) {
		struct in6_addr prefix = address;
		uint8_t flags = OnMeshPrefixEntry::kFlagOnMesh | OnMeshPrefixEntry::kFlagPreferred;

		if (mSetDefaultRouteForAutoAddedPrefix) {
			flags |= OnMeshPrefixEntry::kFlagDefaultRoute;
		}

		if (mSetSLAACForAutoAddedPrefix) {
			flags |= OnMeshPrefixEntry::kFlagSLAAC;
		}

		in6_addr_apply_mask(prefix, entry.get_prefix_len());
		on_mesh_prefix_was_removed(entry.get_origin(), address, entry.get_prefix_len(), flags);
	}
}

// ========================================================================
// MARK: Multicast IPv6 Address Management

void
NCPInstanceBase::check_multicast_address_add_status(int status, const struct in6_addr address, CallbackWithStatus cb)
{
	if (status != kWPANTUNDStatus_Ok)
	{
		syslog(LOG_ERR, "Error %s (%d) adding user-added multicast address on NCP, removing the address ",
			wpantund_status_to_cstr(status),  status);

		multicast_address_was_left(kOriginUser, address);
	}

	cb(status);
}

void
NCPInstanceBase::multicast_address_was_joined(Origin origin, const struct in6_addr &address, CallbackWithStatus cb)
{
	if (!mMulticastAddresses.count(address)) {
		MulticastAddressEntry entry(origin);
		mMulticastAddresses[address] = entry;
		syslog(LOG_INFO, "MulticastAddresses: Adding %s", entry.get_description(address).c_str());

		if ((origin == kOriginThreadNCP) || (origin == kOriginUser)) {
			mPrimaryInterface->join_multicast_address(&address);
		}
		if (origin == kOriginPrimaryInterface) {
			add_multicast_address_on_ncp(address,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding multicast address", cb));
		} else if (origin == kOriginUser) {
			add_multicast_address_on_ncp(address,
				boost::bind(&NCPInstanceBase::check_multicast_address_add_status, this, _1, address, cb));
		} else {
			cb(kWPANTUNDStatus_Ok);
		}
	} else {
		cb(kWPANTUNDStatus_Already);
	}
}

void
NCPInstanceBase::multicast_address_was_left(Origin origin, const struct in6_addr &address, CallbackWithStatus cb)
{
	if (mMulticastAddresses.count(address)) {
		MulticastAddressEntry entry = mMulticastAddresses[address];

		// Allow remove if origin is user, or if it matches the
		// originator of the entry (when it was previously added).

		if ((origin == kOriginUser) || (origin == entry.get_origin())) {
			syslog(LOG_INFO, "MulticastAddresses: Removing %s", entry.get_description(address).c_str());
			mMulticastAddresses.erase(address);

			if ((origin == kOriginThreadNCP) || (origin == kOriginUser)) {
				mPrimaryInterface->leave_multicast_address(&address);
			}

			if ((origin == kOriginPrimaryInterface) || (origin == kOriginUser)) {
				remove_multicast_address_on_ncp(address,
					boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "removing multicast address", cb));
			} else {
				cb(kWPANTUNDStatus_Ok);
			}
		} else {
			cb(kWPANTUNDStatus_InvalidArgument);
		}
	} else {
		cb(kWPANTUNDStatus_Already);
	}

}

// ========================================================================
// MARK: On-Mesh Prefix Management

// Checks whether there is a unicast address matching the given `prefix` from any origin.
bool
NCPInstanceBase::has_address_with_prefix(const IPv6Prefix &prefix)
{
	bool rval = false;
	std::map<struct in6_addr, UnicastAddressEntry>::const_iterator iter;

	for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); ++iter) {
		IPv6Prefix addr_prefix(iter->first, iter->second.get_prefix_len());

		if (addr_prefix == prefix) {
			rval = true;
			break;
		}
	}

	return rval;
}

// Searches for a unicast address in `mUnicastAddresses` map matching the given `prefix` from the given `origin`.
std::map<struct in6_addr, NCPInstanceBase::UnicastAddressEntry>::iterator
NCPInstanceBase::find_address_with_prefix(const IPv6Prefix &prefix, Origin origin)
{
	std::map<struct in6_addr, UnicastAddressEntry>::iterator iter;

	for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); ++iter) {
		IPv6Prefix addr_prefix(iter->first, iter->second.get_prefix_len());

		if ((iter->second.get_origin() == origin) && (addr_prefix == prefix)) {
			break;
		}
	}

	return iter;
}

// Checks whether the given `prefix` is present in the `mOnMeshPrefixes` multimap with SLAAC and on-mesh flags set.
bool
NCPInstanceBase::has_slaac_on_mesh_prefix(const IPv6Prefix &prefix)
{
	bool rval = false;
	std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;

	iter = mOnMeshPrefixes.lower_bound(prefix);

	if (iter != mOnMeshPrefixes.end()) {
		std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator upper_iter = mOnMeshPrefixes.upper_bound(prefix);

		for (; iter != upper_iter; iter++) {
			if (iter->second.is_slaac() && iter->second.is_on_mesh()) {
				rval = true;
				break;
			}
		}
	}

	return rval;
}

// Searches for a given prefix entry in the `mOnMeshPrefixes` multimap.
std::multimap<NCPInstanceBase::IPv6Prefix, NCPInstanceBase::OnMeshPrefixEntry>::iterator
NCPInstanceBase::find_prefix_entry(const IPv6Prefix &prefix, const OnMeshPrefixEntry &entry)
{
	std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;

	iter = mOnMeshPrefixes.lower_bound(prefix);

	if (iter != mOnMeshPrefixes.end()) {
		std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator upper_iter = mOnMeshPrefixes.upper_bound(prefix);

		for (; iter != upper_iter; iter++) {
			if (iter->second == entry) {
				break;
			}
		}

		if (iter == upper_iter) {
			iter = mOnMeshPrefixes.end();
		}
	}

	return iter;
}

void
NCPInstanceBase::on_mesh_prefix_was_added(Origin origin, const struct in6_addr &prefix_address, uint8_t prefix_len,
	uint8_t flags, bool stable, uint16_t rloc16, CallbackWithStatus cb)
{
	IPv6Prefix prefix(prefix_address, prefix_len);
	OnMeshPrefixEntry entry(origin, flags, stable, rloc16);
	std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;

	iter = find_prefix_entry(prefix, entry);

	if (iter == mOnMeshPrefixes.end()) {
		mOnMeshPrefixes.insert(std::make_pair(prefix, entry));
		syslog(LOG_INFO, "OnMeshPrefixes: Adding %s", entry.get_description(prefix).c_str());

		if (origin != kOriginThreadNCP) {
			add_on_mesh_prefix_on_ncp(prefix.get_prefix(), prefix.get_length(), flags, stable,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding on-mesh prefix", cb));
		} else {
			cb(kWPANTUNDStatus_Ok);
		}

		if (mAutoAddOnMeshPrefixesAsInterfaceRoutes) {
			mRequestRouteRefresh = true;
		}

	} else {
		cb(kWPANTUNDStatus_Ok);
	}

	if (mAutoAddSLAACAddress && !mNCPHandlesSLAAC && entry.is_on_mesh() && entry.is_slaac()
		&& prefix.get_length() == kSLAACPrefixLength && !has_address_with_prefix(prefix)
	) {
		struct in6_addr address = make_slaac_addr_from_eui64(prefix.get_prefix().s6_addr, mMACAddress);
		syslog(LOG_NOTICE, "Pushing a new SLAAC address %s/%d to NCP", in6_addr_to_string(address).c_str(), prefix_len);
		add_unicast_address_on_ncp(address, prefix_len,
			boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding SLAAC address", NilReturn()));
		// Note that SLAAC address is added with origin NCP independent of the origin of the prefix.
		unicast_address_was_added(kOriginThreadNCP, address, prefix_len);
	}
}

void
NCPInstanceBase::on_mesh_prefix_was_removed(Origin origin, const struct in6_addr &prefix_address, uint8_t prefix_len,
	uint8_t flags, bool stable, uint16_t rloc16, CallbackWithStatus cb)
{
	IPv6Prefix prefix(prefix_address, prefix_len);
	OnMeshPrefixEntry entry(origin, flags, stable, rloc16);
	std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;

	iter = find_prefix_entry(prefix, entry);

	if (iter != mOnMeshPrefixes.end()) {
		syslog(LOG_INFO, "OnMeshPrefixes: Removing %s", entry.get_description(prefix).c_str());
		mOnMeshPrefixes.erase(iter);

		if (origin != kOriginThreadNCP) {
			remove_on_mesh_prefix_on_ncp(prefix.get_prefix(), prefix.get_length(),
				entry.get_flags(), entry.is_stable(),
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "removing on-mesh prefix", cb));
		} else {
			cb(kWPANTUNDStatus_Ok);
		}

		if (mAutoAddOnMeshPrefixesAsInterfaceRoutes) {
			mRequestRouteRefresh = true;
		}

		if (entry.is_on_mesh() && entry.is_slaac() && prefix.get_length() == kSLAACPrefixLength
			&& !has_slaac_on_mesh_prefix(prefix)
		) {
			std::map<struct in6_addr, UnicastAddressEntry>::iterator addr_iter;

			// Note that SLAAC addresses are added with origin NCP.
			addr_iter = find_address_with_prefix(prefix, kOriginThreadNCP);

			if (addr_iter != mUnicastAddresses.end()) {
				struct in6_addr address = addr_iter->first;
				syslog(LOG_NOTICE, "Removing SLAAC address %s/%d from NCP", in6_addr_to_string(address).c_str(), prefix_len);
				remove_unicast_address_on_ncp(address, prefix_len,
					boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "removing SLAAC address", NilReturn()));
				unicast_address_was_removed(kOriginThreadNCP, address);
			}
		}
	} else {
		cb(kWPANTUNDStatus_Ok);
	}
}

// ========================================================================
// MARK: Route Management

// Searches for a given route entry in the `mOffMeshRoutes` multimap.
std::multimap<NCPInstanceBase::IPv6Prefix, NCPInstanceBase::OffMeshRouteEntry>::iterator
NCPInstanceBase::find_route_entry(const IPv6Prefix &route, const OffMeshRouteEntry &entry)
{
	std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter;

	iter = mOffMeshRoutes.lower_bound(route);

	if (iter != mOffMeshRoutes.end()) {
		std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator upper_iter = mOffMeshRoutes.upper_bound(route);

		for (; iter != upper_iter; iter++) {
			if (iter->second == entry) {
				break;
			}
		}

		if (iter == upper_iter) {
			iter = mOffMeshRoutes.end();
		}
	}

	return iter;
}

void
NCPInstanceBase::route_was_added(Origin origin, const struct in6_addr &route_prefix, uint8_t prefix_len, RoutePreference preference,
	bool stable, uint16_t rloc16, bool next_hop_is_host, CallbackWithStatus cb)
{
	OffMeshRouteEntry entry(origin, preference, stable, rloc16, next_hop_is_host);
	IPv6Prefix route(route_prefix, prefix_len);
	std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter;

	iter = find_route_entry(route, entry);

	if (iter == mOffMeshRoutes.end()) {
		mOffMeshRoutes.insert(std::make_pair(route, entry));
		mRequestRouteRefresh = true;
		syslog(LOG_INFO, "OffMeshRoutes: Adding %s", entry.get_description(route).c_str());

		if (origin != kOriginThreadNCP) {
			add_route_on_ncp(route.get_prefix(), prefix_len, preference, stable,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding off-mesh route", cb));

		} else {
			cb(kWPANTUNDStatus_Ok);
		}
	} else {
		cb(kWPANTUNDStatus_Ok);
	}
}

void
NCPInstanceBase::route_was_removed(Origin origin, const struct in6_addr &route_prefix, uint8_t prefix_len,
	RoutePreference preference, bool stable, uint16_t rloc16, CallbackWithStatus cb)
{
	OffMeshRouteEntry entry(origin, preference, stable, rloc16);
	std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter;
	IPv6Prefix route(route_prefix, prefix_len);

	iter = find_route_entry(route, entry);

	if (iter != mOffMeshRoutes.end()) {
		syslog(LOG_INFO, "OffMeshRoutes: Removing %s", iter->second.get_description(route).c_str());
		mOffMeshRoutes.erase(iter);
		mRequestRouteRefresh = true;

		if (origin != kOriginThreadNCP) {
			remove_route_on_ncp(route.get_prefix(), prefix_len, preference, stable,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "removing off-mesh route", cb));

		} else {
			cb(kWPANTUNDStatus_Ok);
		}
	} else {
		cb(kWPANTUNDStatus_Ok);
	}
}

// Decides if the given route should be added on the primary interface, if we need to add the route `metric` is also
// updated.
bool
NCPInstanceBase::should_add_route_on_interface(const IPv6Prefix &route, uint32_t &metric)
{
	bool should_add = false;

	if (mAutoAddOffMeshRoutesOnInterface) {
		bool route_added_by_device = false;
		bool route_added_by_others = false;
		RoutePreference preference_device = NCPControlInterface::ROUTE_LOW_PREFRENCE;
		RoutePreference preference_others = NCPControlInterface::ROUTE_LOW_PREFRENCE;

		std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter, sub_iter, upper_iter;

		for (iter = mOffMeshRoutes.begin(); iter != mOffMeshRoutes.end(); iter = upper_iter) {

			// Get the iterator pointing to the first element that is greater than current key/route.
			upper_iter = mOffMeshRoutes.upper_bound(iter->first);

			// Skip all elements for which the multimap key does not match the route.
			if (iter->first != route) {
				continue;
			}

			// Iterate through all multimap elements with same key (i.e., same route).
			for (sub_iter = iter; sub_iter != upper_iter; ++sub_iter) {

				if ((sub_iter->second.get_origin() != kOriginThreadNCP) || sub_iter->second.is_next_hop_host()) {
					route_added_by_device = true;
					if (preference_device < sub_iter->second.get_preference()) {
						preference_device = sub_iter->second.get_preference();
					}
				} else {
					route_added_by_others = true;
					if (preference_others < sub_iter->second.get_preference()) {
						preference_others = sub_iter->second.get_preference();
					}
				}
			}
		}

		// The route should be added on host primary interface, if it
		// is added by at least one other device within the network and,
		//  (a) either it is not added by host/this-device, or
		//  (b) if it is also added by device then
		//      - filtering of self added routes is not enabled, and
		//      - it is added at lower preference level.

		if (route_added_by_others) {
			if (!route_added_by_device || (!mFilterSelfAutoAddedOffMeshRoutes && (preference_others > preference_device))) {
				should_add = true;
			}
		}

		// If the route should be added, map the preference level to route metric.

		if (should_add) {
			switch (preference_others) {
			case NCPControlInterface::ROUTE_LOW_PREFRENCE:
				metric = InterfaceRouteEntry::kRouteMetricLow;
				break;

			case NCPControlInterface::ROUTE_MEDIUM_PREFERENCE:
				metric = InterfaceRouteEntry::kRouteMetricMedium;
				break;

			case NCPControlInterface::ROUTE_HIGH_PREFERENCE:
				metric = InterfaceRouteEntry::kRouteMetricHigh;
				break;
			}
		}
	}

	if (!should_add && mAutoAddOnMeshPrefixesAsInterfaceRoutes) {

		// If the "AutoAddOnMeshPrefixesAsInterfaceRoutes" feature is enabled
		// check whether the route matches any of on-mesh prefixes from NCP
		// (with on-mesh flag set).

		std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;

		for (iter = mOnMeshPrefixes.begin(); iter != mOnMeshPrefixes.end(); iter++) {
			if ((iter->first == route) && iter->second.is_from_ncp() && iter->second.is_on_mesh()) {
				should_add = true;
				metric = InterfaceRouteEntry::kRouteMetricMedium;
				break;
			}
		}
	}

	return should_add;
}

void
NCPInstanceBase::refresh_routes_on_interface(void)
{
	bool did_remove = false;
	uint32_t metric;

	if (mAutoAddOffMeshRoutesOnInterface || mAutoAddOnMeshPrefixesAsInterfaceRoutes) {
		syslog(LOG_INFO, "Refreshing routes on primary interface");
	}

	// First, check all currently added routes on primary interface and remove any one that is no longer valid.

	do {
		std::map<IPv6Prefix, InterfaceRouteEntry>::iterator iter;

		did_remove = false;

		for (iter = mInterfaceRoutes.begin(); iter != mInterfaceRoutes.end(); iter++) {

			// If the route should not be added on interface or it has been added with
			// incorrect metric value, remove it from the `mInterfaceRoute` list (note
			// that it will be re-added if route metric is changed).

			if (!should_add_route_on_interface(iter->first, metric)
				|| (metric != iter->second.get_metric())
			) {
				syslog(LOG_INFO, "InterfaceRoutes: Removing %s", iter->second.get_description(iter->first).c_str());
				mPrimaryInterface->remove_route(&iter->first.get_prefix(), iter->first.get_length(),
					iter->second.get_metric());
				mInterfaceRoutes.erase(iter);

				// We removed an element from `mInterfaceRoutes` while iterating over it,
				// so we break from the `for` loop and start the iteration over again on the
				// new updated `mInterfaceRoutes` list.

				did_remove = true;
				break;
			}
		}
	} while (did_remove);

	if (mAutoAddOffMeshRoutesOnInterface) {
		// Iterate through all off-mesh routes to check whether a new route should be added on interface.

		std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter, upper_iter;

		for (iter = mOffMeshRoutes.begin(); iter != mOffMeshRoutes.end(); iter = upper_iter) {

			// Get the iterator pointing to the first element that is greater than current key/route.
			upper_iter = mOffMeshRoutes.upper_bound(iter->first);

			if (should_add_route_on_interface(iter->first, metric)
				&& (mInterfaceRoutes.count(iter->first) == 0)
			) {
				syslog(LOG_INFO, "InterfaceRoutes: Adding %s", iter->second.get_description(iter->first).c_str());
				mPrimaryInterface->add_route(&iter->first.get_prefix(), iter->first.get_length(), metric);
				mInterfaceRoutes[iter->first] = InterfaceRouteEntry(metric);
			}
		}
	}

	if (mAutoAddOnMeshPrefixesAsInterfaceRoutes) {
		// Iterate through all on-mesh prefixes to check whether a new route should be added on interface.

		std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;

		for (iter = mOnMeshPrefixes.begin(); iter != mOnMeshPrefixes.end(); iter++) {

			if (should_add_route_on_interface(iter->first, metric)
				&& (mInterfaceRoutes.count(iter->first) == 0)
			) {
				syslog(LOG_INFO, "InterfaceRoutes: Adding route for prefix %s",
					iter->second.get_description(iter->first).c_str());
				mPrimaryInterface->add_route(&iter->first.get_prefix(), iter->first.get_length(), metric);
				mInterfaceRoutes[iter->first] = InterfaceRouteEntry(metric);
			}
		}
	}
}

// ========================================================================
// MARK: Service management

void
NCPInstanceBase::service_was_added(Origin origin, uint32_t enterprise_number, const Data &service_data, bool stable,
					const Data &server_data, CallbackWithStatus cb)
{
	ServiceEntry entry(origin, enterprise_number, service_data, stable, server_data);

	if (std::find(mServiceEntries.begin(), mServiceEntries.end(), entry) == mServiceEntries.end()) {
		mServiceEntries.push_back(entry);
		syslog(LOG_INFO, "Services: Adding %s", entry.get_description().c_str());

		if (origin != kOriginThreadNCP) {
			add_service_on_ncp(enterprise_number, service_data, stable, server_data,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding service", cb));

		} else {
			cb(kWPANTUNDStatus_Ok);
		}
	} else {
		syslog(LOG_DEBUG, "Services: Adding %s, already present", entry.get_description().c_str());
		cb(kWPANTUNDStatus_Ok);
	}
}

void
NCPInstanceBase::service_was_removed(Origin origin, uint32_t enterprise_number, const Data &service_data, CallbackWithStatus cb)
{
	ServiceEntryBase entry(origin, enterprise_number, service_data);

	const std::vector<ServiceEntry>::iterator iter = std::find(mServiceEntries.begin(), mServiceEntries.end(), entry);

	if (iter != mServiceEntries.end()) {
		syslog(LOG_INFO, "Services: Removing %s", iter->get_description().c_str());
		mServiceEntries.erase(iter);

		if (origin != kOriginThreadNCP) {
			remove_service_on_ncp(enterprise_number, service_data,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "removing service", cb));
		} else {
			cb(kWPANTUNDStatus_Ok);
		}
	} else {
		syslog(LOG_DEBUG, "Services: Removing %s, already removed", entry.get_description().c_str());
		cb(kWPANTUNDStatus_Ok);
	}
}
