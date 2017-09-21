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

std::string
NCPInstanceBase::OnMeshPrefixEntry::get_description(const struct in6_addr &address, bool align) const
{
	char c_string[300];

	if (align) {
		snprintf(c_string, sizeof(c_string), "%-22s prefix_len:%-4d origin:%-8s stable:%s %s",
			in6_addr_to_string(address).c_str(), get_prefix_len(), get_origin_as_string().c_str(),
			is_stable() ? "yes" : "no ", on_mesh_prefix_flags_to_string(get_flags(), true).c_str());

	} else {
		snprintf(c_string, sizeof(c_string), "\"%s/%d\", origin:%s, stable:%s, flags:%s, ",
			in6_addr_to_string(address).c_str(), get_prefix_len(), get_origin_as_string().c_str(),
			is_stable() ? "yes" : "no", on_mesh_prefix_flags_to_string(get_flags()).c_str());
	}

	return std::string(c_string);
}

// ========================================================================
// MARK: Global Entries Management

void
NCPInstanceBase::refresh_address_entries(void)
{
	// Here is where we would do any periodic global address bookkeeping,
	// which doesn't appear to be necessary yet but may become necessary
	// in the future.
}

void
NCPInstanceBase::remove_all_address_prefix_entries(void)
{
	syslog(LOG_INFO, "Removing all address/prefix entries");

	for (
		std::map<struct in6_addr, UnicastAddressEntry>::iterator iter = mUnicastAddresses.begin();
		iter != mUnicastAddresses.end();
		++iter
	) {
		mPrimaryInterface->remove_address(&iter->first, iter->second.get_prefix_len());
	}

	for (
		std::map<struct in6_addr, MulticastAddressEntry>::iterator iter = mMulticastAddresses.begin();
		iter != mMulticastAddresses.end();
		++iter
	) {
		mPrimaryInterface->leave_multicast_address(&iter->first);
	}

	memset(&mNCPLinkLocalAddress, 0, sizeof(mNCPLinkLocalAddress));
	memset(&mNCPMeshLocalAddress, 0, sizeof(mNCPMeshLocalAddress));

	mUnicastAddresses.clear();
	mMulticastAddresses.clear();
	mOnMeshPrefixes.clear();
}

void
NCPInstanceBase::remove_ncp_originated_addresses(void)
{
	bool did_remove = false;

	// We remove all of the addresses/prefixes that originated
	// from the NCP.

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
		std::map<struct in6_addr, OnMeshPrefixEntry>::iterator iter;

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
}

void
NCPInstanceBase::restore_address_prefix_entries_on_ncp(void)
{
	syslog(LOG_INFO, "Restoring interface/user originated address/prefix entries on NCP");

	for (
		std::map<struct in6_addr, UnicastAddressEntry>::iterator iter = mUnicastAddresses.begin();
		iter != mUnicastAddresses.end();
		++iter
	) {
		if (iter->second.is_from_interface() || iter->second.is_from_user()) {
			add_address_on_ncp_and_update_prefixes(iter->first, iter->second);
		}
	}

	for (
		std::map<struct in6_addr, MulticastAddressEntry>::iterator iter = mMulticastAddresses.begin();
		iter != mMulticastAddresses.end();
		++iter
	) {
		if (iter->second.is_from_interface() || iter->second.is_from_user()) {
			add_multicast_address_on_ncp(iter->first);
		}
	}

	for (
		std::map<struct in6_addr, OnMeshPrefixEntry>::iterator iter = mOnMeshPrefixes.begin();
		iter != mOnMeshPrefixes.end();
		++iter
	) {
		if (iter->second.is_from_interface() || iter->second.is_from_user()) {
			add_on_mesh_prefix_on_ncp(iter->first, iter->second.get_prefix_len(), iter->second.get_flags(), iter->second.is_stable());
		}
	}
}

void
NCPInstanceBase::check_ncp_entry_update_status(int status, std::string operation, CallbackWithStatus cb)
{
	if (status == kWPANTUNDStatus_Timeout)
	{
		syslog(LOG_ERR, "Timed out while performing \"%s\" on NCP - Resetting NCP.", operation.c_str());
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
	if (!mUnicastAddresses.count(address)) {
		UnicastAddressEntry entry(origin, prefix_len, valid_lifetime, preferred_lifetime);

		mUnicastAddresses[address] = entry;
		syslog(LOG_INFO, "UnicastAddresses: Adding %s", entry.get_description(address).c_str());

		// Add the address on NCP or primary interface (depending on origin).

		if ((origin == kOriginThreadNCP) || (origin == kOriginUser)) {
			mPrimaryInterface->add_address(&address, prefix_len);
		}

		if ((origin == kOriginPrimaryInterface) || (origin == kOriginUser)) {
			add_address_on_ncp_and_update_prefixes(address, entry);
		}
	}
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
	remove_unicast_address_on_ncp(address, entry.get_prefix_len());

	if (!entry.is_from_ncp()
	   && !IN6_IS_ADDR_LINKLOCAL(&address)
	   && (!buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix)) || (0 != memcmp(mNCPV6Prefix, &address, sizeof(mNCPV6Prefix))))
	) {
		struct in6_addr prefix = address;
		in6_addr_apply_mask(prefix, entry.get_prefix_len());
		on_mesh_prefix_was_removed(entry.get_origin(), address, entry.get_prefix_len());
	}
}

// ========================================================================
// MARK: Multicast IPv6 Address Management

void
NCPInstanceBase::multicast_address_was_joined(Origin origin, const struct in6_addr &address)
{
	if (!mMulticastAddresses.count(address)) {
		MulticastAddressEntry entry(origin);
		mMulticastAddresses[address] = entry;
		syslog(LOG_INFO, "MulticastAddresses: Adding %s", entry.get_description(address).c_str());

		if ((origin == kOriginThreadNCP) || (origin == kOriginUser)) {
			mPrimaryInterface->join_multicast_address(&address);
		}

		if ((origin == kOriginPrimaryInterface) || (origin == kOriginUser)) {
			add_multicast_address_on_ncp(address);
		}
	}
}

void
NCPInstanceBase::multicast_address_was_left(Origin origin, const struct in6_addr &address)
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
				remove_multicast_address_on_ncp(address);
			}
		}
	}
}

// ========================================================================
// MARK: On-Mesh Prefix Management

bool
NCPInstanceBase::lookup_address_for_prefix(struct in6_addr *address, const struct in6_addr &prefix, int prefix_len)
{
	struct in6_addr masked_prefix(prefix);

	in6_addr_apply_mask(masked_prefix, prefix_len);

	std::map<struct in6_addr, UnicastAddressEntry>::const_iterator iter;
	for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); ++iter) {
		struct in6_addr iter_prefix(iter->first);
		in6_addr_apply_mask(iter_prefix, prefix_len);

		if (iter_prefix == masked_prefix) {
			if (address != NULL) {
				*address = iter->first;
			}
			return true;
		}
	}
	return false;
}

void
NCPInstanceBase::on_mesh_prefix_was_added(Origin origin, const struct in6_addr &prefix_address, uint8_t prefix_len,
	uint8_t flags, bool stable, CallbackWithStatus cb)
{
	struct in6_addr prefix(prefix_address);
	OnMeshPrefixEntry entry;

	in6_addr_apply_mask(prefix, prefix_len);

	if (!mOnMeshPrefixes.count(prefix)) {
		entry = OnMeshPrefixEntry(origin, flags, prefix_len, stable);

		mOnMeshPrefixes[prefix] = entry;
		syslog(LOG_INFO, "OnMeshPrefixes: Adding %s", entry.get_description(prefix).c_str());

		if ((origin == kOriginPrimaryInterface) || (origin == kOriginUser)) {
			add_on_mesh_prefix_on_ncp(prefix, prefix_len, flags, stable,
				boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding on-mesh prefix", cb));
		} else {
			cb(kWPANTUNDStatus_Ok);
		}
	} else {
		entry = mOnMeshPrefixes[prefix];
		cb(kWPANTUNDStatus_Already);
	}

	if (entry.is_on_mesh() && entry.is_slaac()
		&& !lookup_address_for_prefix(NULL, prefix, prefix_len)
	) {
		struct in6_addr address = make_slaac_addr_from_eui64(prefix.s6_addr, mMACAddress);
		syslog(LOG_NOTICE, "Pushing a new SLAAC address %s/%d to NCP", in6_addr_to_string(address).c_str(), prefix_len);
		add_unicast_address_on_ncp(address, prefix_len,
			boost::bind(&NCPInstanceBase::check_ncp_entry_update_status, this, _1, "adding SLAAC address", NilReturn()));
		unicast_address_was_added(kOriginThreadNCP, address, prefix_len);
	}
}

void
NCPInstanceBase::on_mesh_prefix_was_removed(Origin origin, const struct in6_addr &prefix_address, uint8_t prefix_len,
	CallbackWithStatus cb)
{
	struct in6_addr prefix(prefix_address);
	in6_addr_apply_mask(prefix, prefix_len);

	if (mOnMeshPrefixes.count(prefix)) {
		OnMeshPrefixEntry entry = mOnMeshPrefixes[prefix];
		uint8_t prefix_len = entry.get_prefix_len();

		// Allow remove if request is coming from the originator of the prefix, or if
		// the prefix was added from an added IPv6 address on interface and now
		// user is removing it.

		if ((entry.get_origin() == origin) || (entry.is_from_interface() && (origin == kOriginUser))) {
			struct in6_addr address;

			syslog(LOG_INFO, "OnMeshPrefixes: Removing %s", entry.get_description(prefix).c_str());
			mOnMeshPrefixes.erase(prefix);

			if ((origin == kOriginPrimaryInterface) || (origin == kOriginUser)) {
				remove_on_mesh_prefix_on_ncp(prefix, entry.get_prefix_len(), entry.get_flags(), entry.is_stable(), cb);
			} else {
				cb(kWPANTUNDStatus_Ok);
			}

			if (lookup_address_for_prefix(&address, prefix, prefix_len)
				&& entry.is_slaac() && entry.is_on_mesh()
			) {
				syslog(LOG_NOTICE, "Removing SLAAC address %s/%d from NCP", in6_addr_to_string(address).c_str(), prefix_len);
				remove_unicast_address_on_ncp(address, prefix_len);
			}
		} else {
			cb(kWPANTUNDStatus_InvalidForCurrentState);
		}
	} else {
		cb(kWPANTUNDStatus_Already);
	}
}
