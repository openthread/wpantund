/*
 *
 * Copyright (c) 2019 Google
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
 *      Module sending ICMPv6 Router Advertisement.
 *
 */


#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include <errno.h>
#include <syslog.h>

#include <netinet/icmp6.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "netif-mgmt.h"
#include "NCPTypes.h"
#include "ICMP6RouterAdvertiser.h"
#include "NCPInstanceBase.h"


using namespace nl;
using namespace nl::wpantund;

nl::wpantund::ICMP6RouterAdvertiser::ICMP6RouterAdvertiser(NCPInstanceBase* instance)
	: mInstance(instance)
	, mNetifMgmtFD(netif_mgmt_open())
	, mEnabled(false)
	, mTxPeriod(DEFAULT_ROUTER_ADV_TX_PERIOD)
	, mDefaultRoutePreference(0)
	, mDefaultRouteLifetime(0)
	, mShouldAddRouteInfoOption(true)
	, mStateChanged(false)
{
	mSocket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

	if (mSocket >= 0) {
		int hop_limit = 255;

		if (setsockopt(mSocket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hop_limit, sizeof(hop_limit)) < 0) {
			syslog(LOG_WARNING, "Failed to set multicast hops on socket");
		}
	}
}

nl::wpantund::ICMP6RouterAdvertiser::~ICMP6RouterAdvertiser(void)
{
	netif_mgmt_close(mNetifMgmtFD);
	close(mSocket);
}

void
nl::wpantund::ICMP6RouterAdvertiser::clear(void)
{
	clear_netifs();
	clear_prefixes();
}

void
nl::wpantund::ICMP6RouterAdvertiser::set_tx_period(uint32_t period)
{
	if (period > MAX_ROUTER_ADV_TX_PERIOD) {
		mTxPeriod = MAX_ROUTER_ADV_TX_PERIOD;
	} else if (period < MIN_ROUTER_ADV_TX_PERIOD) {
		mTxPeriod = MIN_ROUTER_ADV_TX_PERIOD;
	} else {
		mTxPeriod = period;
	}

	mStateChanged = true;
}

std::list<std::string>
nl::wpantund::ICMP6RouterAdvertiser::get_prefix_list(void) const
{
	std::list<std::string> prefix_list;
	char c_string[300];

	for (std::list<Prefix>::const_iterator it = mPrefixes.begin(); it != mPrefixes.end(); it++) {
		snprintf(c_string, sizeof(c_string), "prefix: %s/%d, flags:[ %s%s], valid lifetime:%u, preferred lifetime:%u",
				in6_addr_to_string(it->mPrefix).c_str(), it->mPrefixLength,
				it->mFlagOnLink ? "on-link " : "", it->mFlagAutoAddressConfig ? "auto ": "",
				it->mValidLifetime, it->mPreferredLifetime);
		prefix_list.push_back(std::string(c_string));
	}

	return prefix_list;
}

void
nl::wpantund::ICMP6RouterAdvertiser::add_prefix(
	const struct in6_addr &prefix,
	uint8_t prefix_len,
	uint32_t valid_lifetime,
	uint32_t preferred_lifetime,
	bool flag_on_link,
	bool flag_auto_config
) {
	Prefix entry;

	remove_prefix(prefix, prefix_len);

	entry.mPrefix = prefix;
	entry.mPrefixLength = prefix_len;
	entry.mValidLifetime = valid_lifetime;
	entry.mPreferredLifetime = preferred_lifetime;
	entry.mFlagOnLink = flag_on_link;
	entry.mFlagAutoAddressConfig = flag_auto_config;

	in6_addr_apply_mask(entry.mPrefix, entry.mPrefixLength);

	remove_prefix(entry.mPrefix, entry.mPrefixLength);
	mPrefixes.push_back(entry);

	mStateChanged = true;
}


void
nl::wpantund::ICMP6RouterAdvertiser::remove_prefix(const struct in6_addr &prefix, uint8_t prefix_len)
{
	struct in6_addr masked_prefix = prefix;

	in6_addr_apply_mask(masked_prefix, prefix_len);

	for (std::list<Prefix>::iterator iter = mPrefixes.begin(); iter != mPrefixes.end(); iter++) {
		if ((iter->mPrefixLength == prefix_len) && (iter->mPrefix == masked_prefix)) {
			mPrefixes.erase(iter);
			mStateChanged = true;
			break;
		}
	}
}

void
nl::wpantund::ICMP6RouterAdvertiser::clear_prefixes(void)
{
	if (!mPrefixes.empty()) {
		mPrefixes.clear();
		mStateChanged = true;
	}
}

void
nl::wpantund::ICMP6RouterAdvertiser::send_router_advert(const char *netif_name)
{
	enum {
		ROUTE_INFO_OPTION_TYPE = 24,
		ROUTE_INFO_OPTION_PRF_HIGH   = (0x1 << 3),
		ROUTE_INFO_OPTION_PRF_MEDIUM = (0x0 << 3),
		ROUTE_INFO_OPTION_PRF_LOW    = (0x3 << 3),
		ROUTE_INFO_OPTION_LIFETIME   = 3600, // in seconds

		HW_ADDRESS_SIZE = 6,
	};

	int ifindex;
	uint8_t hw_addr[HW_ADDRESS_SIZE];
	Data msg;
	struct sockaddr_in6 saddr;
	struct nd_router_advert ra;
	struct nd_opt_hdr opt_hdr;
	struct
	{
		uint8_t  mType;
		uint8_t  mLength; // (in units of 8 octets)
		uint8_t  mPrefixLength;
		uint8_t  mPreferenceFlags;
		uint32_t mLifetime;
		/* followed by the prefix (variable-length) */
	} opt_route_info;
	std::map<NCPInstanceBase::IPv6Prefix, NCPInstanceBase::InterfaceRouteEntry>::iterator iter;
	int num_route_info_opt = 0;
	int num_prefix_info_opt = 0;

	if ((mDefaultRouteLifetime == 0) && mPrefixes.empty() &&
		(!mShouldAddRouteInfoOption || mInstance->mInterfaceRoutes.empty())
	) {
		goto bail;
	}

	ifindex = netif_mgmt_get_ifindex(mNetifMgmtFD, netif_name);

	if (ifindex < 0) {
		syslog(LOG_WARNING, "Could not find ifindex for netif \"%s\"", netif_name);
		goto bail;
	}

	if (netif_mgmt_get_hw_address(mNetifMgmtFD, netif_name, hw_addr) < 0) {
		syslog(LOG_WARNING, "Could not get the hw address for netif \"%s\"", netif_name);
		goto bail;
	}

	// Prepare the dest IPv6 address ff02::1
	memset(&saddr, 0 , sizeof(saddr));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_addr.s6_addr[0]  = 0xff;
	saddr.sin6_addr.s6_addr[1]  = 0x02;
	saddr.sin6_addr.s6_addr[15] = 0x01;
	saddr.sin6_scope_id = ifindex;

	// Prepare the Router Advertisement ICMP6 message header
	ra.nd_ra_type = ND_ROUTER_ADVERT;
	ra.nd_ra_code = 0;
	ra.nd_ra_cksum = 0;
	ra.nd_ra_curhoplimit = 255;

	if (mDefaultRoutePreference > 0) {
		ra.nd_ra_flags_reserved = ROUTE_INFO_OPTION_PRF_HIGH;
	} else if (mDefaultRoutePreference == 0) {
		ra.nd_ra_flags_reserved = ROUTE_INFO_OPTION_PRF_MEDIUM;
	} else {
		ra.nd_ra_flags_reserved = ROUTE_INFO_OPTION_PRF_LOW;
	}

	ra.nd_ra_router_lifetime = htons(mDefaultRouteLifetime);
	ra.nd_ra_reachable = htonl(ROUTE_INFO_OPTION_LIFETIME);
	ra.nd_ra_retransmit = htonl(0);

	msg.append(reinterpret_cast<uint8_t *>(&ra), sizeof(ra));

	// Prepare the `Source Link-Layer Address` option
	opt_hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	opt_hdr.nd_opt_len = 1; // in units of 8 octets
	msg.append(reinterpret_cast<uint8_t *>(&opt_hdr), sizeof(opt_hdr));
	msg.append(hw_addr, sizeof(hw_addr));

	// Prepare `Prefix Info` options
	for (std::list<Prefix>::iterator it = mPrefixes.begin(); it != mPrefixes.end(); ++it) {
		struct nd_opt_prefix_info opt_pi;

		memset(&opt_pi, 0, sizeof(opt_pi));

		opt_pi.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		opt_pi.nd_opt_pi_len = 4; // in units of 8 octets

		opt_pi.nd_opt_pi_prefix_len = it->mPrefixLength;

		if (it->mFlagOnLink) {
			opt_pi.nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
		}

		if (it->mFlagAutoAddressConfig) {
			opt_pi.nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		}

		opt_pi.nd_opt_pi_valid_time = htonl(it->mValidLifetime);
		opt_pi.nd_opt_pi_preferred_time = htonl(it->mPreferredLifetime);
		memcpy(&opt_pi.nd_opt_pi_prefix, &it->mPrefix, sizeof(struct in6_addr));

		msg.append(reinterpret_cast<uint8_t *>(&opt_pi), sizeof(opt_pi));

		num_prefix_info_opt++;
	}

	// Prepare `Route Info` option for each interface route
	if (mShouldAddRouteInfoOption) {
		for (iter = mInstance->mInterfaceRoutes.begin(); iter != mInstance->mInterfaceRoutes.end(); ++iter) {
			uint8_t prefix_len = iter->first.get_length();
			uint32_t metric = iter->second.get_metric();

			opt_route_info.mType = ROUTE_INFO_OPTION_TYPE;

			if (prefix_len > 64) {
				opt_route_info.mLength = 3;
			} else if (prefix_len > 0) {
				opt_route_info.mLength = 2;
			} else {
				opt_route_info.mLength = 1;
			}

			opt_route_info.mPrefixLength = prefix_len;

			// Note that smaller metric is higher preference.
			if (metric < NCPInstanceBase::InterfaceRouteEntry::kRouteMetricMedium) {
				opt_route_info.mPreferenceFlags = ROUTE_INFO_OPTION_PRF_HIGH;
			} else if (metric < NCPInstanceBase::InterfaceRouteEntry::kRouteMetricLow) {
				opt_route_info.mPreferenceFlags = ROUTE_INFO_OPTION_PRF_MEDIUM;
			} else {
				opt_route_info.mPreferenceFlags = ROUTE_INFO_OPTION_PRF_LOW;
			}

			opt_route_info.mLifetime = htonl(ROUTE_INFO_OPTION_LIFETIME);

			msg.append(reinterpret_cast<uint8_t *>(&opt_route_info), sizeof(opt_route_info));

			if (prefix_len > 64) {
				msg.append(iter->first.get_prefix().s6_addr, 16);
			} else if (prefix_len > 0) {
				msg.append(iter->first.get_prefix().s6_addr, 8);
			}

			num_route_info_opt++;
		}
	}

	if (sendto(mSocket, msg.data(), msg.size(), 0, reinterpret_cast<struct sockaddr *>(&saddr), sizeof(saddr)) < 0) {
		syslog(LOG_WARNING, "could not send router advert on netif \"%s\"", netif_name);
		goto bail;
	}

	syslog(LOG_INFO, "Sent ICMP6 RouterAdvert on \"%s\" (options: %d prefix info, %d route info)", netif_name,
		num_prefix_info_opt, num_route_info_opt);

bail:
	return;
}

int
nl::wpantund::ICMP6RouterAdvertiser::vprocess_event(int event, va_list args)
{
	EH_BEGIN();

	while (true) {
		EH_WAIT_UNTIL(ncp_state_is_associated(mInstance->get_ncp_state()));

		EH_WAIT_UNTIL_WITH_TIMEOUT(mTxPeriod, mStateChanged);
		mStateChanged = false;

		if (mEnabled) {
			for (std::set<std::string>::iterator iter = mNetifs.begin(); iter != mNetifs.end(); ++iter) {
				send_router_advert(iter->c_str());
			}
		}
   }

   EH_END();
}

