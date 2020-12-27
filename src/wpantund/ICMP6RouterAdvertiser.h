/*
 *
 * Copyright (c) 2019 Google.
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

#ifndef __wpantund__ICMP6RouterAdvetiser__
#define __wpantund__ICMP6RouterAdvetiser__

#include <list>
#include <set>
#include <string>

#include <netinet/in.h>

#include "EventHandler.h"

namespace nl {
namespace wpantund {

class NCPInstanceBase;

class ICMP6RouterAdvertiser : public EventHandler
{
public:
	enum {
		MIN_ROUTER_ADV_TX_PERIOD     = 4,    // in seconds
		MAX_ROUTER_ADV_TX_PERIOD     = 1800, // in seconds
		DEFAULT_ROUTER_ADV_TX_PERIOD = 10,   // in seconds
	};

	ICMP6RouterAdvertiser(NCPInstanceBase* instance);
	~ICMP6RouterAdvertiser(void);

	void clear(void);

	void set_enabled(bool enabled) { mEnabled = enabled; mStateChanged = true; }
	bool is_enabled(void) const { return mEnabled; }

	const std::set<std::string> &get_netifs(void) const { return mNetifs; }
	void add_netif(const std::string &netif) { mNetifs.insert(netif);  mStateChanged = true;}
	void remove_netif(const std::string &netif) { mNetifs.erase(netif); }
	void clear_netifs(void) { mNetifs.clear(); }

	//  RA period in seconds
	void set_tx_period(uint32_t period);
	uint32_t get_tx_period(void) const { return mTxPeriod; }

	void set_default_route_preference(int prf) { mDefaultRoutePreference = prf; mStateChanged = true; }
	int get_default_route_preference(void) const { return mDefaultRoutePreference; }

	void set_default_route_lifetime(uint16_t lifetime) { mDefaultRouteLifetime = lifetime; mStateChanged = true; }
	uint16_t get_default_route_lifetime(void) const { return mDefaultRouteLifetime; }

	void set_should_add_route_info_option(bool enable) { mShouldAddRouteInfoOption = enable; mStateChanged = true; }
	bool get_should_add_route_info_option(void) const { return mShouldAddRouteInfoOption; }

	std::list<std::string> get_prefix_list(void) const;

	void add_prefix(const struct in6_addr &prefix, uint8_t prefix_len, uint32_t valid_lifetime,
		uint32_t preferred_lifetime, bool flag_on_link, bool flag_auto_config);
	void remove_prefix(const struct in6_addr &prefix, uint8_t prefix_len);
	void clear_prefixes(void);

	void signal_routes_changed(void) { mStateChanged = true; }

	virtual int vprocess_event(int event, va_list args);

private:
	struct Prefix {
		struct in6_addr mPrefix;
		uint8_t mPrefixLength;
		uint32_t mValidLifetime;
		uint32_t mPreferredLifetime;
		bool mFlagOnLink;
		bool mFlagAutoAddressConfig;
	};

	void send_router_advert(const char *netif_name);

	NCPInstanceBase *mInstance;
	int mSocket;
	int mNetifMgmtFD;
	bool mEnabled;
	std::set<std::string> mNetifs;
	uint32_t mTxPeriod;
	int mDefaultRoutePreference;
	uint16_t mDefaultRouteLifetime;
	bool mShouldAddRouteInfoOption;
	bool mStateChanged;
	std::list<Prefix> mPrefixes;
};

}; // namespace wpantund
}; // namespace nl

#endif /* defined(__wpantund__ICMP6RouterAdvetiser__) */
