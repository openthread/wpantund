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
 *      This file contains the interface for a C++ wrapper around the
 *      `tunnel.c`/`tunnel.h` interface.
 *
 */

#ifndef __wpantund__TunnelInterface__
#define __wpantund__TunnelInterface__

#include "tunnel.h"
#include "netif-mgmt.h"
#include <cstdio>
#include <string>
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>
#include "UnixSocket.h"
#include <set>
#include "IPv6Helpers.h"
#include <boost/signals2/signal.hpp>

class TunnelIPv6Interface : public nl::UnixSocket
{

public:
	TunnelIPv6Interface(const std::string& interface_name = "", int mtu = 1280);

	virtual ~TunnelIPv6Interface();

	const std::string& get_interface_name(void);

	int get_last_error(void);

	bool is_up(void);
	int set_up(bool isUp);

	bool is_running(void);
	int set_running(bool isRunning);

	// This "online" is a bit of a mashup of "up" and "running".
	// This is going to be phased out.
	bool is_online(void);
	int set_online(bool isOnline);

	const struct in6_addr& get_realm_local_address()const;

	bool add_address(const struct in6_addr *addr, int prefixlen = 64);
	bool remove_address(const struct in6_addr *addr, int prefixlen = 64);

	bool add_route(const struct in6_addr *route, int prefixlen, uint32_t metric);
	bool remove_route(const struct in6_addr *route, int prefixlen, uint32_t metric);

	bool join_multicast_address(const struct in6_addr *addr);
	bool leave_multicast_address(const struct in6_addr *addr);

	virtual void reset(void);
	virtual ssize_t write(const void* data, size_t len);
	virtual ssize_t read(void* data, size_t len);

	virtual int process(void);
	virtual int update_fd_set(fd_set *read_fd_set, fd_set *write_fd_set, fd_set *error_fd_set, int *max_fd, cms_t *timeout);

public: // Signals

	boost::signals2::signal<void(const struct in6_addr&, uint8_t)> mUnicastAddressWasAdded;
	boost::signals2::signal<void(const struct in6_addr&, uint8_t)> mUnicastAddressWasRemoved;
	boost::signals2::signal<void(const struct in6_addr&)> mMulticastAddressWasJoined;
	boost::signals2::signal<void(const struct in6_addr&)> mMulticastAddressWasLeft;

	// void linkStateChanged(isUp, isRunning);
	boost::signals2::signal<void(bool, bool)> mLinkStateChanged;

private:
	void setup_signals(void);
	void setup_mld_listener(void);

	void processNetlinkFD(void);
	void processMLDMonitorFD(void);

	void on_link_state_changed(bool isUp, bool isRunning);
	void on_address_added(const struct in6_addr &address, uint8_t prefix_len);
	void on_multicast_address_joined(const struct in6_addr &address);
	void on_address_removed(const struct in6_addr &address, uint8_t prefix_len);
	void on_multicast_address_left(const struct in6_addr &address);

private:
	std::string mInterfaceName;
	int mLastError;

	int mNetlinkFD;
	int mNetifMgmtFD;
	int mMLDMonitorFD;

	bool mIsRunning;
	bool mIsUp;

	struct Entry {
		int mPrefixLen;
		enum State {
			kWaitingToAdd,            // Waiting to add the address on interface when it becomes online
			kWaitingForAddConfirm,    // Address was added, waiting for callback to confirm the address add
		} mState;

		Entry(State state = kWaitingToAdd, int prefix_len = 64) :
			mPrefixLen(prefix_len),
			mState(state) { }
	};

	std::map<struct in6_addr, Entry> mUnicastAddresses;
	std::map<struct in6_addr, Entry> mPendingMulticastAddresses;

	enum {
		kICMPv6MLDv2Type = 143,
		kICMPv6MLDv2RecordChangeToExcludeType = 3,
		kICMPv6MLDv2RecordChangeToIncludeType = 4,
	};
};
#endif /* defined(__wpantund__TunnelInterface__) */
