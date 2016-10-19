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
 *      This file contains the implementation for a C++ wrapper around the
 *      `tunnel.c`/`tunnel.h` interface.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include "TunnelIPv6Interface.h"
#include <syslog.h>
#include "IPv6Helpers.h"

#if __linux__
#include <asm/types.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#endif

#include <sys/select.h>

#ifndef O_NONBLOCK
#define O_NONBLOCK          O_NDELAY
#endif

TunnelIPv6Interface::TunnelIPv6Interface(const std::string& interface_name, int mtu):
	UnixSocket(tunnel_open(interface_name.c_str()), true),
	mInterfaceName(interface_name),
	mLastError(0),
	mNetlinkFD(-1)
{
	if (0 > mFDRead) {
		throw std::invalid_argument("Unable to open tunnel interface");
	}

	{
		char ActualInterfaceName[TUNNEL_MAX_INTERFACE_NAME_LEN] = "";
		int ret = 0;
		ret = tunnel_get_name(mFDRead, ActualInterfaceName, sizeof(ActualInterfaceName));
		if (ret) {
			syslog(LOG_WARNING,
				   "TunnelIPv6Interface: Couldn't get tunnel name! errno=%d, %s",
				   errno,
				   strerror(errno));
		} else if (mInterfaceName != ActualInterfaceName) {
			syslog(LOG_WARNING,
				   "TunnelIPv6Interface: Couldn't create tunnel named \"%s\", got \"%s\" instead!",
				   mInterfaceName.c_str(),
				   ActualInterfaceName);
			mInterfaceName = ActualInterfaceName;
		}
	}

	tunnel_set_mtu(mFDRead, mtu);

	setup_signals();
}

TunnelIPv6Interface::~TunnelIPv6Interface()
{
	close(mNetlinkFD);
}

#if __linux__ // --------------------------------------------------------------

#define LCG32(x)		((uint32_t)(x)*1664525+1013904223)

void
TunnelIPv6Interface::setup_signals()
{
	int status;
	int fd;
	struct sockaddr_nl la;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	require(fd != -1, bail);

	memset(&la, 0, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_pad = 0;
	la.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR;

	// We calculate the PID in a pseudo-random way based on the
	// address pointer and the actual process ID.
	la.nl_pid = LCG32(getpid()) ^ LCG32((uint32_t)reinterpret_cast<uintptr_t>(this));

	status = bind(fd, (struct sockaddr*) &la, sizeof(la));

	require(status != -1, bail);

	// Success!
	IGNORE_RETURN_VALUE(fcntl(fd, F_SETFL, O_NONBLOCK));

	mNetlinkFD = fd;
	fd = -1;

bail:

	// Cleanup (If necessary)
	if (fd > 0) {
		close(fd);
	}

	return;
}

int
TunnelIPv6Interface::process(void)
{
	uint8_t buffer[1024];
	ssize_t buffer_len(-1);

	if (mNetlinkFD >= 0) {
		buffer_len = recv(mNetlinkFD, buffer, sizeof(buffer), 0);
	}

	if (buffer_len > 0) {
		struct nlmsghdr *nlp;
		struct rtmsg *rtp;
		int rta_len;
		struct rtattr *rta;

		nlp = (struct nlmsghdr *)buffer;
		for (;NLMSG_OK(nlp, buffer_len); nlp=NLMSG_NEXT(nlp, buffer_len))
		{
			if (nlp->nlmsg_type == RTM_NEWADDR || nlp->nlmsg_type == RTM_DELADDR) {
				struct ifaddrmsg *ifaddr = (struct ifaddrmsg *)NLMSG_DATA(nlp);
				char ifnamebuf[IF_NAMESIZE];
				const char *ifname = if_indextoname(ifaddr->ifa_index, ifnamebuf);
				struct in6_addr addr;

				if ((ifname == NULL) || (get_interface_name() != ifname)) {
					continue;
				}

				// get RTNETLINK message header
				// get start of attributes
				rta = (struct rtattr *) IFA_RTA(ifaddr);

				// get length of attributes
				rta_len = IFA_PAYLOAD(nlp);

				for(;RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
					switch(rta->rta_type) {
					case IFA_ADDRESS:
					case IFA_LOCAL:
					case IFA_BROADCAST:
					case IFA_ANYCAST:
						memcpy(addr.s6_addr, RTA_DATA(rta), sizeof(addr));

						if (nlp->nlmsg_type == RTM_NEWADDR) {
							mAddressWasAdded(addr, ifaddr->ifa_prefixlen);
						} else if (nlp->nlmsg_type == RTM_DELADDR) {
							mAddressWasRemoved(addr, ifaddr->ifa_prefixlen);
						}
						break;
					default:
						break;
					}
				}
			}
		}
	}

	return nl::UnixSocket::process();
}

#else // ----------------------------------------------------------------------

void
TunnelIPv6Interface::setup_signals()
{
	// Unknown platform.
}

int
TunnelIPv6Interface::process(void)
{
	return nl::UnixSocket::process();
}

#endif // ---------------------------------------------------------------------

int
TunnelIPv6Interface::update_fd_set(fd_set *read_fd_set, fd_set *write_fd_set, fd_set *error_fd_set, int *max_fd, cms_t *timeout)
{
	if (read_fd_set && (mNetlinkFD >= 0)) {
		FD_SET(mNetlinkFD, read_fd_set);

		if ((max_fd != NULL)) {
			*max_fd = std::max(*max_fd, mNetlinkFD);
		}
	}

	return nl::UnixSocket::update_fd_set(read_fd_set, write_fd_set, error_fd_set, max_fd, timeout);
}

const std::string&
TunnelIPv6Interface::get_interface_name(void)
{
	return mInterfaceName;
}

int
TunnelIPv6Interface::get_last_error(void)
{
	return mLastError;
}

bool
TunnelIPv6Interface::is_online(void)
{
	return tunnel_is_online(mFDRead);
}

int
TunnelIPv6Interface::set_online(bool online)
{
	int ret = 0;

	if (online) {
		syslog(LOG_INFO, "Bringing interface %s online. . .", mInterfaceName.c_str());

		require_action((ret = tunnel_bring_online(mFDRead)) == 0, bail, mLastError = errno);
		require_action(tunnel_is_online(mFDRead), bail, mLastError = errno);

		require_action_string(tunnel_is_online(mFDRead), bail, mLastError = errno, "Tunnel went offline unexpectedly!");

		std::set<struct in6_addr>::const_iterator iter;
		for (iter = mAddresses.begin(); iter != mAddresses.end(); ++iter) {
			(void)tunnel_add_address(mFDRead, iter->s6_addr, 64);
		}
	} else {
		syslog(LOG_INFO, "Taking interface %s offline. . .", mInterfaceName.c_str());

		require_action((ret = tunnel_bring_offline(mFDRead)) == 0, bail, mLastError = errno);
	}

bail:
	return ret;
}

void
TunnelIPv6Interface::reset(void)
{
	syslog(LOG_INFO, "Resetting interface %s. . .", mInterfaceName.c_str());

	while (!mAddresses.empty()) {
		const struct in6_addr addr(*mAddresses.begin());
		remove_address(&addr);
	}

	set_online(false);
}


bool
TunnelIPv6Interface::add_address(const struct in6_addr *addr, int prefixlen)
{
	bool ret = false;

	require_action(!IN6_IS_ADDR_UNSPECIFIED(addr), bail, mLastError = EINVAL);

	if (!mAddresses.count(*addr)) {
		syslog(
			LOG_INFO,
		   "TunnelIPv6Interface: Adding address \"%s\" to interface \"%s\".",
		   in6_addr_to_string(*addr).c_str(),
		   mInterfaceName.c_str()
		);

		mAddresses.insert(*addr);

		if (is_online()) {
			require_noerr_action(tunnel_add_address(mFDRead, addr->s6_addr, prefixlen), bail, mLastError = errno);
		}
	}


	ret = true;

bail:
	return ret;

}


bool
TunnelIPv6Interface::remove_address(const struct in6_addr *addr, int prefixlen)
{
	bool ret = false;

	require_action(!IN6_IS_ADDR_UNSPECIFIED(addr), bail, mLastError = EINVAL);

	syslog(
		LOG_INFO,
	   "TunnelIPv6Interface: Removing address \"%s\" from interface \"%s\".",
	   in6_addr_to_string(*addr).c_str(),
	   mInterfaceName.c_str()
	);

	mAddresses.erase(*addr);

	if (tunnel_remove_address(mFDRead, addr->s6_addr) != 0) {
		mLastError = errno;
		goto bail;
	}

	ret = true;

bail:
	return ret;

}

bool
TunnelIPv6Interface::add_route(const struct in6_addr *route, int prefixlen)
{
	bool ret = false;

	syslog(
		LOG_INFO,
		"TunnelIPv6Interface: Adding route prefix \"%s/%d\" -> \"%s\".",
		in6_addr_to_string(*route).c_str(),
		prefixlen,
		mInterfaceName.c_str()
	);

	if (is_online()) {
		require_noerr_action(tunnel_add_route(mFDRead, route->s6_addr, prefixlen), bail, mLastError = errno);
	}

	ret = true;

bail:
	return ret;
}

bool
TunnelIPv6Interface::remove_route(const struct in6_addr *route, int prefixlen)
{
	bool ret = false;

	syslog(
		LOG_INFO,
		"TunnelIPv6Interface: Removing route prefix \"%s/%d\" -> \"%s\".",
		in6_addr_to_string(*route).c_str(),
		prefixlen,
		mInterfaceName.c_str()
	);

	if (is_online()) {
		require_noerr_action(tunnel_remove_route(mFDRead, route->s6_addr, prefixlen), bail, mLastError = errno);
	}

	ret = true;

bail:
	return ret;
}

ssize_t
TunnelIPv6Interface::read(void* data, size_t len)
{
	ssize_t ret = nl::UnixSocket::read(data, len);
	uint8_t *data_bytes = static_cast<uint8_t*>(data);

	// Remove any subheader, if present.
	if ((ret >= 4) && (data_bytes[0] == 0) && (data_bytes[1] == 0)) {
		ret -= 4;
		memmove(data, static_cast<const void*>(data_bytes + 4), ret);
	}

	return ret;
}

ssize_t
TunnelIPv6Interface::write(const void* data, size_t len)
{
#ifdef __APPLE__
	const uint8_t* const data_bytes = static_cast<const uint8_t*>(data);

	if ((data_bytes[0] != 0) || (data_bytes[0] != 0)) {
		// The utun interface on OS X needs this header.
		// Linux seems to be able to infer the type of the packet
		// with no problems.
		uint8_t packet[len + 4];
		packet[0] = 0;
		packet[1] = 0;
		packet[2] = (PF_INET6 << 8) & 0xFF;
		packet[3] = (PF_INET6 << 0) & 0xFF;
		memcpy(static_cast<void*>(packet + 4), data, len);
		ssize_t ret = nl::UnixSocket::write(packet, len + 4);
		return (ret >= 4)?(ret - 4):(-1);
	}
#endif
	return nl::UnixSocket::write(data, len);
}
