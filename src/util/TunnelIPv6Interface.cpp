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
#include <ifaddrs.h>
#endif

#include <sys/select.h>

#ifndef O_NONBLOCK
#define O_NONBLOCK          O_NDELAY
#endif

namespace {

	const char* kMLDv2MulticastAddress= "ff02::16";

	const char *kFilterMulticastAddresses[] = {
			kMLDv2MulticastAddress,
			"ff02::01", //Link local all nodes
			"ff02::02", //Link local all routers
			"ff03::01", //realm local all nodes
			"ff03::02", //realm local all routers
			"ff03::fc", //realm local all mpl
	};

	struct MLDv2Header {
		uint8_t mType;
		uint8_t _rsv0;
		uint16_t mChecksum;
		uint16_t _rsv1;
		uint16_t mNumRecords;
	} __attribute__((packed));

	struct MLDv2Record {
		uint8_t mRecordType;
		uint8_t mAuxDataLen;
		uint16_t mNumSources;
		struct in6_addr mMulticastAddress;
		struct in6_addr mSourceAddresses[];
	} __attribute__((packed));

} // namespace

static bool
is_addr_multicast(const struct in6_addr &address)
{
	return (address.s6_addr[0] == 0xff);
}

TunnelIPv6Interface::TunnelIPv6Interface(const std::string& interface_name, int mtu):
#if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	UnixSocket(open("/dev/null",O_RDWR), true),
#else
	UnixSocket(tunnel_open(interface_name.c_str()), true),
#endif
	mInterfaceName(interface_name),
	mLastError(0),
	mNetlinkFD(-1),
#if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	mNetifMgmtFD(-1),
#else
	mNetifMgmtFD(netif_mgmt_open()),
#endif
	mMLDMonitorFD(-1),
	mIsRunning(false),
	mIsUp(false)
{
	if (0 > mFDRead) {
		throw std::invalid_argument("Unable to open tunnel interface");
	}

#if !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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

	netif_mgmt_set_mtu(mNetifMgmtFD, mInterfaceName.c_str(), mtu);

	setup_signals();
	setup_mld_listener();
#endif
}

TunnelIPv6Interface::~TunnelIPv6Interface()
{
	close(mNetlinkFD);
	if (mMLDMonitorFD >= 0) {
		close(mMLDMonitorFD);
	}
	netif_mgmt_close(mNetifMgmtFD);
}

void
TunnelIPv6Interface::on_link_state_changed(bool isUp, bool isRunning)
{
	syslog(LOG_INFO, "TunnelIPv6Interface::on_link_state_changed() UP=%d RUNNING=%d", isUp, isRunning);
	if (isRunning != mIsRunning || isUp != mIsUp) {
		if (isRunning && !mIsRunning) {
			std::map<struct in6_addr, Entry>::iterator iter;

			for (iter = mUnicastAddresses.begin(); iter != mUnicastAddresses.end(); ++iter) {
				if (iter->second.mState != Entry::kWaitingToAdd) {
					continue;
				}

				syslog(LOG_INFO, "Adding address \"%s/%d\" to interface \"%s\"",
				       in6_addr_to_string(iter->first).c_str(), iter->second.mPrefixLen,
				       mInterfaceName.c_str());

				IGNORE_RETURN_VALUE(netif_mgmt_add_ipv6_address(mNetifMgmtFD, mInterfaceName.c_str(),
				                    iter->first.s6_addr, iter->second.mPrefixLen));
				iter->second.mState = Entry::kWaitingForAddConfirm;
			}

			for (iter = mPendingMulticastAddresses.begin(); iter != mPendingMulticastAddresses.end();	++iter) {
				if (iter->second.mState != Entry::kWaitingToAdd) {
					continue;
				}

				syslog(LOG_INFO, "Joining multicast address \"%s\" on interface \"%s\".",
				       in6_addr_to_string(iter->first).c_str(), mInterfaceName.c_str());

				IGNORE_RETURN_VALUE(netif_mgmt_join_ipv6_multicast_address(mNetifMgmtFD, mInterfaceName.c_str(),
				                    iter->first.s6_addr));
			}
			mPendingMulticastAddresses.clear();
		}
		mIsUp = isUp;
		mIsRunning = isRunning;
		mLinkStateChanged(isUp, isRunning);
	}
}

void
TunnelIPv6Interface::on_address_added(const struct in6_addr &address, uint8_t prefix_len)
{
	if (mUnicastAddresses.count(address)) {
		mUnicastAddresses.erase(address);
	}

	syslog(LOG_INFO, "TunnelIPv6Interface: \"%s/%d\" was added to \"%s\"", in6_addr_to_string(address).c_str(), prefix_len,
	       get_interface_name().c_str());

	mUnicastAddressWasAdded(address, prefix_len);
}

void
TunnelIPv6Interface::on_multicast_address_joined(const struct in6_addr &address)
{
	if (mPendingMulticastAddresses.count(address)) {
		mPendingMulticastAddresses.erase(address);
	}

	syslog(LOG_INFO, "TunnelIPv6Interface: \"%s\" was added to \"%s\"", in6_addr_to_string(address).c_str(),
	       get_interface_name().c_str());

	mMulticastAddressWasJoined(address);
}

void
TunnelIPv6Interface::on_address_removed(const struct in6_addr &address, uint8_t prefix_len)
{
	// Ignore "removed" signal if address is the list
	// meaning it was added earlier and we are still
	// waiting to confirm that it is added.
	// This is to address the case where before adding an
	// address on interface it may be first removed.

	if (!mUnicastAddresses.count(address)) {
		syslog(LOG_INFO, "TunnelIPv6Interface: \"%s/%d\" was removed from \"%s\"", in6_addr_to_string(address).c_str(), prefix_len,
		       get_interface_name().c_str());

		mUnicastAddressWasRemoved(address, prefix_len);
	}

}

void
TunnelIPv6Interface::on_multicast_address_left(const struct in6_addr &address)
{
	// Ignore "removed" signal if address is the list
	// meaning it was added earlier and we are still
	// waiting to confirm that it is added.
	// This is to address the case where before adding an
	// address on interface it may be first removed.

	if (!mPendingMulticastAddresses.count(address)) {
		syslog(LOG_INFO, "TunnelIPv6Interface: \"%s\" was removed from \"%s\"", in6_addr_to_string(address).c_str(),
		       get_interface_name().c_str());

		mMulticastAddressWasLeft(address);
	}
}

#if __linux__ // --------------------------------------------------------------

#define LCG32(x)		((uint32_t)(x)*1664525+1013904223)

void
TunnelIPv6Interface::setup_signals(void)
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

void
TunnelIPv6Interface::setup_mld_listener(void)
{
	unsigned interfaceIndex = netif_mgmt_get_ifindex(mNetifMgmtFD, mInterfaceName.c_str());
	bool success = false;
	struct ipv6_mreq mreq6;

	mMLDMonitorFD = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMPV6);
	mreq6.ipv6mr_interface = interfaceIndex;
	inet_pton(AF_INET6, kMLDv2MulticastAddress, &mreq6.ipv6mr_multiaddr);

	require(setsockopt(mMLDMonitorFD, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) == 0, bail);
	require(setsockopt(mMLDMonitorFD, SOL_SOCKET, SO_BINDTODEVICE, mInterfaceName.c_str(), mInterfaceName.size()) == 0, bail);

	success = true;

bail:
	if (!success) {
		if (mMLDMonitorFD >= 0) {
			close(mMLDMonitorFD);
		}
		syslog(LOG_ERR, "listen to MLD messages on interface failed\n");
	}
	return;
}

int
TunnelIPv6Interface::process(void)
{
	processNetlinkFD();
	processMLDMonitorFD();

	return nl::UnixSocket::process();
}

void
TunnelIPv6Interface::processNetlinkFD(void)
{
	uint8_t buffer[4096];
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
			char ifnamebuf[IF_NAMESIZE];
			if (nlp->nlmsg_type == RTM_NEWADDR || nlp->nlmsg_type == RTM_DELADDR) {
				struct ifaddrmsg *ifaddr = (struct ifaddrmsg *)NLMSG_DATA(nlp);
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
							on_address_added(addr, ifaddr->ifa_prefixlen);
						} else if (nlp->nlmsg_type == RTM_DELADDR) {
							on_address_removed(addr, ifaddr->ifa_prefixlen);
						}
						break;
					default:
						break;
					}
				}
			} else if (nlp->nlmsg_type == RTM_NEWLINK || nlp->nlmsg_type == RTM_DELLINK) {
				struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlp);
				const char *ifname = if_indextoname(ifinfo->ifi_index, ifnamebuf);
				bool isUp, isRunning;

				if ((ifname == NULL) || (get_interface_name() != ifname)) {
					continue;
				}

				isUp = ((ifinfo->ifi_flags & IFF_UP) == IFF_UP);
				isRunning = ((ifinfo->ifi_flags & IFF_RUNNING) == IFF_RUNNING);

				on_link_state_changed(isUp, isRunning);
			}
		}
	}
}

static bool IsMulticastAddressFiltered(const struct in6_addr& addr_to_check) 
{
	bool found = false;

  for (size_t i = 0; i < sizeof(kFilterMulticastAddresses) /
                             sizeof(kFilterMulticastAddresses[0]);
       i++) {
			struct in6_addr addr;	

			inet_pton(AF_INET6, kFilterMulticastAddresses[i], &addr);
			if (memcmp(&addr, &addr_to_check, sizeof(addr)) == 0) {
				found = true;
				break;
			}
  }

	return found;
}

void
TunnelIPv6Interface::processMLDMonitorFD(void)
{
	uint8_t buffer[4096];
	ssize_t bufferLen(-1);
	struct sockaddr_in6 srcAddr;
	socklen_t addrLen;
	bool fromSelf = false;
	MLDv2Header* hdr = reinterpret_cast<MLDv2Header *>(buffer);
	ssize_t offset;
	uint8_t type;
	struct ifaddrs *ifAddrs = NULL;

	if (mNetlinkFD >= 0) {
		bufferLen = recvfrom(mMLDMonitorFD, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr *>(&srcAddr), &addrLen);
	}
	require_quiet(bufferLen > 0, bail);

	type = buffer[0];
	require_quiet(type == kICMPv6MLDv2Type && bufferLen >= sizeof(MLDv2Header), bail);

	// Check whether it is sent by self
	require(getifaddrs(&ifAddrs) == 0, bail);
	for (struct ifaddrs* ifAddr = ifAddrs; ifAddr != NULL; ifAddr = ifAddr->ifa_next) {
		if (ifAddr->ifa_addr != NULL && ifAddr->ifa_addr->sa_family == AF_INET6 &&
				mInterfaceName == std::string(ifAddr->ifa_name)) {
			struct sockaddr_in6 *addr6 = reinterpret_cast<struct sockaddr_in6 *>(ifAddr->ifa_addr);

			if (memcmp(&addr6->sin6_addr, &srcAddr.sin6_addr, sizeof(in6_addr)) == 0) {
				fromSelf = true;
				break;
			}
		}
	}
	require_quiet(fromSelf, bail);

	hdr = reinterpret_cast<MLDv2Header *>(buffer);
	offset = sizeof(MLDv2Header);

	for (size_t i = 0; i < ntohs(hdr->mNumRecords) && offset < bufferLen; i++) {
		if (bufferLen - offset >= sizeof(MLDv2Record)) {
			MLDv2Record *record = reinterpret_cast<MLDv2Record *>(&buffer[offset]);

			if (!IsMulticastAddressFiltered(record->mMulticastAddress)) {
				if (record->mRecordType == kICMPv6MLDv2RecordChangeToIncludeType) {
					on_multicast_address_joined(record->mMulticastAddress);
				} else if (record->mRecordType == kICMPv6MLDv2RecordChangeToExcludeType) {
					on_multicast_address_left(record->mMulticastAddress);
				}
			}

			offset += sizeof(MLDv2Record) + sizeof(in6_addr) * ntohs(record->mNumSources);
		}
	}

bail:
	if (ifAddrs) {
		freeifaddrs(ifAddrs);
	}

	return;
}

#else // ----------------------------------------------------------------------

void
TunnelIPv6Interface::setup_signals(void)
{
	// Unknown platform.
}

int
TunnelIPv6Interface::process(void)
{
	return nl::UnixSocket::process();
}

void
TunnelIPv6Interface::processNetlinkFD(void)
{
}

void
TunnelIPv6Interface::processMLDMonitorFD(void)
{
}

#endif // ---------------------------------------------------------------------

int
TunnelIPv6Interface::update_fd_set(fd_set *read_fd_set, fd_set *write_fd_set, fd_set *error_fd_set, int *max_fd, cms_t *timeout)
{
	if (read_fd_set) {
		if (mNetlinkFD >= 0)  {
			FD_SET(mNetlinkFD, read_fd_set);
		}

		if (mMLDMonitorFD >= 0) {
			FD_SET(mMLDMonitorFD, read_fd_set);
		}

		if ((max_fd != NULL)) {
			*max_fd = std::max(*max_fd, mNetlinkFD);
			*max_fd = std::max(*max_fd, mMLDMonitorFD);
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
TunnelIPv6Interface::is_up(void)
{
	return netif_mgmt_is_up(mNetifMgmtFD, mInterfaceName.c_str());
}

bool
TunnelIPv6Interface::is_running(void)
{
	return netif_mgmt_is_running(mNetifMgmtFD, mInterfaceName.c_str());
}

bool
TunnelIPv6Interface::is_online(void)
{
	static const int online_flags = IFF_UP | IFF_RUNNING;
	return (netif_mgmt_get_flags(mNetifMgmtFD, mInterfaceName.c_str()) & online_flags) == online_flags;
}

int
TunnelIPv6Interface::set_up(bool isUp)
{
	int ret = 0;
	bool old = is_up();

	if (isUp != old) {
		if (isUp) {
			syslog(LOG_INFO, "Bringing interface %s up. . .", mInterfaceName.c_str());
		} else {
			syslog(LOG_INFO, "Taking interface %s down. . .", mInterfaceName.c_str());
		}

		ret = netif_mgmt_set_up(mNetifMgmtFD, mInterfaceName.c_str(), isUp);

		require_action(ret == 0, bail, mLastError = errno);
	}

bail:
	return ret;
}

int
TunnelIPv6Interface::set_running(bool isRunning)
{
	int ret = 0;
	bool old = is_running();

	if (isRunning != old) {
		if (isRunning) {
			syslog(LOG_INFO, "Bringing interface %s online. . .", mInterfaceName.c_str());
		} else {
			syslog(LOG_INFO, "Taking interface %s offline. . .", mInterfaceName.c_str());
		}

		ret = netif_mgmt_set_running(mNetifMgmtFD, mInterfaceName.c_str(), isRunning);

		mLastError = errno;

		require_action(ret == 0, bail, mLastError = errno);

	}

bail:
	return ret;
}


int
TunnelIPv6Interface::set_online(bool online)
{
	return set_running(online);
}

void
TunnelIPv6Interface::reset(void)
{
	syslog(LOG_INFO, "Resetting interface %s. . .", mInterfaceName.c_str());
	set_online(false);
}


bool
TunnelIPv6Interface::add_address(const struct in6_addr *addr, int prefixlen)
{
	bool ret = false;

	require_action(!IN6_IS_ADDR_UNSPECIFIED(addr), bail, mLastError = EINVAL);

	if (mUnicastAddresses.count(*addr)) {
		ret = true;
		goto bail;
	}

	if (is_online()) {
		syslog(LOG_INFO, "Adding address \"%s/%d\" to interface \"%s\"",
		       in6_addr_to_string(*addr).c_str(), prefixlen, mInterfaceName.c_str());

		require_noerr_action(
			netif_mgmt_add_ipv6_address(mNetifMgmtFD, mInterfaceName.c_str(), addr->s6_addr, prefixlen),
			bail,
			mLastError = errno
		);
		mUnicastAddresses[*addr] = Entry(Entry::kWaitingForAddConfirm, prefixlen);
	} else {
		mUnicastAddresses[*addr] = Entry(Entry::kWaitingToAdd, prefixlen);
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

	if (mUnicastAddresses.count(*addr)) {
		mUnicastAddresses.erase(*addr);
	}

	if (netif_mgmt_remove_ipv6_address(mNetifMgmtFD, mInterfaceName.c_str(), addr->s6_addr) != 0) {
		mLastError = errno;
		goto bail;
	}

	syslog(LOG_INFO,"Removing address \"%s\" from interface \"%s\"",
	       in6_addr_to_string(*addr).c_str(), mInterfaceName.c_str());
	ret = true;

bail:
	return ret;
}

bool
TunnelIPv6Interface::join_multicast_address(const struct in6_addr *addr)
{
	bool ret = false;

	require_action(!IN6_IS_ADDR_UNSPECIFIED(addr), bail, mLastError = EINVAL);

	if (is_online()) {
		if (netif_mgmt_join_ipv6_multicast_address(mNetifMgmtFD, mInterfaceName.c_str(), addr->s6_addr) != 0) {
			mLastError = errno;
			goto bail;
		}

		syslog(LOG_INFO, "Joining multicast address \"%s\" on interface \"%s\".",
		       in6_addr_to_string(*addr).c_str(), mInterfaceName.c_str());
	} else {
		mPendingMulticastAddresses[*addr] = Entry(Entry::kWaitingToAdd);
	}

	ret = true;

bail:
	return ret;
}

bool
TunnelIPv6Interface::leave_multicast_address(const struct in6_addr *addr)
{
	bool ret = false;

	require_action(!IN6_IS_ADDR_UNSPECIFIED(addr), bail, mLastError = EINVAL);

	if (mPendingMulticastAddresses.count(*addr)) {
		mPendingMulticastAddresses.erase(*addr);
	}

	if (netif_mgmt_leave_ipv6_multicast_address(mNetifMgmtFD, mInterfaceName.c_str(), addr->s6_addr) != 0) {
		mLastError = errno;
		goto bail;
	}

	syslog(LOG_INFO, "Leaving multicast address \"%s\" on interface \"%s\".",
	       in6_addr_to_string(*addr).c_str(), mInterfaceName.c_str());
	ret = true;

bail:
	return ret;
}


bool
TunnelIPv6Interface::add_route(const struct in6_addr *route, int prefixlen, uint32_t metric)
{
	bool ret = false;

	if (netif_mgmt_add_ipv6_route(mNetifMgmtFD, mInterfaceName.c_str(), route->s6_addr, prefixlen, metric) != 0) {
		mLastError = errno;
		goto bail;
	}
	syslog(LOG_INFO, "Adding route prefix \"%s/%d\" on interface \"%s\".",
	       in6_addr_to_string(*route).c_str(), prefixlen, mInterfaceName.c_str());

	ret = true;

bail:
	return ret;
}

bool
TunnelIPv6Interface::remove_route(const struct in6_addr *route, int prefixlen, uint32_t metric)
{
	bool ret = false;

	if (netif_mgmt_remove_ipv6_route(mNetifMgmtFD, mInterfaceName.c_str(), route->s6_addr, prefixlen, metric) != 0) {
		mLastError = errno;
		goto bail;
	}

	syslog(LOG_INFO, "Removing route prefix \"%s/%d\" on interface \"%s\".",
	       in6_addr_to_string(*route).c_str(), prefixlen, mInterfaceName.c_str());

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
