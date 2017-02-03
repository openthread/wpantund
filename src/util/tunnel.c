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
 *		This file implements the code which managed the TUN interface.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include "assert-macros.h"
#include "pt.h"

#include <stdio.h>
#include <stdlib.h>
#include "tunnel.h"
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifndef __APPLE__
#include <linux/if_tun.h>
#endif

#include <net/if.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <net/route.h> // AF_ROUTE things

#ifdef __APPLE__
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>   // ND6_INFINITE_LIFETIME
#include <net/if_dl.h>      // struct sockaddr_dl
#include <net/if_utun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#define IFEF_NOAUTOIPV6LL   0x2000  /* Interface IPv6 LinkLocal address not provided by kernel */
#endif

#ifndef TUNNEL_TUNTAP_DEVICE
#define TUNNEL_TUNTAP_DEVICE               "/dev/net/tun"
#endif

int
tunnel_open(const char* tun_name)
{
	int fd = -1;
	char *device = NULL;

	if ((tun_name == NULL) || (tun_name[0] == 0)) {
		tun_name = TUNNEL_DEFAULT_INTERFACE_NAME;
	}

	syslog(LOG_INFO, "Opening tun interface socket with name \"%s\"", tun_name);

#if defined(UTUN_CONTROL_NAME)
	int error = 0;
	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	struct sockaddr_ctl addr;

	/* get/set the id */
	struct ctl_info info;
	memset(&info, 0, sizeof(info));
	strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));
	error = ioctl(fd, CTLIOCGINFO, &info);

	if (error) {
		syslog(LOG_ERR, "Failed to open utun interface: %s", strerror(errno));
		close(fd);
		fd = -1;
		goto bail;
	}

	addr.sc_id = info.ctl_id;
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	addr.sc_unit = 0;  /* allocate dynamically */

	if (strncmp(tun_name, "utun", 4) == 0)
		addr.sc_unit = (int)strtol(tun_name + 4, NULL, 10) + 1;

	error = connect(fd, (struct sockaddr*)&addr, sizeof(addr));

	if (error && errno == EBUSY) {
		addr.sc_unit = 0;  /* allocate dynamically */
		error = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	}

	if (error) {
		syslog(LOG_ERR, "Failed to open tun interface: %s", strerror(errno));
		close(fd);
		fd = -1;
		goto bail;
	}

	tunnel_bring_offline(fd);

	goto bail;

#else

#ifdef __APPLE__
	if (strncmp(tun_name, "utun", 4) == 0)
		tun_name = "tun0";
	asprintf(&device, "/dev/%s", tun_name);
#else
	device = strdup(TUNNEL_TUNTAP_DEVICE);
#endif

	require(NULL != device, bail);

	fd = open(device, O_RDWR | O_NONBLOCK);

	if (0 > fd) {
		syslog(LOG_ERR, "Failed to open tun interface: %s", strerror(errno));
		perror("open-tun");
		goto bail;
	}
#endif

#ifdef TUNSETIFF
	struct ifreq ifr = { .ifr_flags = IFF_TUN | IFF_NO_PI };
	strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);

	require(0 == ioctl(fd, TUNSETIFF, (void*)&ifr), bail);

	// Verify that the name was set. If it wasn't
	// we need to fail.
	char name[20] = "";

	if (tunnel_get_name(fd, name, sizeof(name)) != 0) {
		syslog(LOG_ERR, "Unable to set name on tun interface: %s", strerror(errno));
		perror("open-tun");
		close(fd);
		fd = -1;
		goto bail;
	}

	if (name[0] == 0) {
		syslog(LOG_ERR, "Unable to set name on tun interface");
		close(fd);
		fd = -1;
		goto bail;
	}

#endif

bail:
	free(device);
	return fd;
}

void
tunnel_close(int fd)
{
	close(fd);
}

int
tunnel_get_name(
    int fd, char* name, int maxlen
    )
{
	int ret = -1;

	if (maxlen && name) name[0] = 0;
#if defined(UTUN_CONTROL_NAME)
	socklen_t len = maxlen;
	if (0 == getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len)) {
		ret = 0;
		goto bail;
	}
#elif defined(TUNGETIFF)
	struct ifreq ifr = { };
	require(0 == ioctl(fd, TUNGETIFF, (void*)&ifr), bail);
	strncpy(name, ifr.ifr_name, maxlen);
#else
	struct stat st;
	ret = fstat(fd, &st);
	if (ret) {
		perror("tunnel_get_name: fstat failed.");
		goto bail;
	}
	devname_r(st.st_rdev, S_IFCHR, name, (int)maxlen);
#endif
	ret = 0;
bail:
	return ret;
}

static int
_tunnel_get_iff(
    int fd, struct ifreq *ifr
    )
{
	int ret = -1;

	ret = tunnel_get_name(fd, ifr->ifr_name, sizeof(ifr->ifr_name));

	return ret;
}


bool
tunnel_is_online(int fd)
{
	bool ret = false;
	int status = -1;
	int reqfd = -1;
	struct ifreq ifr = { };

	/* get interface name */
	_tunnel_get_iff(fd, &ifr);

	reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

	status = ioctl(reqfd, SIOCGIFFLAGS, &ifr);
	require_string(status == 0, bail, strerror(errno));

	ret = ((ifr.ifr_flags & IFF_UP) == IFF_UP);

bail:
	close(reqfd);
	return ret;
}

int
tunnel_bring_online(int fd)
{
	int ret = -1;
	int reqfd = -1;
	struct ifreq ifr = { };

	/* get interface name */
	_tunnel_get_iff(fd, &ifr);

	reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

	ret = ioctl(reqfd, SIOCGIFFLAGS, &ifr);
	require_string(ret == 0, bail, strerror(errno));

	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
	ret = ioctl(reqfd, SIOCSIFFLAGS, &ifr);
	require_string(ret == 0, bail, strerror(errno));

bail:
	close(reqfd);
	return ret;
}

int
tunnel_bring_offline(int fd)
{
	int ret = -1;
	int reqfd = -1;
	struct ifreq ifr = { };

	/* get interface name */
	_tunnel_get_iff(fd, &ifr);

	reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

	ret = ioctl(reqfd, SIOCGIFFLAGS, &ifr);
	require_string(ret == 0, bail, strerror(errno));

	ifr.ifr_flags &= ~(IFF_UP);
	ret = ioctl(reqfd, SIOCSIFFLAGS, &ifr);
	require_string(ret == 0, bail, strerror(errno));

bail:
	close(reqfd);
	return ret;
}

int
tunnel_set_mtu(
    int fd, uint16_t mtu
    )
{
	int ret = -1;
	int reqfd = -1;
	struct ifreq ifr = { };

	/* get interface name */
	_tunnel_get_iff(fd, &ifr);

	reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

	ifr.ifr_mtu = mtu;

	ret = ioctl(reqfd, SIOCSIFMTU, &ifr);

	if (ret)
		perror("tapdev: Uable to set MTU, call to ioctl failed.");

	close(reqfd);
	return ret;
}
#ifndef SIOCSIFLLADDR
#define SIOCSIFLLADDR SIOCSIFHWADDR
#endif


static inline void
apply_mask(
    struct in6_addr *address, uint8_t mask
    )
{
	// Coverty might complain in this function, but don't believe it.
	// This code has been reviewed carefully and should not misbehave.

	if (mask > 128) {
		mask = 128;
	}

	memset(
		(void*)(address->s6_addr + ((mask + 7) / 8)),
	    0,
	    16 - ((mask + 7) / 8)
	);

	if (mask % 8) {
		address->s6_addr[mask / 8] &= ~(0xFF >> (mask % 8));
	}
}

int
tunnel_add_address(
    int fd, const uint8_t addr[16], int prefixlen
    )
{
	int ret = -1;
	int reqfd = -1;

	reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

#ifdef __APPLE__

	/************* Add address *************/

	struct in6_aliasreq addreq6 = { };

	ret = tunnel_get_name(fd, addreq6.ifra_name, sizeof(addreq6.ifra_name));

	if (ret) {
		perror("tunnel_add_address: Uable to get interface name.");
		goto bail;
	}

	addreq6.ifra_addr.sin6_family = AF_INET6;
	addreq6.ifra_addr.sin6_len = sizeof(addreq6.ifra_addr);
	memcpy((void*)&addreq6.ifra_addr.sin6_addr, addr, 16);

	addreq6.ifra_prefixmask.sin6_family = AF_INET6;
	addreq6.ifra_prefixmask.sin6_len = sizeof(addreq6.ifra_prefixmask);
	memset((void*)&addreq6.ifra_prefixmask.sin6_addr, 0xFF, 16);
	apply_mask(&addreq6.ifra_prefixmask.sin6_addr, prefixlen);

	addreq6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	addreq6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	addreq6.ifra_lifetime.ia6t_expire = ND6_INFINITE_LIFETIME;
	addreq6.ifra_lifetime.ia6t_preferred = ND6_INFINITE_LIFETIME;

	addreq6.ifra_flags |= IN6_IFF_NODAD;

	ret = ioctl(reqfd, SIOCAIFADDR_IN6, &addreq6);
	if (ret && errno != EALREADY)
		goto bail;

#else

	/* Linux */

	// In linux, we need to remove the address first.
	tunnel_remove_address(fd, addr);

#define ifreq_offsetof(x)  offsetof(struct ifreq, x)

	struct in6_ifreq {
		struct in6_addr ifr6_addr;
		__u32 ifr6_prefixlen;
		unsigned int ifr6_ifindex;
	};

	struct ifreq ifr = { };
	struct sockaddr_in6 sai;
	int sockfd;
	struct in6_ifreq ifr6;

	/* get interface name */
	_tunnel_get_iff(fd, &ifr);

	memset(&sai, 0, sizeof(struct sockaddr));
	sai.sin6_family = AF_INET6;
	sai.sin6_port = 0;

	memcpy((void*)&sai.sin6_addr, addr, 16);

	memcpy((char*)&ifr6.ifr6_addr, (char*)&sai.sin6_addr,
	       sizeof(struct in6_addr));

	if (ioctl(reqfd, SIOGIFINDEX, &ifr) < 0)
		perror("SIOGIFINDEX");
	ifr6.ifr6_ifindex = ifr.ifr_ifindex;
	ifr6.ifr6_prefixlen = 64;
	ret = ioctl(reqfd, SIOCSIFADDR, &ifr6);
	if (ret && errno != EALREADY)
		goto bail;
	ret = 0;

#endif
	ret = 0;
bail:
	if (ret) {
		syslog(LOG_INFO, "tunnel_add_address: errno=%d (%s)", errno, strerror(errno));
	}
	if (reqfd >= 0)
		close(reqfd);

	return ret;
}

int
tunnel_remove_address(
    int fd, const uint8_t addr[16]
    )
{
	int ret = -1;

	int reqfd = -1;

	reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

	struct sockaddr_in6 sai = { };

	memset(&sai, 0, sizeof(struct sockaddr));
	sai.sin6_family = AF_INET6;
	sai.sin6_port = 0;
	memcpy((void*)&sai.sin6_addr, addr, 16);

	/************* Remove address *************/

#ifdef __APPLE__
	sai.sin6_len = sizeof(sai);


	struct in6_ifreq ifreq6 = { };
	ret = tunnel_get_name(fd, ifreq6.ifr_name, sizeof(ifreq6.ifr_name));

	if (ret)
		goto bail;

	ifreq6.ifr_addr = sai;

	if (-1 == ioctl(reqfd, SIOCDIFADDR_IN6, &ifreq6)) {
		ret = -errno;
		goto bail;
	}

#else
	int ifindex = 0;
	{
		struct ifreq ifr = { };

		/* get interface name */
		_tunnel_get_iff(fd, &ifr);

		if (ioctl(reqfd, SIOGIFINDEX, &ifr) < 0)
			perror("SIOGIFINDEX");

		ifindex = ifr.ifr_ifindex;
	}

	struct in6_ifreq {
		struct in6_addr ifr6_addr;
		__u32 ifr6_prefixlen;
		unsigned int ifr6_ifindex;
	};

	struct in6_ifreq ifr6;

	ifr6.ifr6_addr = sai.sin6_addr;
	ifr6.ifr6_ifindex = ifindex;
	ifr6.ifr6_prefixlen = 64;

	if (ioctl(reqfd, SIOCDIFADDR, &ifr6) < 0) {
		ret = -errno;
		goto bail;
	}
#endif
	ret = 0;

bail:
	if (reqfd >= 0)
		close(reqfd);

	return ret;
}


int
tunnel_add_route(
    int fd, const uint8_t route[16], int prefixlen
    )
{
	int ret = -1;
	int reqfd = -1;

	reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

#ifdef __APPLE__

	/************* Add ROUTE TODO *************/

#else
	/* Linux */

	struct ifreq ifr;
	struct in6_rtmsg rt;

	memset(&ifr, 0, sizeof(struct ifreq));

	/* get interface name */
	_tunnel_get_iff(fd, &ifr);

	memset(&rt, 0, sizeof(struct in6_rtmsg));
	memcpy(rt.rtmsg_dst.s6_addr, route, sizeof(struct in6_addr));
	rt.rtmsg_dst_len = prefixlen;
	rt.rtmsg_flags = RTF_UP;
	if (prefixlen == 128) {
		rt.rtmsg_flags |= RTF_HOST;
	}
	rt.rtmsg_metric = 512;

	if (ioctl(reqfd, SIOGIFINDEX, &ifr) < 0)
		perror("SIOGIFINDEX");

	rt.rtmsg_ifindex = ifr.ifr_ifindex;

	ret = ioctl(reqfd, SIOCADDRT, &rt);
	if (ret && errno != EALREADY && errno != EEXIST)
		goto bail;

#endif

	ret = 0;
bail:
	if (ret) {
		syslog(LOG_INFO, "tunnel_add_route: errno=%d (%s)", errno, strerror(errno));
	}
	if (reqfd >= 0)
		close(reqfd);

	return ret;
}

int
tunnel_remove_route(
    int fd, const uint8_t route[16], int prefixlen
    )
{
    int ret = -1;
    int reqfd = -1;

    reqfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

#ifdef __APPLE__

    /************* Remove ROUTE TODO *************/

#else
    /* Linux */

    struct ifreq ifr;
    struct in6_rtmsg rt;

    memset(&ifr, 0, sizeof(struct ifreq));

    /* get interface name */
    _tunnel_get_iff(fd, &ifr);

    memset(&rt, 0, sizeof(struct in6_rtmsg));
    memcpy(rt.rtmsg_dst.s6_addr, route, sizeof(struct in6_addr));
    rt.rtmsg_dst_len = prefixlen;
    rt.rtmsg_flags = RTF_UP;
    if (prefixlen == 128) {
        rt.rtmsg_flags |= RTF_HOST;
    }
    rt.rtmsg_metric = 512;

    if (ioctl(reqfd, SIOGIFINDEX, &ifr) < 0)
        perror("SIOGIFINDEX");

    rt.rtmsg_ifindex = ifr.ifr_ifindex;

    ret = ioctl(reqfd, SIOCDELRT, &rt);
    if (ret && errno != EALREADY && errno != EEXIST)
        goto bail;

#endif

    ret = 0;
bail:
    if (ret) {
        syslog(LOG_INFO, "tunnel_remove_route: errno=%d (%s)", errno, strerror(errno));
    }
    if (reqfd >= 0)
        close(reqfd);

    return ret;
}
