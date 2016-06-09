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
 *      This file contains helper glue code for manipulating IPv6 addresses.
 *
 */

#ifndef wpantund_IPv6Helpers_h
#define wpantund_IPv6Helpers_h

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>

#define MINIMUM_IPV6_PACKET_SIZE	40

static inline bool
operator==(const struct in6_addr &lhs, const struct in6_addr &rhs)
{
	return 0 == memcmp((const void*)&lhs, (const void*)&rhs, sizeof(rhs));
}

static inline bool
operator!=(const struct in6_addr &lhs, const struct in6_addr &rhs)
{
	return !(lhs == rhs);
}

static inline bool
operator<(const struct in6_addr &lhs, const struct in6_addr &rhs)
{
	return memcmp(lhs.s6_addr, rhs.s6_addr, sizeof(struct in6_addr)) < 0;
}

static inline std::string
in6_addr_to_string(const struct in6_addr &addr) {
	char address_string[INET6_ADDRSTRLEN] = "::";
	inet_ntop(AF_INET6, (const void *)&addr, address_string, sizeof(address_string));
	return std::string(address_string);
}

static inline void
in6_addr_apply_mask(struct in6_addr &address, uint8_t mask)
{
	if (mask > 128) {
		mask = 128;
	}

	memset(
		(void*)(address.s6_addr + ((mask + 7) / 8)),
		0,
		16 - ((mask + 7) / 8)
	);

	if (mask % 8) {
		address.s6_addr[mask / 8] &= ~(0xFF >> (mask % 8));
	}
}

static inline bool
is_valid_ipv6_packet(const uint8_t* packet, ssize_t len) {
	return (len > MINIMUM_IPV6_PACKET_SIZE)
		&& (packet[0] & 0xF0) == 0x60; // IPv6 Version
}
#endif
