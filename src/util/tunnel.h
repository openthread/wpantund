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


#ifndef wpantund_tunnel_h
#define wpantund_tunnel_h

#include <stdint.h>
#include <stdbool.h>

#ifdef __APPLE__
#define TUNNEL_DEFAULT_INTERFACE_NAME   "utun2"
#else
#define TUNNEL_DEFAULT_INTERFACE_NAME   "wpan0"
#endif

#define TUNNEL_MAX_INTERFACE_NAME_LEN	60

__BEGIN_DECLS
extern int tunnel_open(const char* tun_name);
extern int tunnel_get_name(
    int fd, char* name, int maxlen);
extern int tunnel_set_mtu(
    int fd, uint16_t mtu);
extern int tunnel_set_hw_address(
    int fd, const uint8_t addr[8]);
extern int tunnel_add_address(
    int fd, const uint8_t addr[16], int prefixlen);
extern int tunnel_remove_address(
    int fd, const uint8_t addr[16]);
extern void tunnel_close(int fd);
extern int tunnel_bring_online(int fd);
extern int tunnel_bring_offline(int fd);
extern bool tunnel_is_online(int fd);
extern int tunnel_add_route(
    int fd, const uint8_t route[16], int prefixlen);
extern int tunnel_remove_route(
    int fd, const uint8_t route[16], int prefixlen);
__END_DECLS


#endif
