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

#ifndef wpantund_socket_utils_h
#define wpantund_socket_utils_h

#include <stdbool.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#define SOCKET_SYSTEM_COMMAND_PREFIX	"system:"
#define SOCKET_FD_COMMAND_PREFIX	"fd:"
#define SOCKET_FILE_COMMAND_PREFIX	"file:"
#define SOCKET_SERIAL_COMMAND_PREFIX	"serial:"
#define SOCKET_SYSTEM_FORKPTY_COMMAND_PREFIX	"system-forkpty:"
#define SOCKET_SYSTEM_SOCKETPAIR_COMMAND_PREFIX	"system-socketpair:"

__BEGIN_DECLS
extern int gSocketWrapperBaud;
bool socket_name_is_system_command(const char* socket_name);
bool socket_name_is_port(const char* socket_name);
bool socket_name_is_inet(const char* socket_name);
bool socket_name_is_device(const char* socket_name);
int lookup_sockaddr_from_host_and_port( struct sockaddr_in6* outaddr, const char* host, const char* port);
int open_serial_socket(const char* socket_name);
int close_serial_socket(int fd);
int fd_has_error(int fd);

int fork_unixdomain_socket(int* fd_pointer);

__END_DECLS


#endif
