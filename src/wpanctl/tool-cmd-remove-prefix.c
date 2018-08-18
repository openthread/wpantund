/*
 *
 * Copyright (c) 2018 Nest Labs, Inc.
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
 *      This file implements "remove-prefix" command in wpanctl.
 *
 */

#include <getopt.h>
#include "wpanctl-utils.h"
#include "tool-cmd-remove-prefix.h"
#include "assert-macros.h"
#include "args.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "string-utils.h"

#include <arpa/inet.h>
#include <errno.h>

const char remove_prefix_cmd_syntax[] = "[args] <prefix>";

static const arg_list_item_t remove_prefix_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'l', "length", "in bits", "Set the prefix length (default is 64)"},
	{0}
};

int tool_cmd_remove_prefix(int argc, char* argv[])
{
	int ret = 0;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	char dbus_path[DBUS_MAXIMUM_NAME_LENGTH + 1];
	char dbus_interface_name[DBUS_MAXIMUM_NAME_LENGTH + 1];
	const char* prefix_str = NULL;
	uint16_t prefix_len_in_bits = 64;
	int16_t priority = 0;
	dbus_bool_t stable = FALSE;
	dbus_bool_t preferred = FALSE;
	dbus_bool_t slaac = FALSE;
	dbus_bool_t dhcp = FALSE;
	dbus_bool_t configure = FALSE;
	dbus_bool_t default_route = FALSE;
	dbus_bool_t on_mesh = FALSE;
	uint8_t prefix_bytes[16] = {};
	uint8_t *addr = prefix_bytes;
	uint32_t preferred_lifetime = 0;
	uint32_t valid_lifetime = 0;

	dbus_error_init(&error);

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h' },
			{"timeout", required_argument, 0, 't'},
			{"length", required_argument, 0, 'l'},
			{0, 0, 0, 0}
		};

		int c;
		int option_index = 0;

		c = getopt_long(argc, argv, "ht:l:", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_arg_list_help(remove_prefix_option_list, argv[0], remove_prefix_cmd_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;

		case 'l':
			prefix_len_in_bits = (uint16_t) strtol(optarg, NULL, 0);
			break;
		}
	}

	if (optind < argc) {
		prefix_str = argv[optind];
		optind++;
	} else {
		fprintf((stderr), "%s: No prefix argument given\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (optind < argc) {
		fprintf(stderr, "%s: error: Unexpected extra argument: \"%s\"\n", argv[0], argv[optind]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	require_action(prefix_str != NULL, bail, ret = ERRORCODE_BADARG);

	// The prefix could either be specified like an IPv6 address, or
	// specified as a bunch of hex numbers. We use the presence of a
	// colon (':') to differentiate.

	if (strstr(prefix_str ,":")) {
		int bits = inet_pton(AF_INET6, prefix_str ,prefix_bytes);

		if (bits < 0) {
			fprintf(stderr, "Bad Prefix \"%s\", errno=%d (%s)\n", prefix_str, errno, strerror(errno));
			goto bail;
		} else if (!bits) {
			fprintf(stderr, "Bad prefix \"%s\"\n", prefix_str);
			goto bail;
		}
	} else {
		int length = parse_string_into_data(prefix_bytes, 8, prefix_str);
		if (length <= 0) {
			fprintf(stderr, "Bad prefix \"%s\"\n", prefix_str);
			goto bail;
		}
	}

	if (gInterfaceName[0] == 0) {
		fprintf(stderr,
			"%s: error: No WPAN interface set (use the `cd` command, or the `-I` argument for `wpanctl`).\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	require_action_string(connection != NULL, bail, ret = ERRORCODE_ALLOC, error.message);

	ret = lookup_dbus_name_from_interface(dbus_interface_name, gInterfaceName);
	require(ret == 0, bail);

	snprintf(dbus_path, sizeof(dbus_path), "%s/%s", WPANTUND_DBUS_PATH, gInterfaceName);

	message = dbus_message_new_method_call(
		dbus_interface_name,
		dbus_path,
		WPANTUND_DBUS_APIv1_INTERFACE,
		WPANTUND_IF_CMD_CONFIG_GATEWAY
	);

	require_action(message != NULL, bail, ret = ERRORCODE_ALLOC);

	addr = prefix_bytes;

	// Note that when removing a prefix the flags lifetime is
	// set to zero. The flag bits do not matter but should be
	// included in the DBus arguments since prefix len is
	// required to identify the prefix being removed.

	dbus_message_append_args(
		message,
		DBUS_TYPE_BOOLEAN, &default_route,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &addr, 16,
		DBUS_TYPE_UINT32, &preferred_lifetime,
		DBUS_TYPE_UINT32, &valid_lifetime,
		DBUS_TYPE_BOOLEAN, &preferred,
		DBUS_TYPE_BOOLEAN, &slaac,
		DBUS_TYPE_BOOLEAN, &on_mesh,
		DBUS_TYPE_INT16, &priority,
		DBUS_TYPE_BOOLEAN, &dhcp,
		DBUS_TYPE_BOOLEAN, &configure,
		DBUS_TYPE_BOOLEAN, &stable,
		DBUS_TYPE_UINT16, &prefix_len_in_bits,
		DBUS_TYPE_INVALID
	);

	reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, &error);

	if (!reply) {
		fprintf(stderr, "%s: error: %s\n", argv[0], error.message);
		ret = ERRORCODE_TIMEOUT;
		goto bail;
	}

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_INT32, &ret, DBUS_TYPE_INVALID) == FALSE) {
		fprintf(stderr, "%s: error in parsing response from wpantund: %s\n", argv[0], error.message);
		ret = ERRORCODE_BADCOMMAND;
		goto bail;
	}

	if (ret == 0) {
		char address_string[INET6_ADDRSTRLEN] = "::";
		inet_ntop(AF_INET6, (const void *)&prefix_bytes, address_string, sizeof(address_string));
		fprintf(stderr,	"Successfully removed prefix \"%s\" len:%d\n", address_string, prefix_len_in_bits);
	} else {
		fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
		print_error_diagnosis(ret);
	}

bail:

	if (connection) {
		dbus_connection_unref(connection);
	}

	if (message) {
		dbus_message_unref(message);
	}

	if (reply) {
		dbus_message_unref(reply);
	}

	dbus_error_free(&error);

	return ret;
}
