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
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <getopt.h>
#include "wpanctl-utils.h"
#include "tool-cmd-performance.h"
#include "assert-macros.h"
#include "args.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "string-utils.h"

#include <arpa/inet.h>
#include <errno.h>

const char performance_cmd_syntax[] = "[args] <dest address>";

static const arg_list_item_t performance_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "type", NULL, "Performance test type: 1. latency test, 2. throughput test"},
	{'s', "sender", NULL, "set the sending node, else set the receiving node"},
	{'l', "length", NULL, "set sending UDP payload size"},
	{0}
};

int tool_cmd_performance_test(int argc, char* argv[])
{
	int ret = 0;
	int c;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	dbus_bool_t isSender = FALSE;
	dbus_bool_t isReceiver = FALSE;
	uint16_t type = 0;
	uint16_t payloadSize = 0;
	const char* peerAddr = NULL;
	char address_string[INET6_ADDRSTRLEN];
	uint8_t addrBytes[16];
	uint8_t *addr = addrBytes;

	dbus_error_init(&error);

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"type", required_argument, 0, 't'},
			{"sender", no_argument, 0, 's'},
			{"length", required_argument, 0, 'l'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "ht:srl:", long_options,
				&option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_arg_list_help(performance_option_list, argv[0], performance_cmd_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 't':
			type = (uint8_t)strtol(optarg, NULL, 0);
			break;

		case 's':
			isSender = TRUE;
			break;

		case 'l':
			payloadSize = (uint16_t) strtol(optarg, NULL, 0);
			break;
		}
	}

	if (optind < argc) {
		if (!peerAddr) {
			peerAddr = argv[optind];
			optind++;
		}
	}

	if (optind < argc) {
		fprintf(stderr,
				"%s: error: Unexpected extra argument: \"%s\"\n",
				argv[0], argv[optind]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (gInterfaceName[0] == 0) {
		fprintf(stderr,
				"%s: error: No WPAN interface set (use the `cd` command, or the `-I` argument for `wpanctl`).\n",
				argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	require_string(connection != NULL, bail, error.message);

	{
		DBusMessageIter iter;
		DBusMessageIter list_iter;
		char path[DBUS_MAXIMUM_NAME_LENGTH+1];
		char interface_dbus_name[DBUS_MAXIMUM_NAME_LENGTH+1];
		ret = lookup_dbus_name_from_interface(interface_dbus_name, gInterfaceName);
		if (ret != 0) {
			goto bail;
		}
		snprintf(path,
				sizeof(path),
				"%s/%s",
				WPANTUND_DBUS_PATH,
				gInterfaceName);

		message = dbus_message_new_method_call(
				  interface_dbus_name,
				  path,
				  WPANTUND_DBUS_APIv1_INTERFACE,
				  WPANTUND_IF_CMD_PERFORMANCE_TEST
				  );

		if(peerAddr) {
			if(strstr(peerAddr,":")) {

				// Address-style
				int bits = inet_pton(AF_INET6, peerAddr, addrBytes);
				if(bits<0) {
					fprintf(stderr,
							"Bad address \"%s\", errno=%d (%s)\n",
							peerAddr,
							errno,
							strerror(errno));
					goto bail;
				} else if(!bits) {
					fprintf(stderr, "Bad address \"%s\"\n", peerAddr);
					goto bail;
				}
			}

			inet_ntop(AF_INET6, (const void *)&addrBytes, address_string, INET6_ADDRSTRLEN);

			fprintf(stderr, "Using dest address \"%s\"\n", address_string);

		}

		addr = addrBytes;

		dbus_message_append_args(
			message,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &addr, 16,
			DBUS_TYPE_INT16, &payloadSize,
			DBUS_TYPE_BOOLEAN, &isSender,
			DBUS_TYPE_INVALID
		);


		reply = dbus_connection_send_with_reply_and_block(
				connection,
				message,
				timeout,
				&error
				);

		if (!reply) {
			fprintf(stderr, "%s: error: %s\n", argv[0], error.message);
			ret = ERRORCODE_TIMEOUT;
			goto bail;
		}

		dbus_message_get_args(reply, &error,
							  DBUS_TYPE_INT32, &ret,
							  DBUS_TYPE_INVALID
							 );

		if (!ret) {
			fprintf(stderr, "performance complete.\n");
		} else {
			fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
			print_error_diagnosis(ret);
		}
	}

bail:

	if (connection)
		dbus_connection_unref(connection);

	if (message)
		dbus_message_unref(message);

	if (reply)
		dbus_message_unref(reply);

	dbus_error_free(&error);

	return ret;
}
