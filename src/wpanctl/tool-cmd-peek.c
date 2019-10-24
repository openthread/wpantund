/*
 *
 * Copyright (c) 2017 Nest Labs, Inc.
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
#include "tool-cmd-peek.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "args.h"

#include <ctype.h>
#include <errno.h>

const char peek_cmd_syntax[] = "[args] <address>";

static const arg_list_item_t peek_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'c', "count", "bytes", "Number of bytes to peek"},
	{'d', "data", "", "Show the result as a sequence of unformatted hex bytes"},
	{0}
};

static void dump_data(const uint8_t *data_ptr, uint16_t data_len)
{
	uint16_t len;
	char buf[100];
	char *cur;
	uint16_t address_index = 0;
	uint16_t i;

	fprintf(stdout, "+------+-------------------------+-------------------------+------------------+\n");

	while (data_len > 0)
	{
		len = data_len < 16 ? data_len : 16;
		cur = buf;
		cur += sprintf(cur, "| %04X |", address_index);

		for (i = 0; i < 16; i++) {
			if (i < len) {
				cur += sprintf(cur, " %02X", data_ptr[i]);
			} else {
				cur += sprintf(cur, "   ");
			}

			if ((i == 7) || (i == 15)) {
				cur += sprintf(cur, " |");
			}
		}

		*cur++ = ' ';

		for (i = 0; i < 16; i++) {
			char c = (char)(0x7f & (data_ptr)[i]);
			*cur++ = (i < len) ? (isprint(c) ? c : '.') :  ' ';
		}

		cur += sprintf(cur, " |");

		fprintf(stdout, "%s\n", buf);

		data_ptr += len;
		data_len -= len;
		address_index += 16;
	}

	fprintf(stdout, "+------+-------------------------+-------------------------+------------------+\n");
}

int tool_cmd_peek(int argc, char* argv[])
{
	int ret = 0;
	int c;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	uint32_t address = 0;
	uint16_t count = 32;
	bool simple_data_format = false;

	dbus_error_init(&error);

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"timeout", required_argument, 0, 't'},
			{"count", required_argument, 0, 'c'},
			{"data", no_argument, 0, 'd'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "ht:c:d", long_options,	&option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_arg_list_help(peek_option_list, argv[0], peek_cmd_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;

		case 'c':
			count = strtol(optarg, NULL, 0);
			break;

		case 'd':
			simple_data_format = true;
			break;
		}
	}

	if (optind < argc) {
		address = strtol(argv[optind], NULL, 0);
		optind++;
	} else {
		fprintf(stderr,	"%s: error: Missing required address parameter\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (optind < argc) {
		fprintf(stderr,	"%s: error: Unexpected extra argument: \"%s\"\n", argv[0], argv[optind]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (gInterfaceName[0] == 0) {
		fprintf(
			stderr,
			"%s: error: No WPAN interface set (use the `cd` command, or the `-I` argument for `wpanctl`).\n",
			argv[0]
		);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	require_string(connection != NULL, bail, error.message);

	{
		char path[DBUS_MAXIMUM_NAME_LENGTH+1];
		char interface_dbus_name[DBUS_MAXIMUM_NAME_LENGTH+1];
		bool did_succeed;
		uint8_t *data_ptr = NULL;
		int data_len = 0;
		uint16_t i;

		ret = lookup_dbus_name_from_interface(interface_dbus_name, gInterfaceName);
		if (ret != 0) {
			print_error_diagnosis(ret);
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
			WPANTUND_IF_CMD_PEEK
		);

		fprintf(stdout, "Peeking at address 0x%x (%d) for %d bytes\n", address, address, count);

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT32, &address,
			DBUS_TYPE_UINT16, &count,
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

		did_succeed = dbus_message_get_args(reply, &error,
			DBUS_TYPE_INT32, &ret,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &data_ptr, &data_len,
			DBUS_TYPE_INVALID
		);

		if (!did_succeed)
		{
			did_succeed = dbus_message_get_args(reply, NULL,
				DBUS_TYPE_INT32, &ret,
				DBUS_TYPE_INVALID
			);
		}

		if (!did_succeed || ret != 0) {
			fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
			print_error_diagnosis(ret);
			goto bail;
		}

		if (simple_data_format) {
			for (i = 0; i < data_len; i++) {
				fprintf(stdout, "%02X ", *data_ptr++);
				if (i % 32 == 31) {
					fprintf(stdout, "\n");
				}
			}
			fprintf(stdout, "\n");
		} else {
			dump_data(data_ptr, data_len);
		}
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
