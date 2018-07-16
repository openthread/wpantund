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
#include "string-utils.h"
#include "tool-cmd-peek.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "args.h"

#include <errno.h>

const char poke_cmd_syntax[] = "[args] <address> <value>";

static const arg_list_item_t poke_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'d', "data", NULL, "Value is binary data (in hex)"},
	{'s', "string", NULL, "Value is a string"},
	{'v', "value", "property-value", "Useful when the value starts with a '-'"},
	{0}
};

int tool_cmd_poke(int argc, char* argv[])
{
	int ret = 0;
	int c;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	enum {
		kValueType_String,
		kValueType_Data,
		kValueType_Byte
	} value_type = kValueType_Byte;
	char *value = NULL;
	uint32_t address = 0;
	uint16_t count;
	uint8_t byte;

	dbus_error_init(&error);

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"timeout", required_argument, 0, 't'},
			{"data", no_argument, 0, 'd'},
			{"string", no_argument, 0, 's'},
			{"value", required_argument, 0, 'v'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "ht:dsv:", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_arg_list_help(poke_option_list, argv[0], poke_cmd_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;

		case 'd':
			value_type = kValueType_Data;
			break;

		case 's':
			value_type = kValueType_String;
			break;

		case 'v':
			value = optarg;
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
		if (!value) {
			value = argv[optind];
			optind++;
		}
	}

	if (optind < argc) {
		fprintf(stderr,	"%s: error: Unexpected extra argument: \"%s\"\n", argv[0], argv[optind]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (!value) {
		fprintf(stderr, "%s: error: Missing value.\n", argv[0]);
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
		bool did_succeed = false;

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
			WPANTUND_IF_CMD_POKE
		);

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT32, &address,
			DBUS_TYPE_INVALID
		);

		if (value_type == kValueType_Byte) {
			byte = (uint8_t)strtol(value, NULL, 0);
			value = (char *)(&byte);
			count = 1;
		} else if (value_type == kValueType_String) {
			count = strlen(value);
		} else if (value_type == kValueType_Data) {
			count = parse_string_into_data((uint8_t*)value,
											strlen(value),
											value);
		} else {
			fprintf(stderr, "%s: error: Bad value type\n", argv[0]);
			ret = ERRORCODE_UNKNOWN;
			goto bail;
		}

		dbus_message_append_args(
				message,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &value, count,
				DBUS_TYPE_INVALID
			);

		if (value_type == kValueType_Byte) {
			fprintf(stdout, "Poking address 0x%x (%d) with single byte 0x%02x\n", address, address, byte);
		} else {
			fprintf(stdout, "Poking address 0x%x (%d) with %d byte(s)\n", address, address, count);
		}

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

		did_succeed = dbus_message_get_args(reply, NULL,
				DBUS_TYPE_INT32, &ret,
				DBUS_TYPE_INVALID
			);

		if (!did_succeed || ret != 0) {
			fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
			print_error_diagnosis(ret);
			goto bail;
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
