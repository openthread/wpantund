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
#include "tool-cmd-add-service.h"
#include "assert-macros.h"
#include "args.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "string-utils.h"

const char add_service_syntax[] = "[args] <enterprise-number> <service-data> <server-data>";

static const arg_list_item_t add_service_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'d', "data", NULL, "Data is binary data (in hex)"},
	{'s', "string", NULL, "Data is a string"},
	{'n', "not-stable", NULL, "Indicate the service is NOT part of stable Network Data"},
	{0}
};

int tool_cmd_add_service(int argc, char* argv[])
{
	int ret = 0;
	int c;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	dbus_bool_t stable = TRUE;
	uint32_t enterprise_number;
	char* service_data;
	int service_data_len;
	char* server_data;
	int server_data_len;

	enum {
		kDataType_String,
		kDataType_Data,
	} data_type = kDataType_String;

	dbus_error_init(&error);

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"timeout", required_argument, 0, 't'},
			{"data", no_argument, 0, 'd'},
			{"string", no_argument, 0, 's'},
			{"not-stable", no_argument, 0, 'n'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "ht:dsn", long_options,
				&option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_arg_list_help(add_service_option_list,
					    argv[0], add_service_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 'd':
			data_type = kDataType_Data;
			break;

		case 's':
			data_type = kDataType_String;
			break;

		case 'n':
			stable = false;
			break;

		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;
		}
	}

	if (optind < argc) {
		enterprise_number = (uint32_t)strtoul(argv[optind], NULL, 0);
		optind++;
	} else {
		fprintf((stderr), "%s: No enterprise number argument given\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (optind < argc) {
		service_data = argv[optind];
		optind++;
	} else {
		fprintf((stderr), "%s: No service data argument given\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (optind < argc) {
		server_data = argv[optind];
		optind++;
	} else {
		fprintf((stderr), "%s: No server data argument given\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
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
		char path[DBUS_MAXIMUM_NAME_LENGTH+1];
		char interface_dbus_name[DBUS_MAXIMUM_NAME_LENGTH+1];
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
		    WPANTUND_IF_CMD_SERVICE_ADD
		    );

		service_data_len = strlen(service_data);
		server_data_len = strlen(server_data);

		if (data_type == kDataType_Data) {
			service_data_len = parse_string_into_data(
				(uint8_t*)service_data, service_data_len, service_data);

			server_data_len = parse_string_into_data(
				(uint8_t*)server_data, server_data_len, server_data);
		}

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT32, &enterprise_number,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &service_data, service_data_len,
			DBUS_TYPE_BOOLEAN, &stable,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &server_data, server_data_len,
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

		if (ret) {
			fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
		} else {
			fprintf(stderr, "Service added.\n");
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
