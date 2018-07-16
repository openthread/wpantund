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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <getopt.h>
#include "wpanctl-utils.h"
#include "string-utils.h"
#include "tool-cmd-join.h"
#include "tool-cmd-scan.h"
#include "assert-macros.h"
#include "args.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"

#include <errno.h>

const char join_cmd_syntax[] = "[args] <network name> or <index of a previously scanned network>";

static const arg_list_item_t join_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'T', "type", "node-type: router(r,2), end-device(end,e,3), sleepy-end-device(sleepy,sed,4), nl-lurker(lurker,l,6)",
		"Join as a specific node type"},
	{'p', "panid", NULL, "Specify a specific PAN ID"},
	{'x', "xpanid", NULL, "Specify a specific Extended PAN ID"},
	{'c', "channel", NULL, "Specify a specific channel"},
	{'k', "key", NULL, "Specify the network key"},
	{'n', "name", NULL, "Forces the input argument to be treated as <network name> instead of scan index"
		" (useful if network name is a number)"},
	{0}
};

int tool_cmd_join(int argc, char* argv[])
{
	int ret = ERRORCODE_OK;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	DBusMessageIter msg_iter;
	DBusMessageIter dict_iter;

	bool parse_arg_as_network_name = false;
	int scanned_network_index = -1;
	const char *network_name = NULL;
	const char *node_type = kWPANTUNDNodeType_EndDevice;
	uint16_t channel = 0;
	uint16_t panid = 0;
	uint64_t xpanid = 0;
	uint8_t network_key[WPANCTL_NETWORK_KEY_SIZE];
	bool has_channel = false;
	bool has_panid = false;
	bool has_xpanid = false;
	bool has_network_key = false;

	dbus_error_init(&error);

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"timeout", required_argument, 0, 't'},
			{"type", required_argument, 0, 'T'},
			{"panid", required_argument, 0, 'p'},
			{"xpanid", required_argument, 0, 'x'},
			{"channel", required_argument, 0, 'c'},
			{"key", required_argument, 0, 'k'},
			{"name", no_argument, 0, 'n'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		int c;

		c = getopt_long(argc, argv, "ht:T:x:p:c:k:n", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_arg_list_help(join_option_list, argv[0], join_cmd_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;

		case 'p':
			has_panid = true;
			panid = strtol(optarg, NULL, 0);
			break;

		case 'x':
			has_xpanid = true;
			xpanid = strtoull(optarg, NULL, 16);
			break;

		case 'c':
			has_channel = true;
			channel = strtol(optarg, NULL, 0);
			break;

		case 'k':
			has_network_key = true;
			if (parse_string_into_data(network_key, WPANCTL_NETWORK_KEY_SIZE, optarg) <= 0) {
				fprintf(stderr, "%s: error: Bad network-key \"%s\"\n", argv[0], optarg);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
			break;

		case 'T':
			node_type = parse_node_type(optarg);
			break;

		case 'n':
			parse_arg_as_network_name = true;
			break;
		}
	}

	if (optind < argc) {

		// Instead of network-name the index of a previously scanned network can be provided.

		if (!parse_arg_as_network_name && sscanf(argv[optind], "%d", &scanned_network_index) == 1) {

			if (gScannedNetworkCount == 0) {
				fprintf(stderr,
					"%s: error: Index %d but no previous/saved scanned networks\n"
					"\nuse `-n` to force the argument to be parsed as <network-name>"
					"\ninstead of <index of a previously scanned network>\n\n",
					argv[0], scanned_network_index);
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			if ((scanned_network_index == 0) || (scanned_network_index > gScannedNetworkCount)) {
				fprintf(stderr, "%s: error: Invalid index %d. %d saved scan networks\n"
					"\nuse `-n` to force the argument to be parsed as <network-name>"
					"\ninstead of <index of a previously scanned network>\n\n",
					argv[0], scanned_network_index, gScannedNetworkCount);
				ret - ERRORCODE_BADARG;
				goto bail;
			}

			if (has_panid) {
				fprintf(stderr, "%s: warning: Specified PANID will be overwritten by scanned network info.\n", argv[0]);
			}

			if (has_xpanid) {
				fprintf(stderr, "%s: warning: Specified XPANID will be overwritten by scanned network info.\n",
					argv[0]);
			}

			if (has_channel) {
				fprintf(stderr, "%s: warning: Specified channel will be overwritten by scanned network info.\n",
					argv[0]);
			}

			has_panid = true;
			panid = gScannedNetworks[scanned_network_index - 1].pan_id;

			has_xpanid = true;
			xpanid = gScannedNetworks[scanned_network_index - 1].xpanid;

			has_channel = true;
			channel = gScannedNetworks[scanned_network_index - 1].channel;

			network_name = gScannedNetworks[scanned_network_index -1].network_name;

		} else {
			network_name = argv[optind];
		}

		if (strnlen(network_name, WPANCTL_NETWORK_NAME_MAX_LEN + 1) > WPANCTL_NETWORK_NAME_MAX_LEN) {
			fprintf(stderr, "%s: error: Network name \"%s\" is too long (max %d chars)\n", argv[0], network_name,
				WPANCTL_NETWORK_NAME_MAX_LEN);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		optind++;

	} else {
		fprintf(stderr, "%s: error: Missing network name\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (optind < argc) {
		fprintf(stderr, "%s: error: Unexpected extra argument: \"%s\"\n", argv[0], argv[optind]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (gInterfaceName[0] == 0) {
		fprintf(stderr,
			"%s: error: No WPAN interface set (use the `cd` command, or the `-I` argument for `wpanctl`).\n", argv[0]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	fprintf(stderr, "Joining WPAN \"%s\" as node type \"%s\"", network_name, node_type);

	if (has_channel) {
		fprintf(stdout, ", channel:%d", channel);
	}

	if (has_panid) {
		fprintf(stdout, ", panid:0x%04X", panid);
	}

	if (has_xpanid) {
		fprintf(stdout, ", xpanid:0x%016llX", (unsigned long long)xpanid);
	}

	if (has_network_key) {
		char key_str[WPANCTL_NETWORK_KEY_SIZE * 2 + 4];
		encode_data_into_string(network_key, sizeof(network_key), key_str, sizeof(key_str), 0);
		fprintf(stdout, ", key:[%s]", key_str);
	}

	if (scanned_network_index != -1) {
		fprintf(stdout, " [scanned network index %d]", scanned_network_index);
	}

	fprintf(stdout, "\n");

	// Prepare DBus connection

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	require_string(connection != NULL, bail, error.message);

	// Prepare DBus message

	ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOIN);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	dbus_message_iter_init_append(message, &msg_iter);

	// Open a container as "Array of Dictionary entries from String to Variants" (dbus type "a{sv}")
	dbus_message_iter_open_container(
		&msg_iter,
		DBUS_TYPE_ARRAY,
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING
			DBUS_TYPE_VARIANT_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
		&dict_iter
	);

	// Append dictionary entries

	append_dbus_dict_entry_basic(
		&dict_iter,
		kWPANTUNDProperty_NetworkName,
		DBUS_TYPE_STRING, &network_name
	);

	append_dbus_dict_entry_basic(
		&dict_iter,
		kWPANTUNDProperty_NetworkNodeType,
		DBUS_TYPE_STRING, &node_type
	);

	if (has_channel) {
		append_dbus_dict_entry_basic(
			&dict_iter,
			kWPANTUNDProperty_NCPChannel,
			DBUS_TYPE_UINT16, &channel
		);
	}

	if (has_panid) {
		append_dbus_dict_entry_basic(
			&dict_iter,
			kWPANTUNDProperty_NetworkPANID,
			DBUS_TYPE_UINT16, &panid
		);
	}

	if (has_xpanid) {
		append_dbus_dict_entry_basic(
			&dict_iter,
			kWPANTUNDProperty_NetworkXPANID,
			DBUS_TYPE_UINT64, &xpanid
		);
	}

	if (has_network_key) {
		append_dbus_dict_entry_byte_array(
			&dict_iter,
			kWPANTUNDProperty_NetworkKey,
			network_key,
			sizeof(network_key)
		);
	}

	dbus_message_iter_close_container(&msg_iter, &dict_iter);

	// Send DBus message and parse the DBus reply

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

	dbus_message_get_args(
		reply, &error,
		DBUS_TYPE_INT32, &ret,
		DBUS_TYPE_INVALID
	);

	if (!ret) {
		fprintf(stdout, "Successfully Joined!\n");
	} else if ((ret == -EINPROGRESS) || (ret == kWPANTUNDStatus_InProgress)) {
		fprintf(stdout, "Partial (insecure) join. Credentials needed. Update key to continue.\n");
		ret = ERRORCODE_OK;
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
