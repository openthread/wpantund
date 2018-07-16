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

#include <getopt.h>
#include "wpanctl-utils.h"
#include "tool-cmd-form.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "args.h"
#include "string-utils.h"

#include <arpa/inet.h>
#include <errno.h>

const char form_cmd_syntax[] = "[args] <network-name>";

static const arg_list_item_t form_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'c', "channel", "channel", "Set the desired channel"},
	{'m', "channel-mask", "mask", "Specify a channel mask (channel will be chosen randomly from given mask)"},
	{'p', "panid", "panid", "Specify a specific PAN ID"},
	{'x', "xpanid", "xpanid", "Specify a specific Extended PAN ID"},
	{'k', "key", "key", "Specify the network key"},
	{'i', "key-index", "index", "Specify network key index"},
	{'T', "type", "node-type: router(r,2), end-device(end,e,3), sleepy-end-device(sleepy,sed,4), nl-lurker(lurker,l,6)",
		"Form as a specific node type" },
	{'M', "mesh-local-prefix", "Mesh-Local IPv6 Prefix", "Specify a non-default mesh-local IPv6 prefix"},
	{'L', "legacy-prefix", "Legacy IPv6 Prefix", "Specify a specific *LEGACY* IPv6 prefix"},
	{0}
};

int tool_cmd_form(int argc, char *argv[])
{
	int ret = 0;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	DBusMessageIter msg_iter;
	DBusMessageIter dict_iter;

	const char *network_name = NULL;
	uint16_t channel = 0;
	uint32_t channel_mask = 0;
	uint16_t panid = 0;
	uint64_t xpanid = 0;
	uint8_t network_key[WPANCTL_NETWORK_KEY_SIZE];
	uint32_t key_index = 0;
	const char *node_type = kWPANTUNDNodeType_Router;
	uint8_t mesh_local_prefix[WPANCTL_PREFIX_SIZE];
	uint8_t legacy_prefix[WPANCTL_PREFIX_SIZE];
	bool has_channel = false;
	bool has_channel_mask = false;
	bool has_panid = false;
	bool has_xpanid = false;
	bool has_network_key = false;
	bool has_key_index = false;
	bool has_node_type = false;
	bool has_mesh_local_prefix = false;
	bool has_legacy_prefix = false;

	dbus_error_init(&error);

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"timeout", required_argument, 0, 't'},
			{"channel", required_argument, 0, 'c'},
			{"channel-mask", required_argument, 0, 'm'},
			{"panid", required_argument, 0, 'p'},
			{"xpanid", required_argument, 0, 'x'},
			{"key", required_argument, 0, 'k'},
			{"key-index", required_argument, 0, 'i'},
			{"ula-prefix", required_argument, 0, 'u'},
			{"mesh-local-prefix", required_argument, 0, 'M'},
			{"legacy-prefix", required_argument, 0, 'L'},
			{"type", required_argument, 0, 'T'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		int c;

		c = getopt_long(argc, argv, "ht:c:m:p:x:k:i:u:M:L:T:", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_arg_list_help(form_option_list, argv[0], form_cmd_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;

		case 'c':
			has_channel = true;
			channel = strtol(optarg, NULL, 0);
			break;

		case 'm':
			has_channel_mask = true;
			channel_mask = strtomask_uint32(optarg);
			if (channel_mask == 0) {
				fprintf(stderr, "%s: error: Bad channel mask \"%s\"\n", argv[0], optarg);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
			break;

		case 'p':
			has_panid = true;
			panid = strtol(optarg, NULL, 0);
			break;

		case 'x':
			has_xpanid = true;
			xpanid = strtoull(optarg, NULL, 16);
			break;

		case 'k':
			has_network_key = true;
			if (parse_string_into_data(network_key, WPANCTL_NETWORK_KEY_SIZE, optarg) <= 0) {
				fprintf(stderr, "%s: error: Bad network-key \"%s\"\n", argv[0], optarg);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
			break;

		case 'i':
			has_key_index = true;
			key_index = strtol(optarg, NULL, 0);
			break;

		case 'M':
			has_mesh_local_prefix = true;
			ret = parse_prefix(optarg, mesh_local_prefix);
			if (ret != ERRORCODE_OK) {
				fprintf(stderr, "%s: error: Bad mesh-local prefix \"%s\"\n", argv[0], optarg);
				goto bail;
			}
			break;

		case 'L':
		case 'u':
			has_legacy_prefix = true;
			ret = parse_prefix(optarg, legacy_prefix);
			if (ret != ERRORCODE_OK) {
				fprintf(stderr, "%s: error: Bad legacy prefix \"%s\"\n", argv[0], optarg);
				goto bail;
			}
			break;

		case 'T':
			has_node_type = true;
			node_type = parse_node_type(optarg);
			break;
		}
	}

	if (optind < argc) {
		network_name = argv[optind];
		optind++;

		if (strnlen(network_name, WPANCTL_NETWORK_NAME_MAX_LEN + 1) > WPANCTL_NETWORK_NAME_MAX_LEN) {
			fprintf(stderr, "%s: error: Network name \"%s\" is too long (max %d chars)\n", argv[0], network_name,
				WPANCTL_NETWORK_NAME_MAX_LEN);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

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

	// Print the parameters

	fprintf(stdout, "Forming WPAN \"%s\" as node type \"%s\"", network_name, node_type);

	if (has_channel) {
		fprintf(stdout, ", channel:%d", channel);
	} else if (has_channel_mask) {
		fprintf(stdout, ", channel-mask:0x%x", channel_mask);
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

	if (has_key_index) {
		fprintf(stdout, ", key-index:%d", key_index);
	}

	if (has_mesh_local_prefix) {
		char address_string[INET6_ADDRSTRLEN] = "::";
		uint8_t prefix_address[WPANCTL_IPv6_ADDRESS_SIZE];

		memset(prefix_address, 0, sizeof(prefix_address));
		memcpy(prefix_address, mesh_local_prefix, WPANCTL_PREFIX_SIZE);
		inet_ntop(AF_INET6, (const void *)&prefix_address, address_string, sizeof(address_string));
		fprintf(stdout, ", mesh-local-prefix:\"%s\"", address_string);
	}

	if (has_legacy_prefix) {
		char address_string[INET6_ADDRSTRLEN] = "::";
		uint8_t prefix_address[WPANCTL_IPv6_ADDRESS_SIZE];

		memset(prefix_address, 0, sizeof(prefix_address));
		memcpy(prefix_address, legacy_prefix, WPANCTL_PREFIX_SIZE);
		inet_ntop(AF_INET6, (const void *)&prefix_address, address_string, sizeof(address_string));
		fprintf(stdout, ", legacy-prefix:\"%s\"", address_string);
	}

	fprintf(stdout, "\n");

	// Prepare DBus connection

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	require_string(connection != NULL, bail, error.message);

	// Prepare DBus message

	ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_FORM);
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

	if (has_node_type) {
		append_dbus_dict_entry_basic(
			&dict_iter,
			kWPANTUNDProperty_NetworkNodeType,
			DBUS_TYPE_STRING, &node_type
		);
	}

	if (has_channel) {
		append_dbus_dict_entry_basic(
			&dict_iter,
			kWPANTUNDProperty_NCPChannel,
			DBUS_TYPE_UINT16, &channel
		);
	}

	if (has_channel_mask) {
		append_dbus_dict_entry_basic(
			&dict_iter,
			kWPANTUNDProperty_NCPChannelMask,
			DBUS_TYPE_UINT32, &channel_mask
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

	if (has_key_index) {
		append_dbus_dict_entry_basic(
			&dict_iter,
			kWPANTUNDProperty_NetworkKeyIndex,
			DBUS_TYPE_UINT32, &key_index
		);
	}

	if (has_mesh_local_prefix) {
		append_dbus_dict_entry_byte_array(
			&dict_iter,
			kWPANTUNDProperty_IPv6MeshLocalPrefix,
			mesh_local_prefix,
			WPANCTL_PREFIX_SIZE
		);
	}

	if (has_legacy_prefix) {
		append_dbus_dict_entry_byte_array(
			&dict_iter,
			kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix,
			legacy_prefix,
			WPANCTL_PREFIX_SIZE
		);
	}

	dbus_message_iter_close_container(&msg_iter, &dict_iter);

	// Send DBus message and parse the DBus reply

	reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, &error);

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
		fprintf(stdout, "Successfully formed!\n");
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
