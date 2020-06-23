/*
 *
 * Copyright (c) 2018 OpenThread Authors, Inc.
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
 *      This file implements "joiner" command in wpanctl.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <getopt.h>
#include "wpanctl-utils.h"
#include "tool-cmd-joiner.h"
#include "args.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "string-utils.h"
#include "commissioner-utils.h"
//#include "spinel.h"

const char joiner_cmd_syntax[] = "[args] <psk> [provisioning_url] [vendor_name] [vendor_model] [vendor_sw_version] [vendor_data]";

static const arg_list_item_t joiner_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'e', "start", NULL, "Bring up the interface and start joiner's commissioning process"},
	{'j', "join", NULL, "Same as start but waits till end of commissioning process"},
	{'d', "stop", NULL, "Stop joiner's commissioning process"},
	{'a', "attach", NULL, "Attach to the commissioned thread network (nonblocking)"},
	{'b', "attach-blocking", NULL, "Same as attach but blocks till device is associated"},
	{'s', "state", NULL, "Joiner state"},
	{0}
};

int tool_cmd_joiner(int argc, char* argv[])
{
	int ret = 0;
	int c;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter dict_iter;
	DBusError error;
	const char *empty_string = "";
	const char *psk = NULL;
	const char *provisioning_url = NULL;
	const char *vendor_name = NULL;
	const char *vendor_model = NULL;
	const char *vendor_sw_version = NULL;
	const char *vendor_data = NULL;
	const char *property_joiner_state = kWPANTUNDProperty_JoinerState;
	dbus_bool_t returnOnStart = true;

	dbus_error_init(&error);

	if (argc == 1) {
		fprintf(stderr, "%s: error: Missing command.\n", argv[0]);
		print_arg_list_help(joiner_option_list,
				argv[0], joiner_cmd_syntax);
		goto bail;
	}

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"timeout", required_argument, 0, 't'},
			{"start", no_argument, 0, 'e'},
			{"join", no_argument, 0, 'j'},
			{"stop", no_argument, 0, 'd'},
			{"attach", no_argument, 0, 'a'},
			{"attach-blocking", no_argument, 0, 'b'},
			{"state", no_argument, 0, 's'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "hst:ejdab", long_options,
						&option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_arg_list_help(joiner_option_list,
								argv[0], joiner_cmd_syntax);
			ret = ERRORCODE_HELP;
			goto bail;

		case 't':
			//timeout
			timeout = strtol(optarg, NULL, 0);
			break;

		case 's':
			// state
			if (optind < argc) {
				fprintf(stderr,
						"%s: error: Unexpected extra argument: \"%s\"\n",
						argv[0], argv[optind]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

			ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_PROP_GET);
			require_action(ret == 0, bail, print_error_diagnosis(ret));

			dbus_message_append_args(
				message,
				DBUS_TYPE_STRING, &property_joiner_state,
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

			dbus_message_iter_init(reply, &iter);

			// Get return code
			dbus_message_iter_get_basic(&iter, &ret);

			if (ret) {
				const char* error_cstr = NULL;

				// Try to see if there is an error explanation we can extract
				dbus_message_iter_next(&iter);
				if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
					dbus_message_iter_get_basic(&iter, &error_cstr);
				}

				if(!error_cstr || error_cstr[0] == 0) {
					error_cstr = (ret<0)?strerror(-ret):"Get failed";
				}

				fprintf(stderr, "%s: %s (%d)\n", property_joiner_state, error_cstr, ret);
				goto bail;
			}

			// Move to the property
			dbus_message_iter_next(&iter);

			uint8_t state;
			dbus_message_iter_get_basic(&iter, &state);
			fprintf(stdout, "%d (%s)\n", state, joiner_state_int2str(state));
			goto bail;

		case 'b':
			returnOnStart = false;
			// Fall through

		case 'a':
			// joiner attaches to commissioned thread network
			connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

			ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_ATTACH);
			require_action(ret == 0, bail, print_error_diagnosis(ret));

			dbus_message_iter_init_append(message, &iter);

			// Open a container as "Array of Dictionary entries from String to Variants" (dbus type "a{sv}")
			dbus_message_iter_open_container(
				&iter,
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
				kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart,
				DBUS_TYPE_BOOLEAN, &returnOnStart
			);

			dbus_message_iter_close_container(&iter, &dict_iter);

			// Send DBus message and parse the DBus reply

			reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, &error);

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
				fprintf(stdout, returnOnStart ? "Successfully started attaching...\n" : "Successfully attached!\n");
			} else {
				fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
				print_error_diagnosis(ret);
			}
			goto bail;

		case 'j':
			returnOnStart = false;
			// Fall through

		case 'e':
			// start commissioning

			if (optind < argc) {
				psk = argv[optind];
				optind++;
			}

			if (!psk) {
				fprintf(stderr, "%s: error: Missing PSK value.\n", argv[0]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			ret = check_psk_format(psk);
			if (ret != 0) {
				fprintf(stderr, "%s: error: Invalid PSKd %d\n", argv[0], ret);
				goto bail;
			}

			if (optind < argc) {
				size_t len;

				provisioning_url = argv[optind++];
				len = strnlen(provisioning_url, (COMMR_PROVIISIONING_URL_MAX_LENGTH + 1));

				if (len > COMMR_PROVIISIONING_URL_MAX_LENGTH) {
					fprintf(stderr, "%s: error: Provisioning URL is too long, must be maximum %d characters\n",
						argv[0], COMMR_PROVIISIONING_URL_MAX_LENGTH);
					ret = ERRORCODE_BADARG;
					goto bail;
				}
			}

			if (optind < argc) {
				vendor_name = argv[optind++];
			}

			if (optind < argc) {
				vendor_model = argv[optind++];
			}

			if (optind < argc) {
				vendor_sw_version = argv[optind++];
			}

			if (optind < argc) {
				vendor_data = argv[optind++];
			}

			if (optind < argc) {
				fprintf(stderr,	"%s: error: Unexpected extra argument: \"%s\"\n", argv[0], argv[optind]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

			require_string(connection != NULL, bail, error.message);

			ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_START);
			require_action(ret == 0, bail, print_error_diagnosis(ret));

			dbus_message_iter_init_append(message, &iter);

			// Open a container as "Array of Dictionary entries from String to Variants" (dbus type "a{sv}")
			dbus_message_iter_open_container(
				&iter,
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
				kWPANTUNDValueMapKey_Joiner_PSKd,
				DBUS_TYPE_STRING, &psk
			);

			append_dbus_dict_entry_basic(
				&dict_iter,
				kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart,
				DBUS_TYPE_BOOLEAN, &returnOnStart
			);

			if (provisioning_url) {
				append_dbus_dict_entry_basic(
					&dict_iter,
					kWPANTUNDValueMapKey_Joiner_ProvisioningUrl,
					DBUS_TYPE_STRING, &provisioning_url
				);
			}

			if (vendor_name) {
				append_dbus_dict_entry_basic(
					&dict_iter,
					kWPANTUNDValueMapKey_Joiner_VendorName,
					DBUS_TYPE_STRING, &vendor_name
				);
			}

			if (vendor_model) {
				append_dbus_dict_entry_basic(
					&dict_iter,
					kWPANTUNDValueMapKey_Joiner_VendorModel,
					DBUS_TYPE_STRING, &vendor_model
				);
			}

			if (vendor_sw_version) {
				append_dbus_dict_entry_basic(
					&dict_iter,
					kWPANTUNDValueMapKey_Joiner_VendorSwVersion,
					DBUS_TYPE_STRING, &vendor_sw_version
				);
			}

			if (vendor_data) {
				append_dbus_dict_entry_basic(
					&dict_iter,
					kWPANTUNDValueMapKey_Joiner_VendorData,
					DBUS_TYPE_STRING, &vendor_data
				);
			}

			dbus_message_iter_close_container(&iter, &dict_iter);

			fprintf(stdout, "Starting joiner commissioning, PSKd:\"%s\"", psk);

			if (provisioning_url) {
				fprintf(stdout, ", ProvisioningURL:\"%s\"", provisioning_url);
			}

			if (vendor_name) {
				fprintf(stdout, ", VendorName:\"%s\"", vendor_name);
			}

			if (vendor_model) {
				fprintf(stdout, ", VendorModel:\"%s\"", vendor_model);
			}

			if (vendor_sw_version) {
				fprintf(stdout, ", VendorSwVersion:\"%s\"", vendor_sw_version);
			}

			if (vendor_data) {
				fprintf(stdout, ", VendorData:\"%s\"", vendor_data);
			}

			fprintf(stdout, " ...\n");

			// Send DBus message and parse the DBus reply

			reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, &error);

			if (!reply) {
				fprintf(stderr, "%s: error: %s\n", argv[0], error.message);
				ret = ERRORCODE_TIMEOUT;
				goto bail;
			}

			dbus_message_get_args(reply, &error, DBUS_TYPE_INT32, &ret, DBUS_TYPE_INVALID);

			if (ret) {
				if (returnOnStart) {
					fprintf(stderr, "Failed to start Joiner Commissioning - error %d. %s\n", ret, wpantund_status_to_cstr(ret));
				} else {
					fprintf(stderr, "Joiner commissioning failed - error %d. %s\n", ret, wpantund_status_to_cstr(ret));
				}
				print_error_diagnosis(ret);
				goto bail;
			}

			if (returnOnStart) {
				fprintf(stdout, "Successfully started!\n");
			} else {
				fprintf(stdout, "Successfully joined!\n");
			}

			goto bail;

		case 'd':
			// stop commissioning

			if (optind < argc) {
				fprintf(stderr,	"%s: error: Unexpected extra argument: \"%s\"\n", argv[0], argv[optind]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

			require_string(connection != NULL, bail, error.message);

			ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_STOP);
			require_action(ret == 0, bail, print_error_diagnosis(ret));

			reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, &error);

			if (!reply) {
				fprintf(stderr, "%s: error: %s\n", argv[0], error.message);
				ret = ERRORCODE_TIMEOUT;
				goto bail;
			}

			dbus_message_get_args(reply, &error, DBUS_TYPE_INT32, &ret, DBUS_TYPE_INVALID);

			if (ret) {
				fprintf(stderr, "Failed to stop joiner commissioning - error %d. %s\n", ret, wpantund_status_to_cstr(ret));
				print_error_diagnosis(ret);
				goto bail;
			}

			fprintf(stdout, "Stopped joiner commissioning\n");
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
