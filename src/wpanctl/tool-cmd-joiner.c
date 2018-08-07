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

const char joiner_cmd_syntax[] = "[args] <psk> [provisioning_url]";

static const arg_list_item_t joiner_option_list[] = {
	{'h', "help", NULL, "Print Help"},
	{'t', "timeout", "ms", "Set timeout period"},
	{'e', "start", NULL, "Bring up the interface and start joiner's commissioning process"},
	{'d', "stop", NULL, "Stop joiner's commissioning process"},
	{'a', "attach", NULL, "Attach to the commissioned thread network"},
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
	DBusError error;
	const char* psk = NULL;
	const char* provisioning_url = NULL;
	int psk_len = 0;
	int provisioning_url_len = 0;
	const char* property_joiner_state = kWPANTUNDProperty_ThreadJoinerState;
	dbus_bool_t action = false;

	dbus_error_init(&error);

	if (argc == 1)
	{
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
			{"stop", no_argument, 0, 'd'},
			{"attach", no_argument, 0, 'a'},
			{"state", no_argument, 0, 's'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		c = getopt_long(argc, argv, "hst:eda", long_options,
						&option_index);
		if (c == -1)
		{
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

			connection = dbus_bus_get(DBUS_BUS_STARTER, &error);

			if (!connection) {
				dbus_error_free(&error);
				dbus_error_init(&error);
				connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
			}

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

		case 'a':
			// joiner attaches to commissioned thread network
			connection = dbus_bus_get(DBUS_BUS_STARTER, &error);

			if (!connection) {
				dbus_error_free(&error);
				dbus_error_init(&error);
				connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
			}

			ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_ATTACH);
			require_action(ret == 0, bail, print_error_diagnosis(ret));

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
				fprintf(stderr, "Successfully Attached!\n");
			} else {
				fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
				print_error_diagnosis(ret);
			}
			goto bail;

		case 'e':
			// start commissioning
			action = true;

			if (optind < argc) {
				psk = argv[optind];
				psk_len = strnlen(psk, COMMR_PSK_MAX_LENGTH+1);
				optind++;
			}

			if (!psk) {
				fprintf(stderr, "%s: error: Missing PSK value.\n", argv[0]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
			else
			{
				ret = check_psk_format(psk);
				if (ret != 0)
				{
					fprintf(stderr, "%s: error: Invalid PSKd %d\n", argv[0], ret);
					goto bail;
				}
			}

			if (optind < argc) {
				provisioning_url = argv[optind];
				provisioning_url_len = strnlen(provisioning_url, (COMMR_PROVIISIONING_URL_MAX_LENGTH + 1));
				optind++;
			}

			if (!provisioning_url && provisioning_url_len > COMMR_PROVIISIONING_URL_MAX_LENGTH)
			{
				fprintf(stderr, "%s: error: Invalid privisioning_url length.\n", argv[0]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
			// intentionally pass through

		case 'd':
			// stop commissioning

			if (optind < argc) {
				fprintf(stderr,
						"%s: error: Unexpected extra argument: \"%s\"\n",
						argv[0], argv[optind]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			connection = dbus_bus_get(DBUS_BUS_STARTER, &error);

			if (!connection) {
				dbus_error_free(&error);
				dbus_error_init(&error);
				connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
			}
			require_string(connection != NULL, bail, error.message);

			ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_COMMISSIONING);
			require_action(ret == 0, bail, print_error_diagnosis(ret));

			dbus_message_append_args(
				message,
				DBUS_TYPE_BOOLEAN, &action,
				DBUS_TYPE_INVALID
			);

			{
				uint8_t psk_bytes[psk_len + 1];
				memset(psk_bytes, '\0', psk_len+1);

				if (psk)
				{
					memcpy(psk_bytes, psk, psk_len);
				}
				char *psk = psk_bytes;

				dbus_message_append_args(
						message,
						DBUS_TYPE_STRING, &psk,
						DBUS_TYPE_INVALID
						);
			}

			{
				uint8_t provisioning_url_bytes[provisioning_url_len];
				memset(provisioning_url_bytes, '\0', provisioning_url_len+1);

				if (provisioning_url)
				{
					memcpy(provisioning_url_bytes, provisioning_url, provisioning_url_len);
				}

				char *provisioning_url = provisioning_url_bytes;

				dbus_message_append_args(
						message,
						DBUS_TYPE_STRING, &provisioning_url,
						DBUS_TYPE_INVALID
						);
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

			dbus_message_get_args(reply, &error,
					DBUS_TYPE_INT32, &ret,
					DBUS_TYPE_INVALID
					);

			if (!ret) {
				fprintf(stderr, "%s joiner commissioning successfully.\n", action ? "start" : "stop");
			} else {
				fprintf(stderr, "%s %s joiner commissioning failed with error %d. %s\n", argv[0],
						action ? "start" : "stop", ret, wpantund_status_to_cstr(ret));
				print_error_diagnosis(ret);
			}
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
