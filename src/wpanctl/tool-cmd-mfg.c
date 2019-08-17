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
#include "tool-cmd-status.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "args.h"

#define MFG_MAX_COMMAND_SIZE        1300
#define MFG_TIMEOUT_IN_SECONDS      10

int tool_cmd_mfg(int argc, char *argv[])
{
	int ret = 0;
	char command[MFG_MAX_COMMAND_SIZE];
	char *input = &command[0];
	const char *output = NULL;
	int timeout = MFG_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;

	DBusError error;

	dbus_error_init(&error);

	{
		char *buf_ptr = command;
		int buf_len = sizeof(command);
		int index;
		int len;

		for (index = 1; index < argc; index++) {

			len = snprintf(
				buf_ptr,
				buf_len,
				"%s%s",
				(index == 1) ? "" : " ",
				argv[index]
			);

			require(len >= 0, bail);

			if (len >= buf_len) {
				fprintf(stderr, "%s: error: command string exceeds max size %lu \n", argv[0], sizeof(command));
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			buf_ptr += len;
			buf_len -= len;
		}
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	require_string(error.name == NULL, bail, error.message);

	{
		DBusMessageIter iter;
		DBusMessageIter list_iter;
		char path[DBUS_MAXIMUM_NAME_LENGTH+1];
		char interface_dbus_name[DBUS_MAXIMUM_NAME_LENGTH+1];

		ret = lookup_dbus_name_from_interface(interface_dbus_name, gInterfaceName);

		if (ret != 0) {
			print_error_diagnosis(ret);
			goto bail;
		}

		snprintf(
			path,
			sizeof(path),
			"%s/%s",
			WPANTUND_DBUS_PATH,
			gInterfaceName
		);

		message = dbus_message_new_method_call(
			interface_dbus_name,
			path,
			WPANTUND_DBUS_NLAPIv1_INTERFACE,
			WPANTUND_IF_CMD_MFG
		);

		dbus_message_append_args(
			message,
			DBUS_TYPE_STRING, &input,
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

		dbus_message_iter_get_basic(&iter, &ret);

		dbus_message_iter_next(&iter);

		if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&iter, &output);
			printf("%s", output);
		} else {
			dump_info_from_iter(stdout, &iter, 0, false, false);
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
