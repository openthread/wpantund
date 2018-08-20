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
#include "tool-cmd-dataset.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "wpan-properties.h"

#include <errno.h>

typedef struct dataset_command_s
{
	const char *long_name;
	const char *short_name;
	const char *prop_value;
	const char *help_string;
} dataset_command_t;

static dataset_command_t datsetCommandList[] =
{
	{
		"erase", "e", kWPANTUNDDatasetCommand_Erase,
		"Erase the local Dataset (all fields are un-set)."
	},
	{
		"get-active", "ga", kWPANTUNDDatasetCommand_GetActive,
		"Get the NCP's Active Operational Dataset and populate the local Dataset from it."
	},
	{
		"set-active", "sa", kWPANTUNDDatasetCommand_SetActive,
		"Set the NCP's Active Operational Dataset from the current local Dataset."
	},
	{
		"mgmt-get-active", "mga", kWPANTUNDDatasetCommand_SendMgmtGetActive,
		"Send a MGMT_GET_ACTIVE meshcop command requesting TLVs in the current local Dataset."
	},
	{
		"mgmt-set-active", "msa", kWPANTUNDDatasetCommand_SendMgmtSetActive,
		"Send a MGMT_SET_ACTIVE meshcop command along with the current local Dataset."
	},
	{
		"get-pending", "gp", kWPANTUNDDatasetCommand_GetPending,
		"Get the NCP's Pending Operational Dataset and populate the local Dataset from it."
	},
	{
		"set-pending", "sp", kWPANTUNDDatasetCommand_SetPending,
		"Set the NCP's Pending Operational Dataset from the current local Dataset."
	},
	{
		"mgmt-get-pending", "mgp", kWPANTUNDDatasetCommand_SendMgmtGetPending,
		"Send a MGMT_GET_PENDING meshcop command requesting TLVs in the current local Dataset."
	},
	{
		"mgmt-set-pending", "msp", kWPANTUNDDatasetCommand_SendMgmtSetPending,
		"Send a MGMT_SET_PENDING meshcop command along with the current local Dataset to leader"
	},
	{
		NULL, NULL, NULL, NULL
	}
};

static void print_help(const char *command_name)
{
	dataset_command_t *entry = datsetCommandList;

	printf("Syntax:\n");
	printf("   %s <command>\n", command_name);
	printf("Valid commands are:\n");

	while (entry->long_name != NULL)	{
		printf("   %-16s (or %-3s)      %s\n", entry->long_name, entry->short_name, entry->help_string);
		entry++;
	}
}

int tool_cmd_dataset(int argc, char* argv[])
{
	int ret = 0;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	const char *prop_name = kWPANTUNDProperty_DatasetCommand;
	dataset_command_t *cmd_entry = datsetCommandList;

	dbus_error_init(&error);

	if (argc == 1) {
		print_help(argv[0]);
		ret = ERRORCODE_HELP;
		goto bail;
	}

	while (cmd_entry->long_name != NULL) {
		if ((strcmp(cmd_entry->long_name, argv[1]) == 0) || (strcmp(cmd_entry->short_name, argv[1]) == 0)) {
			break;
		}

		cmd_entry++;
	}

	if (cmd_entry->long_name == NULL) {
		fprintf(stderr, "%s: error: Bad dataset command\n", argv[0]);
		print_help(argv[0]);
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

		snprintf(path, sizeof(path), "%s/%s", WPANTUND_DBUS_PATH, gInterfaceName);

		message = dbus_message_new_method_call(
			interface_dbus_name,
			path,
			WPANTUND_DBUS_APIv1_INTERFACE,
			WPANTUND_IF_CMD_PROP_SET
		);

		dbus_message_append_args(
			message,
			DBUS_TYPE_STRING, &prop_name,
			DBUS_TYPE_STRING, &cmd_entry->prop_value,
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
