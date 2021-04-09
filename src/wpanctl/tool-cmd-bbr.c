/*
 *  Copyright (c) 2021, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "assert-macros.h"
#include "tool-cmd-bbr.h"
#include "wpan-dbus-v1.h"
#include "wpanctl-utils.h"

#define MAX_COMMAND_LEN     7
#define CMD_CONFIG_PARAMS   3
#define CMD_STATE_PARAMS    0
#define CMD_JITTER_PARAMS   1
#define CMD_REGISTER_PARAMS 0

typedef int (*command_handler_t)(int argc, char* argv[], DBusMessage **message);

static int handle_config(int argc, char* argv[], DBusMessage **message)
{
	int ret = 0;

	if (argc != CMD_CONFIG_PARAMS)
	{
		fprintf(
			stderr,
			"bbr config: error: invalid number of input parameters, got \"%u\", expected \"%u\"\n",
			argc, CMD_CONFIG_PARAMS
		);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	errno = 0;
	char *ptr;
	char *arg = argv[0];
	unsigned long tmp = strtoul(arg, &ptr, 10);
	if ((errno != 0) || (ptr == arg) || (*ptr != '\0') || (tmp > UINT8_MAX)) {
		fprintf(stderr, "bbr config: error: Bad seqence number value %s\n", arg);
		ret = ERRORCODE_BADARG;
		goto bail;
	}
	uint8_t seqno = tmp;

	arg = argv[1];
	tmp = strtoul(arg, &ptr, 10);
	if ((errno != 0) || (ptr == arg) || (*ptr != '\0') || (tmp > UINT16_MAX)) {
		fprintf(stderr, "bbr config: error: Bad delay value %s\n", arg);
		ret = ERRORCODE_BADARG;
		goto bail;
	}
	uint16_t delay = tmp;

	arg = argv[2];
	tmp = strtoul(arg, &ptr, 10);
	if ((errno != 0) || (ptr == arg) || (*ptr != '\0') || (tmp > UINT32_MAX)) {
		fprintf(stderr, "bbr config: error: Bad timeout value %s\n", arg);
		ret = ERRORCODE_BADARG;
		goto bail;
	}
	uint32_t timeout = tmp;

	ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_BACKBONE_ROUTER_CONFIG);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	dbus_message_append_args(
		*message,
		DBUS_TYPE_UINT16, &delay,
		DBUS_TYPE_UINT32, &timeout,
		DBUS_TYPE_BYTE, &seqno,
		DBUS_TYPE_INVALID
	);

bail:
	return ret;
}

static int handle_state(int argc, char* argv[], DBusMessage **message, char *state_str)
{
	int ret = 0;

	if (argc != CMD_STATE_PARAMS)
	{
		fprintf(
			stderr,
			"bbr enable/disable: error: invalid number of input parameters, got \"%u\", expected \"%u\"\n",
			argc, CMD_STATE_PARAMS
		);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_PROP_SET);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	const char *prop_str;
	prop_str = kWPANTUNDProperty_ThreadBackboneRouterLocalState;

	dbus_message_append_args(
		*message,
		DBUS_TYPE_STRING, &prop_str,
		DBUS_TYPE_INVALID
	);

	dbus_message_append_args(
		*message,
		DBUS_TYPE_STRING, &state_str,
		DBUS_TYPE_INVALID
	);

bail:
	return ret;
}

static int handle_enable(int argc, char* argv[], DBusMessage **message)
{
	int ret = handle_state(argc, argv, message, kWPANTUNDThreadBackboneRouterState_Primary);
	return ret;
}

static int handle_disable(int argc, char* argv[], DBusMessage **message)
{
	int ret = handle_state(argc, argv, message, kWPANTUNDThreadBackboneRouterState_Disabled);
	return ret;
}

static int handle_jitter(int argc, char* argv[], DBusMessage **message)
{
	int ret = 0;

	if (argc != CMD_JITTER_PARAMS)
	{
		fprintf(
			stderr,
			"bbr jitter: error: invalid number of input parameters, got \"%u\", expected \"%u\"\n",
			argc, CMD_JITTER_PARAMS
		);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_PROP_SET);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	const char *prop_str;
	prop_str = kWPANTUNDProperty_ThreadBackboneRouterLocalJitter;

	dbus_message_append_args(
		*message,
		DBUS_TYPE_STRING, &prop_str,
		DBUS_TYPE_INVALID
	);

	errno = 0;
	char *ptr;
	char *arg = argv[0];
	unsigned long tmp = strtoul(arg, &ptr, 10);
	if ((errno != 0) || (ptr == arg) || (*ptr != '\0') || (tmp > UINT8_MAX)) {
		fprintf(stderr, "bbr jitter: error: Bad jitter value %s\n", arg);
		ret = ERRORCODE_BADARG;
		goto bail;
	}
	uint8_t jitter = tmp;

	dbus_message_append_args(
		*message,
		DBUS_TYPE_BYTE, &jitter,
		DBUS_TYPE_INVALID
	);

bail:
	return ret;
}

static int handle_register(int argc, char* argv[], DBusMessage **message)
{
	int ret = 0;

	if (argc != CMD_REGISTER_PARAMS)
	{
		fprintf(
			stderr,
			"bbr register: error: invalid number of input parameters, got \"%u\", expected \"%u\"\n",
			argc, CMD_REGISTER_PARAMS
		);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_PROP_SET);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	const char *prop_str;
	prop_str = kWPANTUNDProperty_ThreadBackboneRouterLocalRegister;

	dbus_message_append_args(
		*message,
		DBUS_TYPE_STRING, &prop_str,
		DBUS_TYPE_INVALID
	);

	uint8_t value = 1; // The value does not matter.
	dbus_message_append_args(
		*message,
		DBUS_TYPE_BYTE, &value,
		DBUS_TYPE_INVALID
	);

bail:
	return ret;
}


static const struct bbr_command_t
{
	const char *command;
	command_handler_t handler;
	const char *description;
	const char *usage;
} bbr_commands[] =
{
	{
		.command = "config",
		.handler = handle_config,
		.description = "Set Backbone Router configuration",
		.usage = " bbr config <seqno> <delay> <timeout>\n"
				 "   <seqno>    Sequence number\n"
				 "   <delay>    Reregistration delay\n"
				 "   <timeout>  Multicast Listener Registration Timeout\n\n"
	},
	{
		.command = "enable",
		.handler = handle_enable,
		.description = "Enable Backbone Router functionality",
		.usage = "   bbr enable\n\n"
	},
	{
		.command = "disable",
		.handler = handle_disable,
		.description = "Set Backbone Router state to disabled",
		.usage = "bbr disable\n\n"
	},
	{
		.command = "jitter",
		.handler = handle_jitter,
		.description = "Set Backbone Router registration jitter",
		.usage = "bbr jitter <value>\n\n"
	},
	{
		.command = "register",
		.handler = handle_register,
		.description = "Register local Backbone Router configuration",
		.usage = "bbr register\n\n"
	},
	{
		NULL
	}
};

static void print_help(int argc, char *argv[])
{
	const struct bbr_command_t *entry = bbr_commands;
	static const char *help_usage = "bbr help <command>";

	if (argc == 0) {
		printf("Commands:\n");
		fprintf(stdout, "   %-24s  %s", "help", "Display this help\n");

		while (entry->command) {
			fprintf(stdout, "   %-24s  %s\n", entry->command, entry->description);
			entry++;
		}

		fprintf(stdout, "\nPrint command usage:\n   %s\n", help_usage);
	} else {
		for (entry = bbr_commands; entry->command != NULL; entry++) {
			if(strncmp(entry->command, argv[0], MAX_COMMAND_LEN) == 0) {
				break;
			}
		}

		if (strncmp("help", argv[0], MAX_COMMAND_LEN) == 0) {
			fprintf(stdout, "%s\n", help_usage);
		} else if (entry->command == NULL) {
			fprintf(stderr, "linkmetrics: error: The command \"%s\" is not recognised.\n", argv[0]);
		} else {
			fprintf(stdout, "%s\n", entry->usage);
		}
	}
}

int tool_cmd_bbr(int argc, char* argv[])
{
    int ret = 0;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	const struct bbr_command_t *entry = NULL;

	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;

	dbus_error_init(&error);

	if (argc < 2) {
		fprintf(stderr, "bbr: error: Missing command.\n");
		ret = ERRORCODE_NOCOMMAND;
		goto bail;
	}

	if (strncmp("--help", argv[1], MAX_COMMAND_LEN) == 0 ||
		strncmp("help", argv[1], MAX_COMMAND_LEN) == 0 ||
		strncmp("-h", argv[1], MAX_COMMAND_LEN) == 0
	) {
		print_help(argc - 2, &argv[2]);
		ret = ERRORCODE_OK;
		goto bail;
	}

	for (entry = bbr_commands; entry->command != NULL; entry++) {
		if(strncmp(entry->command, argv[1], MAX_COMMAND_LEN) == 0) {
			break;
		}
	}

	if (entry->command == NULL || entry->handler == NULL) {
		fprintf(stderr, "bbr: error: The command \"%s\" is not recognised.\n", argv[1]);
		ret = ERRORCODE_BADCOMMAND;
		goto bail;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	require_string(connection != NULL, bail, error.message);

	ret = entry->handler(argc - 2, &argv[2], &message);

	require(ret == ERRORCODE_OK, bail);
	reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, &error);

	if (!reply) {
		ret = ERRORCODE_TIMEOUT;
		goto bail;
	}

	dbus_message_get_args(reply, &error,
		DBUS_TYPE_INT32, &ret,
		DBUS_TYPE_INVALID
	);

	if (ret) {
		fprintf(stderr, "%s failed with error %d. %s\n", argv[0], ret, wpantund_status_to_cstr(ret));
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