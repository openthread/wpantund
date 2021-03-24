/*
 *  Copyright (c) 2020, The OpenThread Authors.
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

#include <arpa/inet.h>
#include <netinet/in.h>

#include "assert-macros.h"
#include "tool-cmd-linkmetrics.h"
#include "wpan-dbus-v1.h"
#include "wpanctl-utils.h"


#define MAX_COMMAND_LEN         6
#define MAX_METRICS_LEN         4
#define MAX_FRAME_TYPES_LEN     4
#define CMD_QUERY_PARAMS        3
#define CMD_PROBE_PARAMS        3
#define CMD_MGMT_PARAMS_MIN     3
#define CMD_MGMT_FORWARD_PARAMS_MIN 4
#define CMD_MGMT_FORWARD_PARAMS_FULL 5
#define CMD_MGMT_ENH_ACK_PARAMS 4
#define OUTPUT_MSG_SIZE			512

static const char metric_aliases[] = { 'p', /* PDU count (0)*/
							           'q', /* LQI (1) */
							           'm', /* Link margin (2) */
							           'r'  /* RSSI (3) */ };

static const char frame_type_aliases[] = { 'l', /* MLE Link Probe (0) */
									       'd', /* MAC Data (1) */
									       'r', /* MAC Data Request (2) */
									       'a'  /* MAC ACK (3) */ };

static char output_str[OUTPUT_MSG_SIZE];
static size_t output_str_len = 0;

typedef int (*command_handler_t)(int argc, char* argv[], DBusMessage **message);

struct linkmetrics_command_t
{
	const char *command;
	command_handler_t handler;
	const char *description;
	const char *usage;
};

static void output_message_append(const char *format, ...)
{
	va_list args;
    va_start(args, format);

	output_str_len += vsnprintf(&output_str[output_str_len], OUTPUT_MSG_SIZE - output_str_len, format, args);

	va_end(args);
}

static bool str_to_ids(const char *ids, size_t max, const char* str, char exclude, uint8_t *out)
{
	uint8_t id;
	bool result = true;
	bool found = false;

	while (*str != '\0')
	{
		found = false;

		for (id = 0; id < max; id++) {
			if (*str == ids[id] && *str != exclude)
			{
				found = true;
				*out |= (1 << id);
				break;
			}
		}

		if (!found) {
			result = false;
			break;
		}
		str++;
	}

	return result;
}

// Map link metric aliases ('p', 'q', 'm', 'r') to the corresponding numeric values
static bool metrics_from_cstr(const char* str, char excluded, uint8_t *metrics)
{
	return str_to_ids(metric_aliases, MAX_METRICS_LEN, str, excluded, metrics);
}

// Map link metric frame types ('l', 'd', 'r', 'a') to the corresponding numeric values
static bool frame_types_from_cstr(const char* str, uint8_t *types)
{
	return str_to_ids(frame_type_aliases, MAX_FRAME_TYPES_LEN, str, '\0', types);
}

static int handle_query(int argc, char* argv[], DBusMessage **message)
{
	int ret = 0;
	long num = 0;
	uint8_t series = 0;
	uint8_t metrics;
	const char *dest_str = argv[0];
	const char *subcommand_str = argv[1];
	const char *subcommand_arg_str = argv[2];
	struct in6_addr dest;
	const uint8_t *dest_ptr = (uint8_t *)&dest;
	char *end_ptr;

	const char cmd_single[] = "single";
	const char cmd_forward[] = "forward";

	if (argc != CMD_QUERY_PARAMS) {
		fprintf(
			stderr,
			"linkmetrics query: error: Wrong number of arguments: \"%u\", required: \"%u\"\n",
			argc, CMD_QUERY_PARAMS
		);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	// Parse destination address
	if (!inet_pton(AF_INET6, dest_str, &dest)) {
		fprintf(stderr, "linkmetrics query: error: Bad dest IPv6 address \"%s\"\n", dest_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	// Process subcommand
	if (strncmp(subcommand_str, cmd_single, sizeof(cmd_single)) == 0) {
		if (strnlen(subcommand_arg_str, MAX_METRICS_LEN + 1) > MAX_METRICS_LEN ||
			!metrics_from_cstr(subcommand_arg_str, '\0', &metrics)
		) {
			fprintf(stderr, "linkmetrics query: error: Wrong metrics string \"%s\"\n", subcommand_arg_str);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

	} else if (strncmp(subcommand_str, cmd_forward, sizeof(cmd_forward)) == 0) {
		errno = 0;
		num = strtoul(subcommand_arg_str, &end_ptr, 10);

		if (errno != 0 || num > UINT8_MAX)
		{
			fprintf(stderr, "linkmetrics query: error: Wrong series id: \"%s\"\n", subcommand_arg_str);
			ret = ERRORCODE_BADARG;
			goto bail;
		} else if (num == 0) {
			fprintf(
				stderr,
				"linkmetrics query: error: Series must not be zero, provided: \"%s\"\n",
				subcommand_arg_str
			);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		series = (uint8_t)num;
	} else {
		fprintf(stderr, "linkmetrics query: error: Unknown command \"%s\"\n", subcommand_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_LINK_METRICS_QUERY);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	dbus_message_append_args(
		*message,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_ptr, sizeof(dest),
		DBUS_TYPE_BYTE, &series,
		DBUS_TYPE_BYTE, &metrics,
		DBUS_TYPE_INVALID
	);

	output_message_append("Successfully sent Link Metrics Query message (%s) (dest: %s).\n"
						"In order to check the response fetch the %s property.\n", subcommand_str, dest_str,
						kWPANTUNDCommissionerLinkMetricsQueryResult);

bail:
   return ret;
}

static int handle_probe(int argc, char* argv[], DBusMessage **message)
{
	int ret = 0;
	long num = 0;
	uint8_t series = 0;
	uint8_t length = 0;
	char *end_ptr;
	struct in6_addr dest;
	const uint8_t *dest_ptr = (uint8_t *)&dest;
	const char *dest_str = argv[0];
	const char *series_str = argv[1];
	const char *length_str = argv[2];

	if (argc != CMD_PROBE_PARAMS) {
		fprintf(stderr, "linkmetrics probe: error: Wrong number of arguments: \"%u\", required: \"%u\"\n", argc, CMD_PROBE_PARAMS);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	// Parse destination address
	if (!inet_pton(AF_INET6, dest_str, &dest)) {
		fprintf(stderr, "linkmetrics probe: error: Bad dest IPv6 address \"%s\"\n", dest_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	// Parse series id
	errno = 0;
	num = strtoul(series_str, &end_ptr, 10);

	if (errno != 0 || num > UINT8_MAX) {
		fprintf(stderr, "linkmetrics probe: error: Wrong series id: \"%s\"\n", series_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	series = (uint8_t)num;

	// Parse length
	errno = 0;
	num = strtoul(length_str, &end_ptr, 10);

	if (errno != 0 || num > UINT8_MAX) {
		fprintf(stderr, "linkmetrics probe: error: Wrong length: \"%s\"\n", series_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	length = (uint8_t)num;

	ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_LINK_METRICS_PROBE);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	dbus_message_append_args(
		*message,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_ptr, sizeof(dest),
		DBUS_TYPE_BYTE, &series,
		DBUS_TYPE_BYTE, &length,
		DBUS_TYPE_INVALID
	);

	output_message_append("Successfully sent Link Metrics Probe message (dest: %s).\n.", dest_str);

bail:
	return ret;
}

static int handle_mgmt(int argc, char* argv[], DBusMessage **message)
{
	int ret = 0;
	unsigned long num = 0;
	uint8_t series = 0;
	char *end_ptr;
	struct in6_addr dest;
	uint8_t enh_ack_flags;
	uint8_t metrics = 0;
	uint8_t frame_types = 0;

	// Due to D-Bus requirements we have to provide additional pointer
	const uint8_t *dest_ptr = (uint8_t *)&dest;

	const char *dest_str = argv[0];
	const char *subcommand_str = argv[1];
	char **subcommand_args = &argv[2];

	const char cmd_enh_ack[] = "enhanced-ack";
	const char cmd_clear[] = "clear";
	const char cmd_register[] = "register";
	const char cmd_forward[] = "forward";

	if (argc < CMD_MGMT_PARAMS_MIN) {
		fprintf(
			stderr,
			"linkmetrics mgmt: error: Wrong number of arguments: \"%u\", minimum required: \"%u\"\n",
			 argc, CMD_MGMT_PARAMS_MIN
		);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	// Parse destination address
	if (!inet_pton(AF_INET6, dest_str, &dest)) {
		fprintf(stderr, "linkmetrics mgmt: error: Bad dest IPv6 address \"%s\"\n", dest_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (strncmp(subcommand_str, cmd_enh_ack, sizeof(cmd_enh_ack)) == 0) {
		if (strncmp(subcommand_args[0], cmd_clear, sizeof(cmd_clear)) == 0) {
			enh_ack_flags = 0;
		} else if (strncmp(subcommand_args[0], cmd_register, sizeof(cmd_register)) == 0) {
			enh_ack_flags = 1;

			if (argc != CMD_MGMT_ENH_ACK_PARAMS) {
				fprintf(
					stderr,
					"linkmetrics mgmt enhanced-ack: error: Wrong number of arguments: \"%u\", required: \"%u\"\n",
					argc - 3, CMD_MGMT_ENH_ACK_PARAMS - 3
				);
				ret = ERRORCODE_BADARG;
				goto bail;
			}

			if (strnlen(subcommand_args[1], MAX_METRICS_LEN + 1) > MAX_METRICS_LEN ||
				!metrics_from_cstr(subcommand_args[1], 'p', &metrics)
			) {
				fprintf(stderr, "linkmetrics mgmt: error: Wrong metrics string \"%s\"\n", subcommand_args[1]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
		} else {
			fprintf(stderr, "linkmetrics mgmt: error: Unknown subcommand \"%s\"\n", subcommand_args[0]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_LINK_METRICS_MGMT_ENH_ACK);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			*message,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_ptr, sizeof(dest),
			DBUS_TYPE_BYTE, &enh_ack_flags,
			DBUS_TYPE_BYTE, &metrics,
			DBUS_TYPE_INVALID
		);

		output_message_append("Successfully sent Link Metrics Enh-ACK %s message (dest: %s).\n"
						"In order to check the response fetch the %s property.\n", enh_ack_flags ? "Register" : "Clear",
						dest_str, kWPANTUNDCommissionerLinkMetricsMgmtResponse);
		if (enh_ack_flags) {
			output_message_append("\nLast received Enhanced ACK IE probe can be read with the %s property\n",
								kWPANTUNDCommissionerLinkMetricsLastEnhAckIe);
		}
	} else if (strncmp(subcommand_str, cmd_forward, sizeof(cmd_forward)) == 0) {
		if (argc < CMD_MGMT_FORWARD_PARAMS_MIN) {
			fprintf(
				stderr,
				"linkmetrics mgmt forward: error: Wrong number of arguments: \"%u\", minimum required: \"%u\"\n",
				argc - 2, CMD_MGMT_PARAMS_MIN - 2
			);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		errno = 0;
		num = strtoul(subcommand_args[0], &end_ptr, 10);

		if (errno != 0 || num > UINT8_MAX) {
			fprintf(stderr, "linkmetrics mgmt: error: Wrong series id: \"%s\"\n", subcommand_args[0]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		series = (uint8_t)num;

		if (strnlen(subcommand_args[1], MAX_FRAME_TYPES_LEN + 1) == 1 && subcommand_args[1][0] == 'X') {
			frame_types = 0;
		} else if (strnlen(subcommand_args[1], MAX_FRAME_TYPES_LEN + 1) > MAX_FRAME_TYPES_LEN ||
			!frame_types_from_cstr(subcommand_args[1], &frame_types)
		) {
			fprintf(stderr, "linkmetrics mgmt: error: Wrong frame types string \"%s\"\n", subcommand_args[1]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		if (argc == CMD_MGMT_FORWARD_PARAMS_FULL)
		{
			if (strnlen(subcommand_args[2], MAX_METRICS_LEN + 1) > MAX_METRICS_LEN ||
				!metrics_from_cstr(subcommand_args[2], '\0', &metrics)
			) {
				fprintf(stderr, "linkmetrics mgmt: error: Wrong metrics string \"%s\"\n", subcommand_args[2]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
		}

		ret = create_new_wpan_dbus_message(message, WPANTUND_IF_CMD_LINK_METRICS_MGMT_FORWARD);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			*message,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_ptr, sizeof(dest),
			DBUS_TYPE_BYTE, &series,
			DBUS_TYPE_BYTE, &frame_types,
			DBUS_TYPE_BYTE, &metrics,
			DBUS_TYPE_INVALID
		);

		output_message_append("Successfully sent Link Metrics Mgmt Forward message (dest: %s).\n"
						"In order to check the response fetch the %s property.\n", dest_str,
						kWPANTUNDCommissionerLinkMetricsMgmtResponse);
	} else {
		fprintf(stderr, "linkmetrics mgmt: error: Unknown command \"%s\"\n", subcommand_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

bail:
	return ret;
}

static const struct linkmetrics_command_t commands[] =
{
	{
		.command = "query",
		.handler = handle_query,
		.description = "Send link metrics query to a neighbor",
		.usage = "Single Probe: \n"
				 "   linkmetrics query <destination> single [pqmr]\n\n"
				 "   <destination>   IPv6 link local address\n"
				 "   [pqmr]          List of requested metrics:\n"
				 "                      p: PDU count\n"
				 "                      q: LQI\n"
				 "                      m: Link margin\n"
				 "                      r: PDU count\n\n"
				 "Forward Tracking Series: \n"
				 "   linkmetrics query <destination> forward <seriesId>\n\n"
				 "   <destination>   IPv6 link local address\n"
				 "   <seriesId>      The series ID\n"
	},
	{
		.command = "probe",
		.handler = handle_probe,
		.description = "Send a MLE Link Probe message to the peer",
		.usage = "   linkmetrics probe <destination> <seriesId> <length>\n\n"
				 "   <destination>    IPv6 link local address\n"
				 "   <seriesId>       The series ID for which this Probe message targets at\n"
				 "   <length>         The length of the Probe message, valid range: [0, 64]\n"

	},
	{
		.command = "mgmt",
		.handler = handle_mgmt,
		.description = "Manage Forward Tracking Series and Enhanced ACK probing",
		.usage = "Forward Tracking Series: \n"
				 "   linkmetrics mgmt <destination> forward <seriesId> [ldraX] [pqmr]\n\n"
				 "   <destination>   IPv6 link local address\n"
				 "   <seriesId>      The series ID\n"
				 "   [ldraX]         List of frame types:\n"
				 "                      l: MLE Link Probe\n"
				 "                      d: MAC Data\n"
				 "                      r: MAC Data Request\n"
				 "                      a: MAC Data Request\n"
				 "                      X: Remove the series (used without any other flags)\n"
				 "   [pqmr]          List of requested metrics:\n"
				 "                      p: PDU count\n"
				 "                      q: LQI\n"
				 "                      m: Link margin\n"
				 "                      r: PDU count\n\n"
				 "Enhanced ACK probing:\n"
				 "   linkmetrics mgmt <destination> enhanced-ack clear\n"
				 "   linkmetrics mgmt <destination> enhanced-ack register [qmr]\n\n"
				 "   <desination>    IPv6 link local address\n"
				 "   [qmr]          List of requested metrics:\n"
				 "                      q: LQI\n"
				 "                      m: Link margin\n"
				 "                      r: PDU count\n\n"
	},
	{
		NULL
	}
};

static void print_help(int argc, char *argv[])
{
	const struct linkmetrics_command_t *entry = commands;
	static const char *help_usage = "linkmetrics help <command>";

	if (argc == 0) {
		printf("Commands:\n");
		fprintf(stdout, "   %-24s  %s", "help", "Display this help\n");

		while (entry->command) {
			fprintf(stdout, "   %-24s  %s\n", entry->command, entry->description);
			entry++;
		}

		fprintf(stdout, "\nPrint command usage:\n   %s\n", help_usage);
	} else {
		for (entry = commands; entry->command != NULL; entry++) {
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

int tool_cmd_linkmetrics(int argc, char* argv[])
{
	int ret = 0;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	const struct linkmetrics_command_t *entry = NULL;

	memset(output_str, 0, OUTPUT_MSG_SIZE);
	output_str_len = 0;

	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;

	dbus_error_init(&error);

	if (argc < 2) {
		fprintf(stderr, "linkmetrics: error: Missing command.\n");
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

	for (entry = commands; entry->command != NULL; entry++) {
		if(strncmp(entry->command, argv[1], MAX_COMMAND_LEN) == 0) {
			break;
		}
	}

	if (entry->command == NULL || entry->handler == NULL) {
		fprintf(stderr, "linkmetrics: error: The command \"%s\" is not recognised.\n", argv[1]);
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

bail:
	if (ret != 0) {
		print_error_diagnosis(ret);
	} else {
		if (output_str_len) {
			fprintf(stdout, "linkmetrics %s: %s", argv[1], output_str);
		}
	}

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
