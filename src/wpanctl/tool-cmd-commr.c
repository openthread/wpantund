/*
 *
 * Copyright (c) 2018 Nest Labs, Inc.
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
#include <inttypes.h>
#include "wpanctl-utils.h"
#include "tool-cmd-commr.h"
#include "args.h"
#include "assert-macros.h"
#include "wpan-dbus-v1.h"
#include "string-utils.h"
#include "commissioner-utils.h"

#include <arpa/inet.h>
#include <errno.h>

enum {
	COMMR_CMD_HELP,
	COMMR_CMD_START,
	COMMR_CMD_STOP,
	COMMR_CMD_JOINER_ADD,
	COMMR_CMD_JOINER_ADD_WITH_DISCERNER,
	COMMR_CMD_JOINER_REMOVE,
	COMMR_CMD_JOINER_REMOVE_WITH_DISCERNER,
	COMMR_CMD_ANNOUNCE_BEGIN,
	COMMR_CMD_ENERGY_SCAN,
	COMMR_CMD_PAN_ID_QUERY,
	COMMR_CMD_MGMT_GET,
	COMMR_CMD_MGMT_SET,
	COMMR_CMD_GENERATE_PSKC,
};

static const struct commr_command_entry_t
{
	int id;
	const char *name;
	const char *alias;
	int min_args;
	int max_args;
	const char *arg_format;
	const char *help_str;
} commr_commands [] =
{
	{
		COMMR_CMD_HELP,
		"help", NULL,
		0, 0, "",
		"Print help."
	},
	{
		COMMR_CMD_START,
		"start", "enable",
		0, 0, "",
		"Start Commissioner"
	},
	{
		COMMR_CMD_STOP,
		"stop", "disable",
		 0, 0, "",
		 "Stop Commissioner"
	},
	{
		COMMR_CMD_JOINER_ADD,
		"joiner-add", "add",
		3, 3, " <eui64> <timeout> <psk>",
		"Add joiner, use * as <eui64> for any, <timeout> in sec"
	},
	{
		COMMR_CMD_JOINER_ADD_WITH_DISCERNER,
		"joiner-add-discerner", "add-discerner",
		4, 4, " <value> <bit-len> <timeout> <psk>",
		"Add joiner with a given discerner value/bit-len, <timeout> in sec"
	},
	{
		COMMR_CMD_JOINER_REMOVE,
		"joiner-remove", "remove",
		1, 2, " <eui64> [<timeout>=0]",
		"Remove joiner, use * as <eui64> for any, <timeout> in sec"
	},
	{
		COMMR_CMD_JOINER_REMOVE_WITH_DISCERNER,
		"joiner-remove-discerner", "remove-discerner",
		2, 3, " <value> <bit-len> [<timeout>=0]",
		"Remove joiner with a given discerner value/bit-len, <timeout> in sec"
	},
	{
		COMMR_CMD_ANNOUNCE_BEGIN,
		"announce-begin", "announce",
		4, 4, " <chan_mask> <count> <period> <dest-ip>",
		"Send Announce Begin message, <period> in millisec"
	},
	{
		COMMR_CMD_ENERGY_SCAN,
		"energy-scan", "scan",
		5, 5, " <chan_mask> <count> <period> <dur> <dest-ip>",
		"Send Energy Scan Query message, <period>/<dur> in millisec"
	},
	{
		COMMR_CMD_PAN_ID_QUERY,
		"pan-id-query", "panid",
		3, 3, " <pan-id> <chan_mask> <dest-ip>",
		"Send PAN ID Query message"
	},
	{
		COMMR_CMD_MGMT_GET,
		"mgmt-get", NULL,
		0, 1, " [<tlvs>]",
		"Send MGMT_COMMISSIONER_GET, <tlvs> as hex byte array"
	},
	{
		COMMR_CMD_MGMT_SET, "mgmt-set", NULL,
		1, 1, " <tlvs>",
		"Send MGMT_COMMISSIONER_SET, <tlvs> as hex byte array"
	},
	{
		COMMR_CMD_GENERATE_PSKC, "gen-pskc", "pskc",
		3, 3, " <pass-phrase> <net-name> <xpanid>",
		"Generate PSKc for a given pass-phrase, network name, and XPANID (as hex string)"
	},
	{
		-1
	}
};

static void
print_help(const char *prog_name)
{
	const char commr_cmd_syntax[] = "[args] <command>";

	static const arg_list_item_t commr_option_list[] = {
		{'t', "timeout", "ms", "Set timeout period"},
		{'c', "check-psk", NULL, "Checks validity/format of PSK for joiner add"},
		{0}
	};

	const struct commr_command_entry_t *entry;
	char cmd_and_args[80];

	print_arg_list_help(commr_option_list, prog_name, commr_cmd_syntax);
	printf("Commands:\n");

	for (entry = commr_commands; entry->id >= 0; entry++) {
		snprintf(cmd_and_args, sizeof(cmd_and_args), "%s%s", entry->name, entry->arg_format);
		printf("   %-59s  %s", cmd_and_args, entry->help_str);
		if (entry->alias != NULL) {
			printf(" (alias: `%s`)\n", entry->alias);
		} else {
			printf("\n");
		}
	}
}

int
tool_cmd_commr(int argc, char* argv[])
{
	int ret = 0;
	int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
	bool check_psk_arg = false;

	const char *cmd_str = NULL;
	const struct commr_command_entry_t *cmd_entry = NULL;
	char outcome_str[256];

	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;

	dbus_error_init(&error);
	outcome_str[0] = 0;

	while (true) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"timeout", required_argument, 0, 't'},
			{"check-psk", no_argument, 0, 'c'},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		int c;

		c = getopt_long(argc, argv, "t:c", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 't':
			timeout = strtol(optarg, NULL, 0);
			break;

		case 'c':
			check_psk_arg = true;
			break;
		}
	}

	if (optind < argc) {
		cmd_str = argv[optind];
		optind++;
	} else {
		fprintf(stderr, "%s: error: Missing command.\n", argv[0]);
		print_help(argv[0]);
		goto bail;
	}


	for (cmd_entry = commr_commands; cmd_entry->id >= 0; cmd_entry++) {
		if (!strcmp(cmd_entry->name, cmd_str)
			|| ((cmd_entry->alias != NULL) && !strcmp(cmd_entry->alias, cmd_str))
		) {
			break;
		}
	}

	if (cmd_entry->id < 0) {
		fprintf(stderr, "%s: Unknown command \"%s\".\n", argv[0], cmd_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	// Check the number of arguments

	if ((argc - optind < cmd_entry->min_args) || (argc - optind > cmd_entry->max_args)) {
		fprintf(stderr, "%s %s: error: Too %s arguments, %d given, ", argv[0], cmd_str,
			(argc - optind < cmd_entry->min_args)? "few" : "many", argc - optind);

		if (cmd_entry->min_args == cmd_entry->max_args) {
			fprintf(stderr, "expecting %d\n", cmd_entry->min_args);
		} else {
			fprintf(stderr, "expecting %d-%d\n", cmd_entry->min_args, cmd_entry->max_args);
		}

		printf("Format:\n");
		printf("   %s%s   %s", cmd_entry->name, cmd_entry->arg_format, cmd_entry->help_str);

		if (cmd_entry->alias != NULL) {
			printf(" (alias: `%s`)\n", cmd_entry->alias);
		} else {
			printf("\n");
		}

		ret = ERRORCODE_BADARG;
		goto bail;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	require_string(connection != NULL, bail, error.message);

	switch (cmd_entry->id)
	{
	case COMMR_CMD_HELP:
		print_help(argv[0]);
		ret = ERRORCODE_HELP;
		goto bail;

	case COMMR_CMD_START:
	case COMMR_CMD_STOP:
	{
		const char *str;

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_PROP_SET);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		str = kWPANTUNDProperty_CommissionerState;

		dbus_message_append_args(message,
			DBUS_TYPE_STRING, &str,
			DBUS_TYPE_INVALID
		);

		str = (cmd_entry->id == COMMR_CMD_START)
			? kWPANTUNDCommissionerState_Active
			: kWPANTUNDCommissionerState_Disabled;

		dbus_message_append_args(
			message,
			DBUS_TYPE_STRING, &str,
			DBUS_TYPE_INVALID
		);

		snprintf(outcome_str, sizeof(outcome_str),
			"Commissioner %s",
			(cmd_entry->id == COMMR_CMD_START) ? "started" : "stopped"
		);

		break;
	}

	case COMMR_CMD_JOINER_ADD:
	{
		uint8_t eui64[COMMR_EUI64_SIZE];
		bool any_eui64 = false;
		uint32_t joiner_timeout;
		const char *psk;

		// joiner-add <eui64> <timeout> <psk>

		if (strcmp(argv[optind], "*") == 0) {
			any_eui64 = true;
		} else {
			int len = parse_string_into_data(eui64, sizeof(eui64), argv[optind]);
			if (len != sizeof(eui64)) {
				fprintf(stderr, "%s %s: error: Bad address \"%s\"\n", argv[0], cmd_str, argv[optind]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
		}

		joiner_timeout = (uint32_t)strtol(argv[optind + 1], NULL, 0);
		psk = argv[optind + 2];

		if (check_psk_arg) {
			ret = check_psk_format(psk);
			if (ret != 0) {
				fprintf(stderr, "%s %s: error: Invalid PSKd\n", argv[0], cmd_str);
				goto bail;
			}
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_ADD);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_STRING, &psk,
			DBUS_TYPE_UINT32, &joiner_timeout,
			DBUS_TYPE_INVALID
		);

		if (!any_eui64) {
			uint8_t *eui64_ptr = eui64;
			dbus_message_append_args(
				message,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &eui64_ptr, sizeof(eui64),
				DBUS_TYPE_INVALID
			);
		}

		if (any_eui64) {
			snprintf(outcome_str, sizeof(outcome_str),
				"Added Joiner (*), timeout:%d, PSKd:\"%s\"",
				joiner_timeout, psk
			);
		} else {
			snprintf(outcome_str, sizeof(outcome_str),
				"Added Joiner %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X, timeout:%d, PSKd:\"%s\"",
				eui64[0], eui64[1], eui64[2], eui64[3], eui64[4], eui64[5], eui64[6], eui64[7],
				joiner_timeout, psk
			);
		}

		break;
	}

	case COMMR_CMD_JOINER_ADD_WITH_DISCERNER:
	{
		uint8_t eui64[COMMR_EUI64_SIZE];
		uint8_t *eui64_ptr = eui64;
		uint64_t discerner_value = 0;
		uint8_t discerner_bit_len = 0;
		uint32_t joiner_timeout;
		const char *psk;

		// joiner-add-discerner <discerner value> <discerner bit length> <timeout> <psk>

		memset(&eui64, 0, sizeof(eui64));

		discerner_value = (uint64_t)strtoll(argv[optind], NULL, 0);
		discerner_bit_len = (uint8_t)strtol(argv[optind + 1], NULL, 0);
		joiner_timeout = (uint32_t)strtol(argv[optind + 2], NULL, 0);
		psk = argv[optind + 3];

		if (check_psk_arg) {
			ret = check_psk_format(psk);
			if (ret != 0) {
				fprintf(stderr, "%s %s: error: Invalid PSKd\n", argv[0], cmd_str);
				goto bail;
			}
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_ADD);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_STRING, &psk,
			DBUS_TYPE_UINT32, &joiner_timeout,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &eui64_ptr, sizeof(eui64),
			DBUS_TYPE_BYTE, &discerner_bit_len,
			DBUS_TYPE_UINT64, &discerner_value,
			DBUS_TYPE_INVALID
		);

		snprintf(outcome_str, sizeof(outcome_str),
			"Added Joiner with Discerner %" PRIu64 ", bit-len:%d, timeout:%d, PSKd:\"%s\"",
			discerner_value, discerner_bit_len,joiner_timeout, psk);

		break;
	}

	case COMMR_CMD_JOINER_REMOVE:
	{
		uint8_t eui64[COMMR_EUI64_SIZE];
		bool any_eui64 = false;
		uint32_t joiner_timeout = 0;

		// joiner-remove <eui64> [<timeout>=0]

		if (strcmp(argv[optind], "*") == 0) {
			any_eui64 = true;
		} else {
			int len = parse_string_into_data(eui64, sizeof(eui64), argv[optind]);
			if (len != sizeof(eui64)) {
				fprintf(stderr, "%s %s: error: Bad EUI64 \"%s\"\n", argv[0], cmd_str, argv[optind]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
		}

		if (optind + 1 < argc) {
			joiner_timeout = (uint32_t)strtol(argv[optind + 1], NULL, 0);
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_REMOVE);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT32, &joiner_timeout,
			DBUS_TYPE_INVALID
		);

		if (!any_eui64) {
			uint8_t *eui64_ptr = eui64;
			dbus_message_append_args(
				message,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &eui64_ptr, sizeof(eui64),
				DBUS_TYPE_INVALID
			);
		}

		if (any_eui64) {
			snprintf(outcome_str, sizeof(outcome_str), "Removed Joiner (*), timeout:%d", joiner_timeout);
		} else {
			snprintf(outcome_str, sizeof(outcome_str),
				"Removed Joiner %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X, timeout:%d",
				eui64[0], eui64[1], eui64[2], eui64[3], eui64[4], eui64[5], eui64[6], eui64[7],
				joiner_timeout
			);
		}

		break;
	}

	case COMMR_CMD_JOINER_REMOVE_WITH_DISCERNER:
	{
		uint8_t eui64[COMMR_EUI64_SIZE];
		uint8_t *eui64_ptr = eui64;
		uint64_t discerner_value = 0;
		uint8_t discerner_bit_len = 0;
		uint32_t joiner_timeout = 0;

		// joiner-remove-discerner <discerner value> <discerner bit length> [<timeout>=0]

		memset(&eui64, 0, sizeof(eui64));

		discerner_value = (uint64_t)strtoll(argv[optind], NULL, 0);
		discerner_bit_len = (uint8_t)strtol(argv[optind + 1], NULL, 0);

		if (optind + 2 < argc) {
			joiner_timeout = (uint32_t)strtol(argv[optind + 2], NULL, 0);
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_JOINER_REMOVE);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT32, &joiner_timeout,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &eui64_ptr, sizeof(eui64),
			DBUS_TYPE_BYTE, &discerner_bit_len,
			DBUS_TYPE_UINT64, &discerner_value,
			DBUS_TYPE_INVALID
		);
		snprintf(outcome_str, sizeof(outcome_str),
			"Removed Joiner with Discerner %" PRIu64 " bit-len:%d, timeout:%d",
			discerner_value, discerner_bit_len, joiner_timeout);

		break;
	}

	case COMMR_CMD_ANNOUNCE_BEGIN:
	{
		uint32_t channel_mask;
		uint8_t count;
		uint16_t period;
		uint8_t dest[COMMR_IPv6_ADDRESS_SIZE];
		uint8_t *dest_ptr = dest;
		char address_string[INET6_ADDRSTRLEN] = "::";

		// announce-begin <chan_mask> <count> <period> <dest-ip>

		channel_mask = strtomask_uint32(argv[optind]);

		if (channel_mask == 0) {
			fprintf(stderr, "%s %s: error: Bad channel mask \"%s\"\n", argv[0], cmd_str, argv[optind]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		count = (uint8_t)strtol(argv[optind + 1], NULL, 0);
		period = (uint16_t)strtol(argv[optind + 2], NULL, 0);

		if (inet_pton(AF_INET6, argv[optind + 3] , dest) <= 0) {
			fprintf(stderr, "%s %s: error: Bad dest IPv6 address \"%s\"\n", argv[0], cmd_str, argv[optind + 3]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_ANNOUNCE_BEGIN);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT32, &channel_mask,
			DBUS_TYPE_BYTE, &count,
			DBUS_TYPE_UINT16, &period,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_ptr, sizeof(dest),
			DBUS_TYPE_INVALID
		);

		inet_ntop(AF_INET6, (const void *)&dest, address_string, sizeof(address_string));
		snprintf(outcome_str, sizeof(outcome_str),
			"Successfully sent Announce Begin, channel-mask:0x%x, count:%d, period:%d, dest:\"%s\"",
			channel_mask, count, period, address_string
		);

		break;
	}

	case COMMR_CMD_ENERGY_SCAN:
	{
		uint32_t channel_mask;
		uint8_t count;
		uint16_t period;
		uint16_t duration;
		uint8_t dest[COMMR_IPv6_ADDRESS_SIZE];
		uint8_t *dest_ptr = dest;
		char address_string[INET6_ADDRSTRLEN] = "::";

		// energy-scan <chan_mask> <count> <period> <dur> <dest-ip>

		channel_mask = strtomask_uint32(argv[optind]);

		if (channel_mask == 0) {
			fprintf(stderr, "%s %s: error: Bad channel mask \"%s\"\n", argv[0], cmd_str, argv[optind]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		count = (uint8_t)strtol(argv[optind + 1], NULL, 0);
		period = (uint16_t)strtol(argv[optind + 2], NULL, 0);
		duration = (uint16_t)strtol(argv[optind + 3], NULL, 0);

		if (inet_pton(AF_INET6, argv[optind + 4] , dest) <= 0) {
			fprintf(stderr, "%s %s: error: Bad dest IPv6 address \"%s\"\n", argv[0], cmd_str, argv[optind + 4]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_ENERGY_SCAN_QUERY);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT32, &channel_mask,
			DBUS_TYPE_BYTE, &count,
			DBUS_TYPE_UINT16, &period,
			DBUS_TYPE_UINT16, &duration,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_ptr, sizeof(dest),
			DBUS_TYPE_INVALID
		);

		inet_ntop(AF_INET6, (const void *)&dest, address_string, sizeof(address_string));
		snprintf(outcome_str, sizeof(outcome_str),
			"Successfully sent Energy Scan Query, channel-mask:0x%x, count:%d, period:%d, duration:%d, dest:\"%s\"\n"
			"Use property \"%s\" to get received Energy Scan results",
			channel_mask, count, period, duration, address_string,
			kWPANTUNDProperty_CommissionerEnergyScanResult
		);

		break;
	}

	case COMMR_CMD_PAN_ID_QUERY:
	{
		uint16_t panid;
		uint32_t channel_mask;
		uint8_t dest[COMMR_IPv6_ADDRESS_SIZE];
		uint8_t *dest_ptr = dest;
		char address_string[INET6_ADDRSTRLEN] = "::";

		// pan-id-query <pan-id> <chan_mask> <dest-ip>

		panid = (uint16_t)strtol(argv[optind], NULL, 0);

		channel_mask = strtomask_uint32(argv[optind + 1]);

		if (channel_mask == 0) {
			fprintf(stderr, "%s %s: error: Bad channel mask \"%s\"\n", argv[0], cmd_str, argv[optind + 1]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		if (inet_pton(AF_INET6, argv[optind + 2] , dest) <= 0) {
			fprintf(stderr, "%s %s: error: Bad dest IPv6 address \"%s\"\n", argv[0], cmd_str, argv[optind + 2]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_PAN_ID_QUERY);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_UINT16, &panid,
			DBUS_TYPE_UINT32, &channel_mask,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_ptr, sizeof(dest),
			DBUS_TYPE_INVALID
		);

		inet_ntop(AF_INET6, (const void *)&dest, address_string, sizeof(address_string));
		snprintf(outcome_str, sizeof(outcome_str),
			"Successfully sent PAN ID Query, pan-id:0x%04x, channel-mask:0x%x, dest:\"%s\"\n"
			"Use property \"%s\" to get received PAN ID Conflict results",
			panid, channel_mask, address_string,
			kWPANTUNDProperty_CommissionerPanIdConflictResult
		);

		break;
	}

	case COMMR_CMD_MGMT_GET:
	case COMMR_CMD_MGMT_SET:
	{
		uint8_t tlvs[COMMR_TLVS_MAX_LEN];
		uint8_t *tlvs_ptr = tlvs;
		char tlvs_str[COMMR_TLVS_MAX_LEN + 1];
		const char *prop_name;
		int len = 0;

		if (optind < argc) {
			len = parse_string_into_data(tlvs, sizeof(tlvs), argv[optind]);

			if (len <= 0) {
				fprintf(stderr, "%s %s: error: Bad TLV hex data \"%s\"\n", argv[0], cmd_str, argv[optind]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_PROP_SET);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		prop_name = (cmd_entry->id == COMMR_CMD_MGMT_GET)
			? kWPANTUNDProperty_CommissionerSendMgmtGet
			: kWPANTUNDProperty_CommissionerSendMgmtSet;

		dbus_message_append_args(
			message,
			DBUS_TYPE_STRING, &prop_name,
			DBUS_TYPE_INVALID
		);

		if (len > 0) {
			dbus_message_append_args(
				message,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &tlvs_ptr, len,
				DBUS_TYPE_INVALID
			);
		} else  {
			const char *empty_value = "";
			dbus_message_append_args(
				message,
				DBUS_TYPE_STRING, &empty_value,
				DBUS_TYPE_INVALID
			);
		}

		encode_data_into_string(tlvs, len, tlvs_str, sizeof(tlvs_str), 0);

		snprintf(outcome_str, sizeof(outcome_str),
			"Send MGMT_COMMISSIONER_%s with [%s]",
			(cmd_entry->id == COMMR_CMD_MGMT_GET) ? "GET" : "SET",
			tlvs_str
		);

		break;
	}

	case COMMR_CMD_GENERATE_PSKC:
	{
		// gen-pskc <pass-phrase> <network-name> <xpanid as hex string>

		const char *pass_phrase = argv[optind];
		const char *network_name = argv[optind + 1];
		uint8_t xpanid[COMMR_XPANID_SIZE];
		uint8_t *xpanid_ptr = xpanid;
		int len = 0;

		len = parse_string_into_data(xpanid, sizeof(xpanid), argv[optind + 2]);

		if (len != COMMR_XPANID_SIZE) {
			fprintf(stderr, "%s %s: error: Bad XPANId \"%s\" - should be %d bytes as hex string.\n",
				argv[0], cmd_str, argv[optind + 2], COMMR_XPANID_SIZE);
			ret = ERRORCODE_BADARG;
			goto bail;
		}

		ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_GENERATE_PSKC);
		require_action(ret == 0, bail, print_error_diagnosis(ret));

		dbus_message_append_args(
			message,
			DBUS_TYPE_STRING, &pass_phrase,
			DBUS_TYPE_STRING, &network_name,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &xpanid_ptr, sizeof(xpanid),
			DBUS_TYPE_INVALID
		);

		fprintf(
			stdout,
			"Generating PSKc from pass-phrase:\"%s\", network-name:\"%s\", XPANId:[%02X%02X%02X%02X%02X%02X%02X%02X]\n",
			pass_phrase, network_name,
			xpanid[0], xpanid[1], xpanid[2], xpanid[3], xpanid[4], xpanid[5], xpanid[6], xpanid[7]
		);

		break;
	}

	default:
		fprintf(stderr, "%s: Unknown command \"%s\".\n", argv[0], cmd_str);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	reply = dbus_connection_send_with_reply_and_block(connection, message, timeout, &error);

	if (!reply) {
		fprintf(stderr, "%s %s: error: %s\n", argv[0], cmd_str, error.message);
		ret = ERRORCODE_TIMEOUT;
		goto bail;
	}

	dbus_message_get_args(reply, &error,
		DBUS_TYPE_INT32, &ret,
		DBUS_TYPE_INVALID
	);

	if (ret != 0) {
		fprintf(stderr, "%s %s failed with error %d. %s\n", argv[0], cmd_str, ret, wpantund_status_to_cstr(ret));
		goto bail;
	}

	if (cmd_entry->id == COMMR_CMD_GENERATE_PSKC) {
		DBusMessageIter iter;

		dbus_message_iter_init(reply, &iter);
		dbus_message_iter_next(&iter); // skip over ret val which is already checked.

		fprintf(stdout, "Generated PSKc is ");
		dump_info_from_iter(stdout, &iter, 0, false, false);

	} else {
		printf("%s\n", outcome_str);
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
