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

#include <arpa/inet.h>

#include "assert-macros.h"
#include "tool-cmd-mlr.h"
#include "wpan-dbus-v1.h"
#include "wpanctl-utils.h"


#define MLR_REG_MAXADDR		15

static void print_help(void)
{
	printf("Multicast Listener Registration\n");
	printf("Usage:\n");
	printf("mlr-reg <addr> [addr ...] [mlrtimeout]\n");
	printf("<addr>       Multicast Listener Address\n");
	printf("mlrtimeout   Optional MLR timeout.\n");
	printf("             When 0 listeners will be removed from primary BBR\n");
	printf("             When non-zero is MLR timeout in seconds, listeners\n");
	printf("             will be added to primary BBR or their timeout updated\n");
	printf("             When omitted default MLR timeout of the BBR will be used.\n");
}

int tool_cmd_mlr_reg(int argc, char* argv[])
{
	if (argc < 2)
	{
		fprintf(stderr, "mlr-reg: error: Missing parameters.\n");
		return ERRORCODE_BADARG;
	}

	if ((strcmp("help", argv[1]) == 0) ||
		(strcmp("--help", argv[1]) == 0) ||
		(strcmp("-h", argv[1]) == 0))
	{
		print_help();
		return ERRORCODE_HELP;
	}

	int ret = ERRORCODE_OK;
	DBusConnection* connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;

	dbus_error_init(&error);

	int argidx = 1;
	size_t addr_count = 0U;
	struct in6_addr addr[MLR_REG_MAXADDR];
	dbus_bool_t mlr_timeout_present = FALSE;
	uint32_t mlr_timeout;
	uint32_t timeout = 1000;

	// Parse addr from input argv
	do {
		struct in6_addr tmp_addr;

		if (!inet_pton(AF_INET6, argv[argidx], &tmp_addr)) {
			if (addr_count == 0U) {
				fprintf(stderr, "mlr-reg: error: Bad address %s\n", argv[argidx]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
			else {
				// List of input addresses is finished, end of loop
				break;
			}
		}
		argidx++;

		if (addr_count >= MLR_REG_MAXADDR) {
			fprintf(stderr, "mlr-reg: error: Too many addresses\n");
			ret = ERRORCODE_BADARG;
			goto bail;
		}
		addr[addr_count++] = tmp_addr;

	} while (argidx < argc);

	if (argidx < argc) {
		// Parse optional mlr_timeout
		errno = 0;
		char * ptr;
		unsigned long tmp_v;

		tmp_v = strtoul(argv[argidx], &ptr, 10);

		if ((errno != 0) || (ptr == argv[argidx]) || (*ptr != '\0') || (tmp_v > UINT32_MAX)) {
			fprintf(stderr, "mlr-reg: error: Bad timeout value %s\n", argv[argidx]);
			ret = ERRORCODE_BADARG;
			goto bail;
		}
		mlr_timeout = tmp_v;
		mlr_timeout_present = TRUE;
		argidx++;
	}

	// There should be no more parameters
	if (argidx < argc) {
		fprintf(stderr, "mlr-reg: error: Unexpected argument %s\n", argv[argidx]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	require_string(connection != NULL, bail, error.message);

	ret = create_new_wpan_dbus_message(&message, WPANTUND_IF_CMD_MLR_REQUEST);
	require_action(ret == 0, bail, print_error_diagnosis(ret));

	DBusMessageIter iter;
	dbus_message_iter_init_append(message, &iter);

	{
		// Open a container as "Array of Array of Byte"
		DBusMessageIter sub_iter = DBUS_MESSAGE_ITER_INIT_CLOSED;
		dbus_message_iter_open_container(
			&iter,
			DBUS_TYPE_ARRAY,
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			&sub_iter
		);

		for (size_t i = 0U; i < addr_count; ++i) {
			void * data = addr[i].s6_addr;
			size_t data_len = sizeof(addr[i].s6_addr);
			DBusMessageIter sub_sub_iter;
			dbus_message_iter_open_container(
				&sub_iter,
				DBUS_TYPE_ARRAY,
				DBUS_TYPE_BYTE_AS_STRING,
				&sub_sub_iter
			);
			dbus_message_iter_append_fixed_array(&sub_sub_iter, DBUS_TYPE_BYTE, &data, data_len);
			dbus_message_iter_close_container(&sub_iter, &sub_sub_iter);
		}

		dbus_message_iter_close_container(&iter, &sub_iter);
	}

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &mlr_timeout_present);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &mlr_timeout);

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
