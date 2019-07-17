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

#include "assert-macros.h"
#include <syslog.h>
#include <errno.h>
#include "SpinelNCPTaskPeek.h"
#include "SpinelNCPInstance.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

nl::wpantund::SpinelNCPTaskPeek::SpinelNCPTaskPeek(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	uint32_t address,
	uint16_t count
):	SpinelNCPTask(instance, cb), mAddress(address), mCount(count)
{
}

int
nl::wpantund::SpinelNCPTaskPeek::vprocess_event(int event, va_list args)
{
	int ret = kWPANTUNDStatus_Failure;

	EH_BEGIN();

	if (!mInstance->mEnabled) {
		ret = kWPANTUNDStatus_InvalidWhenDisabled;
		finish(ret);
		EH_EXIT();
	}

	if (mInstance->get_ncp_state() == UPGRADING) {
		ret = kWPANTUNDStatus_InvalidForCurrentState;
		finish(ret);
		EH_EXIT();
	}

	// Wait for a bit to see if the NCP will enter the right state.
	EH_REQUIRE_WITHIN(
		NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
		!ncp_state_is_initializing(mInstance->get_ncp_state()) && !mInstance->is_initializing_ncp(),
		on_error
	);

	// The first event to a task is EVENT_STARTING_TASK. The following
	// line makes sure that we don't start processing this task
	// until it is properly scheduled. All tasks immediately receive
	// the initial `EVENT_STARTING_TASK` event, but further events
	// will only be received by that task once it is that task's turn
	// to execute.
	EH_WAIT_UNTIL(EVENT_STARTING_TASK != event);

	mNextCommand = SpinelPackData(
	    SPINEL_FRAME_PACK_CMD(
	        SPINEL_DATATYPE_UINT32_S   // Address
	        SPINEL_DATATYPE_UINT16_S   // Count
	    ),
	    SPINEL_CMD_PEEK,
	    mAddress,
	    mCount
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	ret = mNextCommandRet;

	require_noerr(ret, on_error);

	if (event == EVENT_NCP(SPINEL_CMD_PEEK_RET))
	{
		spinel_prop_key_t prop_key = va_arg_small(args, spinel_prop_key_t);
		const uint8_t *frame_ptr = va_arg(args, const uint8_t*);
		spinel_size_t frame_len = va_arg_small(args, spinel_size_t);
		const uint8_t *data_ptr = NULL;
		spinel_size_t data_len = 0;
		spinel_ssize_t parsed_len;
		uint32_t address;
		uint16_t count;

		parsed_len = spinel_datatype_unpack(frame_ptr, frame_len, "CiLSD", NULL, NULL, &address, &count, &data_ptr, &data_len);

		require(parsed_len > 0, on_error);
		require(address == mAddress, on_error);
		require(data_len == mCount, on_error);

		ret = kWPANTUNDStatus_Ok;

		finish(ret, Data(data_ptr, data_len));

		EH_EXIT();
	}

on_error:

	if (ret == kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "Peek failed: %d", ret);

	finish(ret);

	EH_END();
}

