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

#include "assert-macros.h"
#include <syslog.h>
#include <errno.h>
#include "SpinelNCPTaskHostDidWake.h"
#include "SpinelNCPInstance.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

nl::wpantund::SpinelNCPTaskHostDidWake::SpinelNCPTaskHostDidWake(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	bool should_tickle
):	SpinelNCPTask(instance, cb), mShouldTickle(should_tickle)
{
}

int
nl::wpantund::SpinelNCPTaskHostDidWake::vprocess_event(int event, va_list args)
{
	int ret = kWPANTUNDStatus_Ok;

	EH_BEGIN();

	if (!mInstance->mEnabled) {
		finish(ret);
		EH_EXIT();
	}

	if (mInstance->get_ncp_state() == UPGRADING) {
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

	if (mShouldTickle) {
		mNextCommand = SpinelPackData(SPINEL_FRAME_PACK_CMD_NOOP);
		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
		ret = mNextCommandRet;
		require_noerr(ret, on_error);
	}

	finish(ret);

	EH_EXIT();

on_error:

	if (ret != kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "HostDidWake tickle failed: %d", ret);

	mInstance->ncp_is_misbehaving();

	finish(ret);

	EH_END();
}

