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
 *    Description:
 *		This file contains the code that handles transitioning the
 *      NCP into a deep-sleep state.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include <syslog.h>
#include <errno.h>
#include "SpinelNCPTaskDeepSleep.h"
#include "SpinelNCPInstance.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

nl::wpantund::SpinelNCPTaskDeepSleep::SpinelNCPTaskDeepSleep(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb
):	SpinelNCPTask(instance, cb)
{
}

void
nl::wpantund::SpinelNCPTaskDeepSleep::finish(int status, const boost::any& value)
{
	mInstance->mResetIsExpected = false;

	SpinelNCPTask::finish(status, value);
}


int
nl::wpantund::SpinelNCPTaskDeepSleep::vprocess_event(int event, va_list args)
{
	int ret = kWPANTUNDStatus_Failure;

	EH_BEGIN();

	// The first event to a task is EVENT_STARTING_TASK. The following
	// line makes sure that we don't start processing this task
	// until it is properly scheduled. All tasks immediately receive
	// the initial `EVENT_STARTING_TASK` event, but further events
	// will only be received by that task once it is that task's turn
	// to execute.
	EH_WAIT_UNTIL(EVENT_STARTING_TASK != event);

	// If we are still initializing, wait until we are finished.
	EH_WAIT_UNTIL_WITH_TIMEOUT(mInstance->mDriverState == SpinelNCPInstance::NORMAL_OPERATION, NCP_DEFAULT_COMMAND_SEND_TIMEOUT);

	if (mInstance->can_set_ncp_power()) {
		mNextCommand = SpinelPackData(SPINEL_FRAME_PACK_CMD_NOOP);
		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

		// Wait for half a second after the last ncp-generated event before
		// manually cutting the power, just to be conservative.
		do {
			EH_WAIT_UNTIL(!IS_EVENT_FROM_NCP(event));
			EH_WAIT_UNTIL_WITH_TIMEOUT(0.5, IS_EVENT_FROM_NCP(event));
		} while(!eh_did_timeout);

		if (mInstance->set_ncp_power(false) == kWPANTUNDStatus_Ok) {
			mInstance->change_ncp_state(DEEP_SLEEP);
		} else {
			syslog(LOG_ERR, "DeepSleep: set_ncp_power(false) failed.");

			// Turning off the power manually didn't work for some reason.
			// Turn it back on and we will try to do it via the API.
			mInstance->set_ncp_power(true);
		}
	}

	if (mInstance->get_ncp_state() != DEEP_SLEEP) {
		syslog(LOG_NOTICE, "DeepSleep: Putting NCP to sleep.");

		mNextCommand = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S),
			SPINEL_PROP_POWER_STATE,
			SPINEL_POWER_STATE_DEEP_SLEEP
		);
		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
		ret = mNextCommandRet;
		if (ret == spinel_status_to_wpantund_status(SPINEL_STATUS_PROP_NOT_FOUND)) {
			ret = kWPANTUNDStatus_FeatureNotImplemented;
		}
		require_noerr(ret, on_error);

		mInstance->change_ncp_state(DEEP_SLEEP);
	}

on_error:

	if (mInstance->get_ncp_state() == DEEP_SLEEP) {
		syslog(LOG_NOTICE, "NCP is asleep.");
		ret = kWPANTUNDStatus_Ok;
	} else if (ret == kWPANTUNDStatus_FeatureNotImplemented) {
		syslog(LOG_WARNING, "NCP does not support deep sleep.");
	} else {
		syslog(LOG_WARNING, "NCP DID NOT GO TO SLEEP!");
		if (kWPANTUNDStatus_Ok == ret) {
			ret = kWPANTUNDStatus_Failure;
		}
	}

	finish(ret);

	EH_END();
}
