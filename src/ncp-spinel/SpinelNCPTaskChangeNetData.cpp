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

#include "assert-macros.h"
#include <syslog.h>
#include <errno.h>
#include "SpinelNCPTaskChangeNetData.h"
#include "SpinelNCPInstance.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

nl::wpantund::SpinelNCPTaskChangeNetData::SpinelNCPTaskChangeNetData(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	const Data& change_net_data_command,
	int timeout
):	SpinelNCPTask(instance, cb), mChangeNetDataCommand(change_net_data_command)
{
	mNextCommandTimeout = timeout;
	mRetVal = kWPANTUNDStatus_Failure;
}

int
nl::wpantund::SpinelNCPTaskChangeNetData::vprocess_event(int event, va_list args)
{
	EH_BEGIN();

	mRetVal = kWPANTUNDStatus_Failure;

	// The first event to a task is EVENT_STARTING_TASK. The following
	// line makes sure that we don't start processing this task
	// until it is properly scheduled. All tasks immediately receive
	// the initial `EVENT_STARTING_TASK` event, but further events
	// will only be received by that task once it is that task's turn
	// to execute.
	EH_WAIT_UNTIL(EVENT_STARTING_TASK != event);

	mNextCommand = SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
		SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
		true
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	mRetVal = mNextCommandRet;

	// In case of BUSY error status (meaning the `ALLOW_LOCAL_NET_DATA_CHANGE`
	// was already true), allow the operation to proceed.

	require((mRetVal == SPINEL_STATUS_OK) || (mRetVal == SPINEL_STATUS_BUSY), on_error);

	mNextCommand = mChangeNetDataCommand;

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	mRetVal = mNextCommandRet;

	// Even in case of failure we proceed to set ALLOW_LOCAL_NET_DATA_CHANGE
	// to `false`. The error status is checked after this. It is stored in
	// a class instance variable `mRetVal` so that the value is preserved
	// over the protothread EH_SPAWN() call.

	mNextCommand = SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
		SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
		false
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	require_noerr(mRetVal, on_error);

	mRetVal = mNextCommandRet;

	require_noerr(mRetVal, on_error);

	finish(mRetVal);

	EH_EXIT();

on_error:

	if (mRetVal == kWPANTUNDStatus_Ok) {
		mRetVal = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "Change local network data failed: %d", mRetVal);

	finish(mRetVal);

	EH_END();
}
