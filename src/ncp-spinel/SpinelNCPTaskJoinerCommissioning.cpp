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
#include "SpinelNCPTaskJoinerCommissioning.h"
#include "SpinelNCPInstance.h"
#include "any-to.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

nl::wpantund::SpinelNCPTaskJoinerCommissioning::SpinelNCPTaskJoinerCommissioning(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	bool action,
	const char *psk,
	const char *provisioning_url
	): SpinelNCPTask(instance, cb), mAction(action),
	mPsk(psk), mProvisioningUrl(provisioning_url),
	mLastState(instance->get_ncp_state())
{
}

void
nl::wpantund::SpinelNCPTaskJoinerCommissioning::finish(int status, const boost::any& value)
{
	if (mAction && status != kWPANTUNDStatus_Ok) {
		mInstance->change_ncp_state(mLastState);
	}

	SpinelNCPTask::finish(status, value);
}

int
nl::wpantund::SpinelNCPTaskJoinerCommissioning::vprocess_event(int event, va_list args)
{
	int ret = kWPANTUNDStatus_Failure;
	Data frame;

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
		!ncp_state_is_initializing(mInstance->get_ncp_state()),
		on_error
	);

	if (ncp_state_is_associated(mInstance->get_ncp_state())) {
		ret = kWPANTUNDStatus_Already;
		finish(ret);
		EH_EXIT();
	}

	// The first event to a task is EVENT_STARTING_TASK. The following
	// line makes sure that we don't start processing this task
	// until it is properly scheduled. All tasks immediately receive
	// the initial `EVENT_STARTING_TASK` event, but further events
	// will only be received by that task once it is that task's turn
	// to execute.
	EH_WAIT_UNTIL(EVENT_STARTING_TASK != event);

	if (mAction) {
		mLastState = mInstance->get_ncp_state();

		mInstance->change_ncp_state(ASSOCIATING);

		// Turn off promiscuous mode, if it happens to be on
		mNextCommand = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S),
				SPINEL_PROP_MAC_PROMISCUOUS_MODE,
				SPINEL_MAC_PROMISCUOUS_MODE_OFF
				);
		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
		ret = mNextCommandRet;
		check_noerr(ret);

		// Now bring up the network by bringing up the interface
		mNextCommand = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
				SPINEL_PROP_NET_IF_UP,
				true
				);

		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
		ret = mNextCommandRet;
		require((ret == kWPANTUNDStatus_Ok) || (ret == kWPANTUNDStatus_Already), on_error);
	}

	syslog(LOG_INFO, "Joiner commissioning %s (psk: %s) (provisioning_url %s)",
			mAction ? "start" : "stop", mPsk.c_str(), mProvisioningUrl.c_str());

	mNextCommand = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(
				SPINEL_DATATYPE_BOOL_S
				SPINEL_DATATYPE_UTF8_S
				SPINEL_DATATYPE_UTF8_S
				),
			SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING,
			mAction,
			mPsk.c_str(),
			mProvisioningUrl.c_str()
			);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
	ret = mNextCommandRet;
	require_noerr(ret, on_error);

	finish(ret);

	EH_EXIT();

on_error:

	if (ret == kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "Joiner commission %s failed: %d", mAction ? "start" : "stop", ret);

	finish(ret);

	EH_END();
}
