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
#include "SpinelNCPTaskGetChildTable.h"
#include "SpinelNCPInstance.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

nl::wpantund::SpinelNCPTaskGetChildTable::SpinelNCPTaskGetChildTable(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	ResultFormat result_format
):	SpinelNCPTask(instance, cb), mResultFormat(result_format), mChildTable()
{
}

int
nl::wpantund::SpinelNCPTaskGetChildTable::prase_child_table(const uint8_t *data_in, spinel_size_t data_len,
                                                            ChildTable& child_table)
{
	int ret = kWPANTUNDStatus_Ok;

	child_table.clear();

	while (data_len > 0)
	{
		spinel_ssize_t len = 0;
		ChildInfoEntry child_info;
		const spinel_eui64_t *eui64 = NULL;
		uint8_t mode;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			"T("
				SPINEL_DATATYPE_EUI64_S         // EUI64 Address
				SPINEL_DATATYPE_UINT16_S        // Rloc16
				SPINEL_DATATYPE_UINT32_S        // Timeout
				SPINEL_DATATYPE_UINT32_S        // Age
				SPINEL_DATATYPE_UINT8_S         // Network Data Version
				SPINEL_DATATYPE_UINT8_S         // Link Quality In
				SPINEL_DATATYPE_INT8_S          // Average RSS
				SPINEL_DATATYPE_UINT8_S         // Mode (flags)
			")",
			&eui64,
			&child_info.mRloc16,
			&child_info.mTimeout,
			&child_info.mAge,
			&child_info.mNetworkDataVersion,
			&child_info.mLinkQualityIn,
			&child_info.mAverageRssi,
            &mode
		);

		if (len <= 0)
		{
			break;
		}

		memcpy(child_info.mExtAddress, eui64, sizeof(child_info.mExtAddress));

		child_info.mRxOnWhenIdle = ((mode & kThreadMode_RxOnWhenIdle) != 0);
		child_info.mSecureDataRequest = ((mode & kThreadMode_SecureDataRequest) != 0);
		child_info.mFullFunction = ((mode & kThreadMode_FullFunctionDevice) != 0);
		child_info.mFullNetworkData = ((mode & kThreadMode_FullNetworkData) != 0);

		child_table.push_back(child_info);

		data_in += len;
		data_len -= len;
	}

	return ret;
}

int
nl::wpantund::SpinelNCPTaskGetChildTable::vprocess_event(int event, va_list args)
{
	int ret = kWPANTUNDStatus_Failure;
	unsigned int prop_key;
	const uint8_t *data_in;
	spinel_size_t data_len;

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

	// The first event to a task is EVENT_STARTING_TASK. The following
	// line makes sure that we don't start processing this task
	// until it is properly scheduled. All tasks immediately receive
	// the initial `EVENT_STARTING_TASK` event, but further events
	// will only be received by that task once it is that task's turn
	// to execute.
	EH_WAIT_UNTIL(EVENT_STARTING_TASK != event);

	mNextCommand = SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET,
		SPINEL_PROP_THREAD_CHILD_TABLE
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	ret = mNextCommandRet;

	require_noerr(ret, on_error);

	require(EVENT_NCP_PROP_VALUE_IS == event, on_error);

	prop_key = va_arg(args, unsigned int);
	data_in = va_arg(args, const uint8_t*);
	data_len = va_arg_small(args, spinel_size_t);

	require(prop_key == SPINEL_PROP_THREAD_CHILD_TABLE, on_error);

	prase_child_table(data_in, data_len, mChildTable);

	ret = kWPANTUNDStatus_Ok;

	if (mResultFormat == kResultFormat_StringArray)
	{
		std::list<std::string> result;
		ChildTable::iterator it;

		for (it = mChildTable.begin(); it != mChildTable.end(); it++)
		{
			result.push_back(it->get_as_string());
		}

		finish(ret, result);
	}
	else if (mResultFormat == kResultFormat_ValueMapArray)
	{
		std::list<ValueMap> result;
		ChildTable::iterator it;

		for (it = mChildTable.begin(); it != mChildTable.end(); it++)
		{
			result.push_back(it->get_as_valuemap());
		}

		finish(ret, result);
	}
	else
	{
		finish(ret);
	}

	mChildTable.clear();

	EH_EXIT();

on_error:

	if (ret == kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "Getting child table failed: %d", ret);

	finish(ret);

	mChildTable.clear();

	EH_END();
}

std::string
SpinelNCPTaskGetChildTable::ChildInfoEntry::get_as_string(void) const
{
	char c_string[800];

	snprintf(c_string, sizeof(c_string),
		"%02X%02X%02X%02X%02X%02X%02X%02X, rolc16: %04x, netDataVer: %-3d, inLQI: %-2d, aveRSS: %-3d, timeout: %-5u, "
		"age: %-5u, RxOnWhenIdle: %s, FFD: %s, secureDataReq: %s, fullNetData: %s",
		mExtAddress[0], mExtAddress[1], mExtAddress[2], mExtAddress[3],
		mExtAddress[4], mExtAddress[5], mExtAddress[6], mExtAddress[7],
		mRloc16,
		mNetworkDataVersion,
		mLinkQualityIn,
		mAverageRssi,
		mTimeout,
		mAge,
		mRxOnWhenIdle ? "yes" : "no",
		mFullFunction ? "yes" : "no",
		mSecureDataRequest ? "yes" : "no",
		mFullNetworkData ? "yes" : "no"
	);

	return std::string(c_string);
}

ValueMap
SpinelNCPTaskGetChildTable::ChildInfoEntry::get_as_valuemap(void) const
{
	// TODO: return the child info as a value map dictionary.
	return ValueMap();
}
