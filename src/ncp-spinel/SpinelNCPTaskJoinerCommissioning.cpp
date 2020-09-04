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
#include <stdint.h>
#include <inttypes.h>
#include "SpinelNCPTaskJoinerCommissioning.h"
#include "SpinelNCPInstance.h"
#include "any-to.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

static const char *kOptionalParamsValueMapKeys[] = {
	kWPANTUNDValueMapKey_Joiner_ProvisioningUrl,
	kWPANTUNDValueMapKey_Joiner_VendorName,
	kWPANTUNDValueMapKey_Joiner_VendorModel,
	kWPANTUNDValueMapKey_Joiner_VendorSwVersion,
	kWPANTUNDValueMapKey_Joiner_VendorData,
	NULL
};

nl::wpantund::SpinelNCPTaskJoinerCommissioning::SpinelNCPTaskJoinerCommissioning(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	bool action,
	const ValueMap& options
): SpinelNCPTask(instance, cb), mAction(action), mOptions(options), mLastState(instance->get_ncp_state())
{
}

void
nl::wpantund::SpinelNCPTaskJoinerCommissioning::finish(int status, const boost::any &value)
{
	if (mAction && status != kWPANTUNDStatus_Ok) {
		mInstance->change_ncp_state(mLastState);
	}

	SpinelNCPTask::finish(status, value);
}

int
nl::wpantund::SpinelNCPTaskJoinerCommissioning::convert_joiner_status_to_wpan_error(int last_status)
{
	int ret = kWPANTUNDStatus_JoinerFailed_Unknown;

	switch (last_status) {
	case SPINEL_STATUS_JOIN_SUCCESS:
		ret = kWPANTUNDStatus_Ok;
		break;
	case SPINEL_STATUS_JOIN_SECURITY:
		ret = kWPANTUNDStatus_JoinerFailed_Security;
		break;
	case SPINEL_STATUS_JOIN_NO_PEERS:
		ret = kWPANTUNDStatus_JoinerFailed_NoPeers;
		break;
	case SPINEL_STATUS_JOIN_RSP_TIMEOUT:
		ret = kWPANTUNDStatus_JoinerFailed_ResponseTimeout;
		break;
	case SPINEL_STATUS_JOIN_FAILURE:
	default:
		ret = kWPANTUNDStatus_JoinerFailed_Unknown;
		break;
	}

	return ret;
}

int
nl::wpantund::SpinelNCPTaskJoinerCommissioning::vprocess_event(int event, va_list args)
{
	int ret = kWPANTUNDStatus_Failure;
	int last_status = peek_ncp_callback_status(event, args);
	uint64_t discerner_value;
	uint8_t discerner_len;

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

	if (!mAction) {
		syslog(LOG_INFO, "Stopping Joiner Commissioning");

		// First bringing down the interface to cover for case
		// where it was brought up when Joiner starts.
		mNextCommand = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
			SPINEL_PROP_NET_IF_UP,
			false
		);
		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
		ret = mNextCommandRet;
		require((ret == kWPANTUNDStatus_Ok) || (ret == kWPANTUNDStatus_Already), on_error);

		mNextCommand = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
			SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING,
			false
		);

		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
		ret = mNextCommandRet;
		require_noerr(ret, on_error);

	} else { // starting joiner commissioning

		mLastState = mInstance->get_ncp_state();

		// Ensure PSKd is provided.
		if (!mOptions.count(kWPANTUNDValueMapKey_Joiner_PSKd)) {

			syslog(LOG_ERR, "Starting Joiner Commissioning failed. Missing PSKd");
			ret = kWPANTUNDStatus_InvalidArgument;
			goto on_error;
		}

		// Use empty string for any unspecified optional parameter
		for (const char **key = &kOptionalParamsValueMapKeys[0]; *key != NULL; key++) {
			if (!mOptions.count(*key)) {
				mOptions[*key] = std::string("");
			}
		}

		if (!mOptions.count(kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart)) {
			mOptions[kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart] = boost::any(false);
		}

		if (mOptions.count(kWPANTUNDValueMapKey_Joiner_DiscernerValue)
		   && !mOptions.count(kWPANTUNDValueMapKey_Joiner_DiscernerBitLength)) {

			syslog(LOG_ERR, "Starting Joiner Commissioning failed. Discerner value provided without length");
			ret = kWPANTUNDStatus_InvalidArgument;
			goto on_error;
		}

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
		require((ret == kWPANTUNDStatus_Ok), on_error);

		syslog(LOG_INFO,
			"Starting Joiner Commissioning, PSKd(hidden), ProvisioningURL:\"%s\", "
			"VendorInfo [Name:\"%s\", Model:\"%s\", SwVer:\"%s\", Data:\"%s\"]",
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_ProvisioningUrl]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorName]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorModel]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorSwVersion]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorData]).c_str()
		);

		if (mOptions.count(kWPANTUNDValueMapKey_Joiner_DiscernerValue)) {
			discerner_value = any_to_uint64(mOptions[kWPANTUNDValueMapKey_Joiner_DiscernerValue]);
			discerner_len = static_cast<uint8_t>(any_to_int(mOptions[kWPANTUNDValueMapKey_Joiner_DiscernerBitLength]));

			syslog(LOG_INFO, "with Joiner Discerner %" PRIu64 " (bit-len:%d)", discerner_value, discerner_len);

			mNextCommand = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(
					SPINEL_DATATYPE_UINT8_S
					SPINEL_DATATYPE_INT64_S
				),
				SPINEL_PROP_MESHCOP_JOINER_DISCERNER,
				discerner_len,
				discerner_value
			);

			EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
			ret = mNextCommandRet;
			require((ret == kWPANTUNDStatus_Ok) || (ret == kWPANTUNDStatus_Already), on_error);
		}

		mNextCommand = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(
				SPINEL_DATATYPE_BOOL_S
				SPINEL_DATATYPE_UTF8_S
				SPINEL_DATATYPE_UTF8_S
				SPINEL_DATATYPE_UTF8_S
				SPINEL_DATATYPE_UTF8_S
				SPINEL_DATATYPE_UTF8_S
				SPINEL_DATATYPE_UTF8_S
			),
			SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING,
			mAction,
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_PSKd]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_ProvisioningUrl]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorName]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorModel]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorSwVersion]).c_str(),
			any_to_string(mOptions[kWPANTUNDValueMapKey_Joiner_VendorData]).c_str()
		);

		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
		ret = mNextCommandRet;
		require_noerr(ret, on_error);

		if (!any_to_bool(mOptions[kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart])) {

			// Wait for LAST_STATUS JOIN response from NCP to indicate the Joiner operation status
			EH_REQUIRE_WITHIN(
				NCP_JOINER_TIMEOUT,
				((last_status >= SPINEL_STATUS_JOIN__BEGIN) && (last_status < SPINEL_STATUS_JOIN__END)),
				on_error
			);

			ret = convert_joiner_status_to_wpan_error(last_status);
		}
	}

	finish(ret);

	EH_EXIT();

on_error:

	if (ret == kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR,
		"%s Joiner Commissioning failed: %d (%s)",
		mAction ? "Starting" : "Stopping",
		ret, wpantund_status_to_cstr(ret)
	);

	finish(ret);

	EH_END();
}

nl::wpantund::SpinelNCPTaskJoinerAttach::SpinelNCPTaskJoinerAttach(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	const ValueMap& options
): SpinelNCPTask(instance, cb), mOptions(options)
{
}

int
nl::wpantund::SpinelNCPTaskJoinerAttach::vprocess_event(int event, va_list args)
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

	syslog(LOG_INFO, "Joiner Attach");

	// If the "ReturnImmediatelyOnStart" is not given, assume `false`
	// (i.e. default behavior will block and wait till device becomes
	// associated).

	if (!mOptions.count(kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart)) {
		mOptions[kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart] = boost::any(false);
	}

	mNextCommand = SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
		SPINEL_PROP_NET_STACK_UP,
		true
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	ret = mNextCommandRet;

	require((ret == kWPANTUNDStatus_Ok) || (ret == kWPANTUNDStatus_Already), on_error);

	if (!any_to_bool(mOptions[kWPANTUNDValueMapKey_Joiner_ReturnImmediatelyOnStart])) {

		// Wait for device to be associated
		EH_REQUIRE_WITHIN(
			NCP_JOIN_TIMEOUT,
			ncp_state_is_associated(mInstance->get_ncp_state()) && !mInstance->is_initializing_ncp(),
			on_error
		);
	}

	ret = kWPANTUNDStatus_Ok;

	finish(ret);

	EH_EXIT();

on_error:

	if (ret == kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "Joiner Attach failed: %d (%s)", ret, wpantund_status_to_cstr(ret));

	finish(ret);

	EH_END();
}
