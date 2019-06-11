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
#include "SpinelNCPTaskForm.h"
#include "SpinelNCPInstance.h"
#include "SpinelNCPTaskScan.h"
#include "any-to.h"
#include "spinel-extra.h"
#include "IPv6Helpers.h"
#include "sec-random.h"

using namespace nl;
using namespace nl::wpantund;

nl::wpantund::SpinelNCPTaskForm::SpinelNCPTaskForm(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	const ValueMap& options
):	SpinelNCPTask(instance, cb), mOptions(options), mLastState(instance->get_ncp_state()), mDataset()
{
	// The parameters in `mOption` value-map dictionary are used first, but
	// if PAN-Id, extended PAN-Id, or network key are not provided in the
	// `mOptions`, we check if there is a previously set value and use it instead.

	if (!mOptions.count(kWPANTUNDProperty_NetworkPANID)) {
		uint16_t panid = instance->mCurrentNetworkInstance.panid;

		if (panid != 0xffff) {
			mOptions[kWPANTUNDProperty_NetworkPANID] = panid;
			syslog(LOG_INFO, "Form: No PAN-ID specified, using previously set value 0x%04X", panid);
		}
	}

	if (!mOptions.count(kWPANTUNDProperty_NetworkXPANID) && instance->mXPANIDWasExplicitlySet) {
		char xpanid_str[100];

		mOptions[kWPANTUNDProperty_NetworkXPANID] = instance->mCurrentNetworkInstance.get_xpanid_as_uint64();
		encode_data_into_string(
			instance->mCurrentNetworkInstance.xpanid, sizeof(instance->mCurrentNetworkInstance.xpanid),
			xpanid_str, sizeof(xpanid_str), 0);
		syslog(LOG_INFO, "Form: No Extended PAN-ID specified, using previously set value 0x%s", xpanid_str);
	}

	if (!mOptions.count(kWPANTUNDProperty_NetworkKey) && !instance->mNetworkKey.empty()) {
		mOptions[kWPANTUNDProperty_NetworkKey] = instance->mNetworkKey;
		syslog(LOG_INFO, "Form: No network key specified, using previously set value [value hidden]");
	}
}

void
nl::wpantund::SpinelNCPTaskForm::finish(int status, const boost::any& value)
{
	if (!ncp_state_is_associated(mInstance->get_ncp_state())) {
		mInstance->change_ncp_state(mLastState);
	}

	SpinelNCPTask::finish(status, value);
}

int
nl::wpantund::SpinelNCPTaskForm::vprocess_event(int event, va_list args)
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

	if (!mInstance->mCapabilities.count(SPINEL_CAP_ROLE_ROUTER)) {
		// We can't form unless we are router-capable
		ret = kWPANTUNDStatus_FeatureNotSupported;
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

	mLastState = mInstance->get_ncp_state();
	mInstance->change_ncp_state(ASSOCIATING);

	// Clear any previously saved network settings
	mNextCommand = SpinelPackData(SPINEL_FRAME_PACK_CMD_NET_CLEAR);
	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
	ret = mNextCommandRet;

	check_noerr(ret);

	// Turn off promiscuous mode, if it happens to be on
	mNextCommand = SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S),
		SPINEL_PROP_MAC_PROMISCUOUS_MODE,
		SPINEL_MAC_PROMISCUOUS_MODE_OFF
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
	ret = mNextCommandRet;
	check_noerr(ret);

	if (mOptions.count(kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix)) {
		if (mInstance->mCapabilities.count(SPINEL_CAP_NEST_LEGACY_INTERFACE)) {
			{
				Data data = any_to_data(mOptions[kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix]);
				mNextCommand = SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
					SPINEL_PROP_NEST_LEGACY_ULA_PREFIX,
					data.data(),
					data.size()
				);
			}

			EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

			ret = mNextCommandRet;

			require_noerr(ret, on_error);
		}
	}

	// Get a new Operational DataSet from NCP.
	{
		unsigned int prop_key;
		const uint8_t *data_in;
		spinel_size_t data_len;

		mNextCommand = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_NEW_DATASET);

		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

		ret = mNextCommandRet;

		require_noerr(ret, on_error);
		require(EVENT_NCP_PROP_VALUE_IS == event, on_error);

		prop_key = va_arg(args, unsigned int);
		data_in = va_arg(args, const uint8_t*);
		data_len = va_arg_small(args, spinel_size_t);

		require(prop_key == SPINEL_PROP_THREAD_NEW_DATASET, on_error);

		mDataset.set_from_spinel_frame(data_in, data_len);
	}

	// Ensure generated mDataset contains all the required fields.

	require(mDataset.mActiveTimestamp.has_value(), on_error);
	require(mDataset.mChannel.has_value(), on_error);
	require(mDataset.mChannelMaskPage0.has_value(), on_error);
	require(mDataset.mPanId.has_value(), on_error);
	require(mDataset.mExtendedPanId.has_value(), on_error);
	require(mDataset.mMeshLocalPrefix.has_value(), on_error);

	// Channel

	if (mOptions.count(kWPANTUNDProperty_NCPChannel)) {
		uint8_t channel = any_to_int(mOptions[kWPANTUNDProperty_NCPChannel]);

		// Make sure the channel is in the supported channel mask
		if ((mDataset.mChannelMaskPage0.get() & (1U << channel)) == 0) {
			syslog(LOG_ERR, "Form: Channel %d is not supported by NCP. Supported channels mask is %08x",
				channel, mDataset.mChannelMaskPage0.get());
			ret = kWPANTUNDStatus_InvalidArgument;
			goto on_error;
		}

		mDataset.mChannel = channel;

		syslog(LOG_NOTICE, "Form: Channel %d (user-specified)", channel);

	} else if (mOptions.count(kWPANTUNDProperty_NCPChannelMask)) {
		uint32_t mask = any_to_int(mOptions[kWPANTUNDProperty_NCPChannelMask]);
		uint8_t channel;

		// Make sure the mask is in the supported channel mask.
		if ((mDataset.mChannelMaskPage0.get() & mask) == 0) {
			syslog(LOG_ERR, "Invalid mask 0x%08x. Supported channels mask is 0x%08x", mask,
				mDataset.mChannelMaskPage0.get());
			ret = kWPANTUNDStatus_InvalidArgument;
			goto on_error;
		}

		mask &= mDataset.mChannelMaskPage0.get();

		if ((mask & mInstance->mPreferredChannelMask) != 0) {
			mask &= mInstance->mPreferredChannelMask;
			syslog(LOG_INFO, "Form: Picking channel from user-specified mask combined with preferred mask 0x%08x", mask);
		} else {
			syslog(LOG_INFO, "Form: Picking channel from user-specified mask: 0x%08x", mask);
		}

		// Randomly pick a channel from the mask.
		do {
			sec_random_fill(&channel, 1);
			channel = (channel % 32);
		} while (0 == ((1 << channel) & mask));

		mDataset.mChannel = channel;
		syslog(LOG_NOTICE, "Form: Channel %d (randomly selected from mask)", channel);
	} else {
		syslog(LOG_NOTICE, "Form: Channel %d (chosen by NCP)", mDataset.mChannel.get());
	}

	// PAN-Id

	if (mOptions.count(kWPANTUNDProperty_NetworkPANID)) {
		mDataset.mPanId = any_to_int(mOptions[kWPANTUNDProperty_NetworkPANID]);
		syslog(LOG_NOTICE, "Form: PAN-ID 0x%04X (user-specified)", mDataset.mPanId.get());
	} else {
		syslog(LOG_NOTICE, "Form: PAN-ID 0x%04X (chosen by NCP)", mDataset.mPanId.get());
	}

	// Extended PAN-Id

	if (mOptions.count(kWPANTUNDProperty_NetworkXPANID)) {
		uint64_t xpanid = any_to_uint64(mOptions[kWPANTUNDProperty_NetworkXPANID]);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		reverse_bytes(reinterpret_cast<uint8_t *>(&xpanid), sizeof(xpanid));
#endif
		mDataset.mExtendedPanId = Data(reinterpret_cast<uint8_t *>(&xpanid), sizeof(xpanid));

		syslog(LOG_NOTICE, "Form: XPAN-ID %s (user-specified)", mDataset.mExtendedPanId.get().to_string().c_str());
	} else {
		syslog(LOG_NOTICE, "Form: XPAN-ID %s (chosen by NCP)", mDataset.mExtendedPanId.get().to_string().c_str());
	}

	// Network Name

	if (mOptions.count(kWPANTUNDProperty_NetworkName)) {
		mDataset.mNetworkName = any_to_string(mOptions[kWPANTUNDProperty_NetworkName]);
		syslog(LOG_NOTICE, "Form: NetworkName \"%s\" (user-specified)", mDataset.mNetworkName.get().c_str());
	} else {
		syslog(LOG_NOTICE, "Form: NetworkName \"%s\" (chosen by NCP)", mDataset.mNetworkName.get().c_str());
	}

	// Master Key

	if (mOptions.count(kWPANTUNDProperty_NetworkKey)) {
		mDataset.mMasterKey = any_to_data(mOptions[kWPANTUNDProperty_NetworkKey]);
		syslog(LOG_NOTICE, "Form: Master Key (user-specified)");
	} else {
		syslog(LOG_NOTICE, "Form: Master Key (chosen by NCP)");
	}

	// Mesh-local Prefix

	if (mOptions.count(kWPANTUNDProperty_IPv6MeshLocalPrefix)) {
		mDataset.mMeshLocalPrefix = any_to_ipv6(mOptions[kWPANTUNDProperty_IPv6MeshLocalPrefix]);
		syslog(LOG_NOTICE, "Form: MeshLocal Prefix %s (user-specified)",
			in6_addr_to_string(mDataset.mMeshLocalPrefix.get()).c_str());
	} else if (mOptions.count(kWPANTUNDProperty_IPv6MeshLocalAddress)) {
		mDataset.mMeshLocalPrefix = any_to_ipv6(mOptions[kWPANTUNDProperty_IPv6MeshLocalAddress]);
		syslog(LOG_NOTICE, "Form: MeshLocal Prefix %s (user-specified)",
			in6_addr_to_string(mDataset.mMeshLocalPrefix.get()).c_str());
	} else {
		syslog(LOG_NOTICE, "Form: MeshLocal Prefix %s (chosen by NCP)",
			in6_addr_to_string(mDataset.mMeshLocalPrefix.get()).c_str());
	}

	// Push the new dataset as the active dataset.
	{
		Data spinel_encoded_dataset;

		mDataset.convert_to_spinel_frame(spinel_encoded_dataset);

		mNextCommand = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
			SPINEL_PROP_THREAD_ACTIVE_DATASET,
			spinel_encoded_dataset.data(),
			spinel_encoded_dataset.size()
		);
	}

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
	ret = mNextCommandRet;

	require_noerr(ret, on_error);

	if (mOptions.count(kWPANTUNDProperty_NetworkKeyIndex)) {
		mNextCommand = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT32_S),
			SPINEL_PROP_NET_KEY_SEQUENCE_COUNTER,
			any_to_int(mOptions[kWPANTUNDProperty_NetworkKeyIndex])
		);

		EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

		ret = mNextCommandRet;

		require_noerr(ret, on_error);
	}

	// Now bring up the network by bringing up the interface and the stack.

	mNextCommand = SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
		SPINEL_PROP_NET_IF_UP,
		true
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	ret = mNextCommandRet;

	require(ret == kWPANTUNDStatus_Ok || ret == kWPANTUNDStatus_Already, on_error);

	mNextCommand = SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
		SPINEL_PROP_NET_STACK_UP,
		true
	);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));

	ret = mNextCommandRet;

	require_noerr(ret, on_error);

	EH_REQUIRE_WITHIN(
		NCP_FORM_TIMEOUT,
		ncp_state_is_associated(mInstance->get_ncp_state()),
		on_error
	);

	ret = kWPANTUNDStatus_Ok;

	finish(ret);

	EH_EXIT();

on_error:

	if (ret == kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "Form failed: %d", ret);

	finish(ret);

	EH_END();
}
