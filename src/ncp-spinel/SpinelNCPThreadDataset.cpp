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
#include "SpinelNCPInstance.h"
#include "SpinelNCPTask.h"
#include "SpinelNCPThreadDataset.h"
#include "any-to.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;

void
ThreadDataset::clear(void)
{
	mActiveTimestamp.clear();
	mPendingTimestamp.clear();
	mMasterKey.clear();
	mNetworkName.clear();
	mExtendedPanId.clear();
	mMeshLocalPrefix.clear();
	mDelay.clear();
	mPanId.clear();
	mChannel.clear();
	mPSKc.clear();
	mChannelMaskPage0.clear();
	mSecurityPolicy.clear();
	mRawTlvs.clear();
	mDestIpAddress.clear();
}

void
ThreadDataset::convert_to_valuemap(ValueMap &map)
{
	map.clear();

	if (mActiveTimestamp.has_value()) {
		map[kWPANTUNDProperty_DatasetActiveTimestamp] = mActiveTimestamp.get();
	}

	if (mPendingTimestamp.has_value()) {
		map[kWPANTUNDProperty_DatasetPendingTimestamp] = mPendingTimestamp.get();
	}

	if (mMasterKey.has_value()) {
		map[kWPANTUNDProperty_DatasetMasterKey] = mMasterKey.get();
	}

	if (mNetworkName.has_value()) {
		map[kWPANTUNDProperty_DatasetNetworkName] = mNetworkName.get();
	}

	if (mExtendedPanId.has_value()) {
		map[kWPANTUNDProperty_DatasetExtendedPanId] = mExtendedPanId.get();
	}

	if (mMeshLocalPrefix.has_value()) {
		map[kWPANTUNDProperty_DatasetMeshLocalPrefix] = any_to_string(mMeshLocalPrefix.get());
	}

	if (mDelay.has_value()) {
		map[kWPANTUNDProperty_DatasetDelay] = mDelay.get();
	}

	if (mPanId.has_value()) {
		map[kWPANTUNDProperty_DatasetPanId] = mPanId.get();
	}

	if (mChannel.has_value()) {
		map[kWPANTUNDProperty_DatasetChannel] = mChannel.get();
	}

	if (mPSKc.has_value()) {
		map[kWPANTUNDProperty_DatasetPSKc] = mPSKc.get();
	}

	if (mChannelMaskPage0.has_value()) {
		map[kWPANTUNDProperty_DatasetChannelMaskPage0] = mChannelMaskPage0.get();
	}

	if (mRawTlvs.has_value()) {
		map[kWPANTUNDProperty_DatasetRawTlvs] = mRawTlvs.get();
	}

	if (mSecurityPolicy.has_value()) {
		map[kWPANTUNDProperty_DatasetSecPolicyKeyRotation] = mSecurityPolicy.get().mKeyRotationTime;
		map[kWPANTUNDProperty_DatasetSecPolicyFlags] = mSecurityPolicy.get().mFlags;
	}

	if (mDestIpAddress.has_value()) {
		map[kWPANTUNDProperty_DatasetDestIpAddress] = in6_addr_to_string(mDestIpAddress.get());
	}
}

void
ThreadDataset::convert_to_string_list(std::list<std::string> &list)
{
	char str[256];
	list.clear();

	if (mActiveTimestamp.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  0x%08X%08X", kWPANTUNDProperty_DatasetActiveTimestamp,
			static_cast<uint32_t>(mActiveTimestamp.get() >> 32),
			static_cast<uint32_t>(mActiveTimestamp.get() & 0xFFFFFFFF));
		list.push_back(str);
	}

	if (mPendingTimestamp.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  0x%08X%08X", kWPANTUNDProperty_DatasetPendingTimestamp,
			static_cast<uint32_t>(mPendingTimestamp.get() >> 32),
			static_cast<uint32_t>(mPendingTimestamp.get() & 0xFFFFFFFF)
		);
		list.push_back(str);
	}

	if (mChannel.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  %d", kWPANTUNDProperty_DatasetChannel, mChannel.get());
		list.push_back(str);
	}

	if (mNetworkName.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  \"%s\"", kWPANTUNDProperty_DatasetNetworkName, mNetworkName.get().c_str());
		list.push_back(str);
	}

	if (mPanId.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  0x%02X", kWPANTUNDProperty_DatasetPanId, mPanId.get());
		list.push_back(str);
	}

	if (mExtendedPanId.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  0x%s", kWPANTUNDProperty_DatasetExtendedPanId,
			any_to_string(mExtendedPanId.get()).c_str());
		list.push_back(str);
	}

	if (mMasterKey.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  [%s]", kWPANTUNDProperty_DatasetMasterKey,
			any_to_string(mMasterKey.get()).c_str());
		list.push_back(str);
	}

	if (mMeshLocalPrefix.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  %s/64", kWPANTUNDProperty_DatasetMeshLocalPrefix,
			any_to_string(mMeshLocalPrefix.get()).c_str());
		list.push_back(str);
	}

	if (mDelay.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  %d", kWPANTUNDProperty_DatasetDelay, mDelay.get());
		list.push_back(str);
	}

	if (mChannelMaskPage0.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  0x%08X", kWPANTUNDProperty_DatasetChannelMaskPage0,
			mChannelMaskPage0.get());
		list.push_back(str);
	}

	if (mPSKc.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  [%s]", kWPANTUNDProperty_DatasetPSKc, any_to_string(mPSKc.get()).c_str());
		list.push_back(str);
	}

	if (mSecurityPolicy.has_value()) {
		snprintf(str, sizeof(str), "%-32s =  %d", kWPANTUNDProperty_DatasetSecPolicyKeyRotation,
			mSecurityPolicy.get().mKeyRotationTime);
		list.push_back(str);
		snprintf(str, sizeof(str), "%-32s =  0x%0X", kWPANTUNDProperty_DatasetSecPolicyFlags,
			mSecurityPolicy.get().mFlags);
		list.push_back(str);
	}

	if (mRawTlvs.has_value()) {
		snprintf(
			str, sizeof(str), "%-32s =  [%s]", kWPANTUNDProperty_DatasetRawTlvs,
			any_to_string(mRawTlvs.get()).c_str()
		);
		list.push_back(str);
	}

	if (mDestIpAddress.has_value()) {
		snprintf(
			str, sizeof(str), "%-32s =  %s", kWPANTUNDProperty_DatasetDestIpAddress,
			any_to_string(mDestIpAddress.get()).c_str()
		);
		list.push_back(str);
	}
}

int
ThreadDataset::set_from_spinel_frame(const uint8_t *data_in, spinel_size_t data_len)
{
	int ret = kWPANTUNDStatus_Ok;

	clear();

	while (data_len > 0) {
		spinel_ssize_t len = 0;
		const uint8_t *struct_data;
		spinel_size_t struct_len;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_DATA_WLEN_S,
			&struct_data,
			&struct_len
		);

		require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		ret = parse_dataset_entry(struct_data, struct_len);
		require_noerr(ret, bail);

		data_in += len;
		data_len -= len;
	}

bail:

	if (ret != kWPANTUNDStatus_Ok) {
		clear();
	}

	return ret;
}

int
ThreadDataset::parse_dataset_entry(const uint8_t *data_in, spinel_size_t data_len)
{
	int ret = kWPANTUNDStatus_Ok;
	unsigned int prop_key;
	const uint8_t *value_data;
	spinel_size_t value_len;
	spinel_ssize_t len = 0;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		(
			SPINEL_DATATYPE_UINT_PACKED_S
			SPINEL_DATATYPE_DATA_S
		),
		&prop_key,
		&value_data,
		&value_len
	);

	require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

	switch (static_cast<spinel_prop_key_t>(prop_key)) {

	case SPINEL_PROP_DATASET_ACTIVE_TIMESTAMP:
		{
			uint64_t active_timestamp;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				SPINEL_DATATYPE_UINT64_S,
				&active_timestamp
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mActiveTimestamp = active_timestamp;
		}
		break;

	case SPINEL_PROP_DATASET_PENDING_TIMESTAMP:
		{
			uint64_t pending_timestamp;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				SPINEL_DATATYPE_UINT64_S,
				&pending_timestamp
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mPendingTimestamp = pending_timestamp;
		}
		break;

	case SPINEL_PROP_NET_MASTER_KEY:
		require_action(value_len > 0, bail, ret = kWPANTUNDStatus_Failure);
		mMasterKey = Data(value_data, value_len);
		break;

	case SPINEL_PROP_NET_NETWORK_NAME:
		{
			const char *name;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				SPINEL_DATATYPE_UTF8_S,
				&name
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mNetworkName = std::string(name);
		}
		break;

	case SPINEL_PROP_NET_XPANID:
		require_action(value_len > 0, bail, ret = kWPANTUNDStatus_Failure);
		mExtendedPanId = Data(value_data, value_len);
		break;

	case SPINEL_PROP_IPV6_ML_PREFIX:
		{
			const struct in6_addr *prefix;
			uint8_t prefix_len;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				(
					SPINEL_DATATYPE_IPv6ADDR_S
					SPINEL_DATATYPE_UINT8_S
				),
				&prefix,
				&prefix_len
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			require_action(prefix_len == kMeshLocalPrefixLen, bail, ret = kWPANTUNDStatus_Failure);
			mMeshLocalPrefix = *prefix;
		}
		break;

	case SPINEL_PROP_DATASET_DELAY_TIMER:
		{
			uint32_t delay_timer;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				SPINEL_DATATYPE_UINT32_S,
				&delay_timer
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mDelay = delay_timer;
		}
		break;

	case SPINEL_PROP_MAC_15_4_PANID:
		{
			uint16_t panid;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				SPINEL_DATATYPE_UINT16_S,
				&panid
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mPanId = panid;
		}
		break;

	case SPINEL_PROP_PHY_CHAN:
		{
			uint8_t channel;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				SPINEL_DATATYPE_UINT8_S,
				&channel
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mChannel = channel;
		}
		break;

	case SPINEL_PROP_NET_PSKC:
		require_action(value_len > 0, bail, ret = kWPANTUNDStatus_Failure);
		mPSKc = Data(value_data, value_len);
		break;

	case SPINEL_PROP_PHY_CHAN_SUPPORTED:
		{
			uint32_t channel_mask = 0;

			while (value_len > 0) {
				uint8_t channel = *value_data;

				require_action(channel <= 31, bail, ret = kWPANTUNDStatus_Failure);
				channel_mask |= (1U << channel);

				value_data += sizeof(uint8_t);
				value_len -= sizeof(uint8_t);
			}
			mChannelMaskPage0 = channel_mask;
		}
		break;

	case SPINEL_PROP_DATASET_SECURITY_POLICY:
		{
			ThreadDataset::SecurityPolicy sec_policy;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				(
					SPINEL_DATATYPE_UINT16_S
					SPINEL_DATATYPE_UINT8_S
				),
				&sec_policy.mKeyRotationTime,
				&sec_policy.mFlags
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mSecurityPolicy = sec_policy;
		}
		break;

	case SPINEL_PROP_DATASET_RAW_TLVS:
		require_action(value_len > 0, bail, ret = kWPANTUNDStatus_Failure);
		mRawTlvs = Data(value_data, value_len);
		break;

	case SPINEL_PROP_DATASET_DEST_ADDRESS:
		{
			const struct in6_addr *address;

			len = spinel_datatype_unpack(
				value_data,
				value_len,
				SPINEL_DATATYPE_IPv6ADDR_S,
				&address
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
			mDestIpAddress = *address;
		}
		break;

	default:
		syslog(
			LOG_WARNING,
			"Unsupported/unknown property key in a Thread Operational Dataset: %s (%d)",
			spinel_prop_key_to_cstr(static_cast<spinel_prop_key_t>(prop_key)),
			prop_key
		);
		break;
	}

bail:
	return ret;
}

void
ThreadDataset::convert_to_spinel_frame(Data &frame, bool include_value)
{
	frame.clear();

	if (mActiveTimestamp.has_value()) {

		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT64_S),
				SPINEL_PROP_DATASET_ACTIVE_TIMESTAMP,
				mActiveTimestamp.get()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_DATASET_ACTIVE_TIMESTAMP
			));
		}
	}

	if (mPendingTimestamp.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT64_S),
				SPINEL_PROP_DATASET_PENDING_TIMESTAMP,
				mPendingTimestamp.get()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_DATASET_PENDING_TIMESTAMP
			));
		}
	}

	if (mMasterKey.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_DATA_S),
				SPINEL_PROP_NET_MASTER_KEY,
				mMasterKey.get().data(),
				mMasterKey.get().size()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_NET_MASTER_KEY
			));
		}
	}

	if (mNetworkName.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UTF8_S),
				SPINEL_PROP_NET_NETWORK_NAME,
				mNetworkName.get().c_str()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_NET_NETWORK_NAME
			));
		}
	}

	if (mExtendedPanId.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_DATA_S),
				SPINEL_PROP_NET_XPANID,
				mExtendedPanId.get().data(),
				mExtendedPanId.get().size()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_NET_XPANID
			));
		}
	}

	if (mMeshLocalPrefix.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(
					SPINEL_DATATYPE_UINT_PACKED_S
					SPINEL_DATATYPE_IPv6ADDR_S
					SPINEL_DATATYPE_UINT8_S
				),
				SPINEL_PROP_IPV6_ML_PREFIX,
				&mMeshLocalPrefix.get(),
				kMeshLocalPrefixLen
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_IPV6_ML_PREFIX
			));
		}
	}

	if (mDelay.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT32_S),
				SPINEL_PROP_DATASET_DELAY_TIMER,
				mDelay.get()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_DATASET_DELAY_TIMER
			));
		}
	}

	if (mPanId.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT16_S),
				SPINEL_PROP_MAC_15_4_PANID,
				mPanId.get()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_MAC_15_4_PANID
			));
		}
	}

	if (mChannel.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_UINT8_S),
				SPINEL_PROP_PHY_CHAN,
				mChannel.get()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_PHY_CHAN
			));
		}
	}

	if (mPSKc.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_DATA_S),
				SPINEL_PROP_NET_PSKC,
				mPSKc.get().data(),
				mPSKc.get().size()
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_NET_PSKC
			));
		}
	}

	if (mChannelMaskPage0.has_value()) {
		if (include_value) {
			uint8_t mask_data[32];
			uint8_t mask_len = 0;

			for (uint8_t i = 0; i < 32; i++) {
				if (mChannelMaskPage0.get() & (1U << i)) {
					mask_data[mask_len++] = i;
				}
			}

			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S SPINEL_DATATYPE_DATA_S),
				SPINEL_PROP_PHY_CHAN_SUPPORTED,
				mask_data,
				mask_len
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_PHY_CHAN_SUPPORTED
			));
		}
	}

	if (mSecurityPolicy.has_value()) {
		if (include_value) {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(
					SPINEL_DATATYPE_UINT_PACKED_S
					SPINEL_DATATYPE_UINT16_S
					SPINEL_DATATYPE_UINT8_S
				),
				SPINEL_PROP_DATASET_SECURITY_POLICY,
				mSecurityPolicy.get().mKeyRotationTime,
				mSecurityPolicy.get().mFlags
			));
		} else {
			frame.append(SpinelPackData(
				SPINEL_DATATYPE_STRUCT_S(SPINEL_DATATYPE_UINT_PACKED_S),
				SPINEL_PROP_DATASET_SECURITY_POLICY
			));
		}
	}

	if (mRawTlvs.has_value()) {  /* always include the raw TLV value */
		frame.append(SpinelPackData(
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_UINT_PACKED_S
				SPINEL_DATATYPE_DATA_S
			),
			SPINEL_PROP_DATASET_RAW_TLVS,
			mRawTlvs.get().data(),
			mRawTlvs.get().size()
		));
	}

	if (mDestIpAddress.has_value()) { /* always include dest IP address value */
		frame.append(SpinelPackData(
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_UINT_PACKED_S
				SPINEL_DATATYPE_IPv6ADDR_S
			),
			SPINEL_PROP_DATASET_DEST_ADDRESS,
			&mDestIpAddress.get()
		));
	}
}
