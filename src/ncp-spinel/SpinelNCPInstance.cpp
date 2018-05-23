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

#include "SpinelNCPInstance.h"
#include "time-utils.h"
#include "assert-macros.h"
#include <syslog.h>
#include <errno.h>
#include "socket-utils.h"
#include <stdexcept>
#include <sys/file.h>
#include "SuperSocket.h"
#include "SpinelNCPTask.h"
#include "SpinelNCPTaskWake.h"
#include "SpinelNCPTaskSendCommand.h"
#include "SpinelNCPTaskJoin.h"
#include "SpinelNCPTaskGetNetworkTopology.h"
#include "SpinelNCPTaskGetMsgBufferCounters.h"
#include "SpinelNCPThreadDataset.h"
#include "any-to.h"
#include "spinel-extra.h"
#include "IPv6Helpers.h"

#define kWPANTUNDProperty_Spinel_CounterPrefix		"NCP:Counter:"

#define kWPANTUND_Whitelist_RssiOverrideDisabled    127

using namespace nl;
using namespace wpantund;

WPANTUND_DEFINE_NCPINSTANCE_PLUGIN(spinel, SpinelNCPInstance);

void
SpinelNCPInstance::handle_ncp_log(const uint8_t* data_ptr, int data_len)
{
	static char linebuffer[NCP_DEBUG_LINE_LENGTH_MAX + 1];
	static int linepos = 0;
	while (data_len--) {
		char nextchar = *data_ptr++;

		if ((nextchar == '\t') || (nextchar >= 32)) {
			linebuffer[linepos++] = nextchar;
		}

		if ( (linepos != 0)
		  && ( (nextchar == '\n')
			|| (nextchar == '\r')
			|| (linepos >= (sizeof(linebuffer) - 1))
		  )
		)
		{
			// flush.
			linebuffer[linepos] = 0;
			syslog(LOG_WARNING, "NCP => %s\n", linebuffer);
			linepos = 0;
		}
	}
}

void
SpinelNCPInstance::start_new_task(const boost::shared_ptr<SpinelNCPTask> &task)
{
	if (ncp_state_is_detached_from_ncp(get_ncp_state())) {
		task->finish(kWPANTUNDStatus_InvalidWhenDisabled);
	} else if (PT_SCHEDULE(task->process_event(EVENT_STARTING_TASK))) {

		if (ncp_state_is_sleeping(get_ncp_state())
			&& (dynamic_cast<const SpinelNCPTaskWake*>(task.get()) == NULL)
		) {
			if (can_set_ncp_power()
			    || !mCapabilities.count(SPINEL_CAP_MCU_POWER_STATE)
			){
				start_new_task(boost::shared_ptr<SpinelNCPTask>(new SpinelNCPTaskWake(this, NilReturn())));
			}
		}

		mTaskQueue.push_back(task);
	}
}

int
nl::wpantund::spinel_status_to_wpantund_status(int spinel_status)
{
	wpantund_status_t ret;
	switch (spinel_status) {
	case SPINEL_STATUS_ALREADY:
		ret = kWPANTUNDStatus_Already;
		break;
	case SPINEL_STATUS_BUSY:
		ret = kWPANTUNDStatus_Busy;
		break;
	case SPINEL_STATUS_IN_PROGRESS:
		ret = kWPANTUNDStatus_InProgress;
		break;
	case SPINEL_STATUS_JOIN_FAILURE:
		ret = kWPANTUNDStatus_JoinFailedUnknown;
		break;
	case SPINEL_STATUS_JOIN_INCOMPATIBLE:
		ret = kWPANTUNDStatus_JoinFailedAtScan;
		break;
	case SPINEL_STATUS_JOIN_SECURITY:
		ret = kWPANTUNDStatus_JoinFailedAtAuthenticate;
		break;
	case SPINEL_STATUS_OK:
		ret = kWPANTUNDStatus_Ok;
		break;
	case SPINEL_STATUS_PROP_NOT_FOUND:
		ret = kWPANTUNDStatus_PropertyNotFound;
		break;
	case SPINEL_STATUS_INVALID_ARGUMENT:
		ret = kWPANTUNDStatus_NCP_InvalidArgument;
		break;
	case SPINEL_STATUS_INVALID_STATE:
		ret = kWPANTUNDStatus_InvalidForCurrentState;
		break;

	default:
		ret = WPANTUND_NCPERROR_TO_STATUS(spinel_status);
		break;
	}

	return ret;
}

int
nl::wpantund::peek_ncp_callback_status(int event, va_list args)
{
	int ret = 0;

	if (EVENT_NCP_PROP_VALUE_IS == event) {
		va_list tmp;
		va_copy(tmp, args);
		unsigned int key = va_arg(tmp, unsigned int);
		if (SPINEL_PROP_LAST_STATUS == key) {
			const uint8_t* spinel_data_ptr = va_arg(tmp, const uint8_t*);
			spinel_size_t spinel_data_len = va_arg(tmp, spinel_size_t);

			if (spinel_datatype_unpack(spinel_data_ptr, spinel_data_len, "i", &ret) <= 0) {
				ret = SPINEL_STATUS_PARSE_ERROR;
			}
		}
		va_end(tmp);
	} else if (EVENT_NCP_RESET == event) {
		va_list tmp;
		va_copy(tmp, args);
		ret = va_arg(tmp, int);
		va_end(tmp);
	}

	return ret;
}

SpinelNCPInstance::SpinelNCPInstance(const Settings& settings) :
	NCPInstanceBase(settings), mControlInterface(this), mVendorCustom(this)
{
	mInboundFrameDataLen = 0;
	mInboundFrameDataPtr = NULL;
	mInboundFrameDataType = 0;
	mInboundFrameHDLCCRC = 0;
	mInboundFrameSize = 0;
	mInboundHeader = 0;
	mIsCommissioned = false;
	mFilterRLOCAddresses = true;
	mTickleOnHostDidWake = false;
	mIsPcapInProgress = false;
	mLastHeader = 0;
	mLastTID = 0;
	mNetworkKeyIndex = 0;
	mOutboundBufferEscapedLen = 0;
	mOutboundBufferLen = 0;
	mOutboundBufferSent = 0;
	mOutboundBufferType = 0;
	mResetIsExpected = false;
	mSetSteeringDataWhenJoinable = false;
	mSubPTIndex = 0;
	mTXPower = 0;
	mThreadMode = 0;
	mXPANIDWasExplicitlySet = false;
	mChannelManagerNewChannel = 0;

	mSupprotedChannels.clear();
	mSettings.clear();

	memset(mSteeringDataAddress, 0xff, sizeof(mSteeringDataAddress));

	if (!settings.empty()) {
		int status;
		Settings::const_iterator iter;

		for(iter = settings.begin(); iter != settings.end(); iter++) {
			if (!NCPInstanceBase::setup_property_supported_by_class(iter->first)) {
				status = static_cast<NCPControlInterface&>(get_control_interface())
					.property_set_value(iter->first, iter->second);

				if (status != 0) {
					syslog(LOG_WARNING, "Attempt to set property \"%s\" failed with err %d", iter->first.c_str(), status);
				}
			}
		}
	}
}

SpinelNCPInstance::~SpinelNCPInstance()
{
}

std::string
SpinelNCPInstance::thread_mode_to_string(uint8_t mode)
{
	char c_string[400];

	snprintf(
		c_string,
		sizeof(c_string),
		"RxOnWhenIdle:%s FFD:%s FullNetData:%s SecDataReq:%s",
		((mode & SPINEL_THREAD_MODE_RX_ON_WHEN_IDLE) != 0)     ? "yes" : "no",
		((mode & SPINEL_THREAD_MODE_FULL_FUNCTION_DEV) != 0)   ? "yes" : "no",
		((mode & SPINEL_THREAD_MODE_FULL_NETWORK_DATA) != 0)   ? "yes" : "no",
		((mode & SPINEL_THREAD_MODE_SECURE_DATA_REQUEST) != 0) ? "yes" : "no"
	);

	return c_string;
}

uint8_t
SpinelNCPInstance::get_thread_mode(void)
{
	return mThreadMode;
}

bool
SpinelNCPInstance::setup_property_supported_by_class(const std::string& prop_name)
{
	return NCPInstanceBase::setup_property_supported_by_class(prop_name);
}

SpinelNCPControlInterface&
SpinelNCPInstance::get_control_interface()
{
	return mControlInterface;
}

uint32_t
SpinelNCPInstance::get_default_channel_mask(void)
{
	uint32_t channel_mask = 0;
	uint16_t i;

	for (i = 0; i < 32; i++) {
		if (mSupprotedChannels.find(i) != mSupprotedChannels.end()) {
			channel_mask |= (1 << i);
		}
	}

	return channel_mask;
}

std::set<std::string>
SpinelNCPInstance::get_supported_property_keys()const
{
	std::set<std::string> properties (NCPInstanceBase::get_supported_property_keys());

	properties.insert(kWPANTUNDProperty_ConfigNCPDriverName);
	properties.insert(kWPANTUNDProperty_NCPChannel);
	properties.insert(kWPANTUNDProperty_NCPChannelMask);
	properties.insert(kWPANTUNDProperty_NCPFrequency);
	properties.insert(kWPANTUNDProperty_NCPRSSI);
	properties.insert(kWPANTUNDProperty_NCPExtendedAddress);
	properties.insert(kWPANTUNDProperty_NCPCCAFailureRate);

	if (mCapabilities.count(SPINEL_CAP_ROLE_SLEEPY)) {
		properties.insert(kWPANTUNDProperty_NCPSleepyPollInterval);
	}

	if (mCapabilities.count(SPINEL_CAP_NET_THREAD_1_0)) {
		properties.insert(kWPANTUNDProperty_ThreadRLOC16);
		properties.insert(kWPANTUNDProperty_ThreadDeviceMode);
		properties.insert(kWPANTUNDProperty_ThreadRouterID);
		properties.insert(kWPANTUNDProperty_ThreadLeaderAddress);
		properties.insert(kWPANTUNDProperty_ThreadLeaderRouterID);
		properties.insert(kWPANTUNDProperty_ThreadLeaderWeight);
		properties.insert(kWPANTUNDProperty_ThreadLeaderLocalWeight);
		properties.insert(kWPANTUNDProperty_ThreadNetworkData);
		properties.insert(kWPANTUNDProperty_ThreadNetworkDataVersion);
		properties.insert(kWPANTUNDProperty_ThreadStableNetworkData);
		properties.insert(kWPANTUNDProperty_ThreadStableNetworkDataVersion);
		properties.insert(kWPANTUNDProperty_ThreadLeaderNetworkData);
		properties.insert(kWPANTUNDProperty_ThreadStableLeaderNetworkData);
		properties.insert(kWPANTUNDProperty_ThreadChildTable);
		properties.insert(kWPANTUNDProperty_ThreadChildTableAddresses);
		properties.insert(kWPANTUNDProperty_ThreadNeighborTable);
		properties.insert(kWPANTUNDProperty_ThreadRouterTable);
		properties.insert(kWPANTUNDProperty_ThreadCommissionerEnabled);
		properties.insert(kWPANTUNDProperty_ThreadOffMeshRoutes);
		properties.insert(kWPANTUNDProperty_NetworkPartitionId);
		properties.insert(kWPANTUNDProperty_ThreadActiveDataset);
		properties.insert(kWPANTUNDProperty_ThreadPendingDataset);

		if (mCapabilities.count(SPINEL_CAP_ERROR_RATE_TRACKING)) {
			properties.insert(kWPANTUNDProperty_ThreadNeighborTableErrorRates);
		}
	}

	if (mCapabilities.count(SPINEL_CAP_COUNTERS)) {
		properties.insert(kWPANTUNDProperty_NCPCounterAllMac);
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_IP_SEC_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_IP_INSEC_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_IP_DROPPED");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_IP_SEC_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_IP_INSEC_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_IP_DROPPED");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_SPINEL_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_SPINEL_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_SPINEL_ERR");
	}

	if (mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
		properties.insert(kWPANTUNDProperty_MACWhitelistEnabled);
		properties.insert(kWPANTUNDProperty_MACWhitelistEntries);
		properties.insert(kWPANTUNDProperty_MACBlacklistEnabled);
		properties.insert(kWPANTUNDProperty_MACBlacklistEntries);
	}

	if (mCapabilities.count(SPINEL_CAP_JAM_DETECT)) {
		properties.insert(kWPANTUNDProperty_JamDetectionStatus);
		properties.insert(kWPANTUNDProperty_JamDetectionEnable);
		properties.insert(kWPANTUNDProperty_JamDetectionRssiThreshold);
		properties.insert(kWPANTUNDProperty_JamDetectionWindow);
		properties.insert(kWPANTUNDProperty_JamDetectionBusyPeriod);
		properties.insert(kWPANTUNDProperty_JamDetectionDebugHistoryBitmap);
	}

	if (mCapabilities.count(SPINEL_CAP_CHANNEL_MONITOR)) {
		properties.insert(kWPANTUNDProperty_ChannelMonitorSampleInterval);
		properties.insert(kWPANTUNDProperty_ChannelMonitorRssiThreshold);
		properties.insert(kWPANTUNDProperty_ChannelMonitorSampleWindow);
		properties.insert(kWPANTUNDProperty_ChannelMonitorSampleCount);
		properties.insert(kWPANTUNDProperty_ChannelMonitorChannelQuality);
	}

	if (mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
		properties.insert(kWPANTUNDProperty_ChannelManagerNewChannel);
		properties.insert(kWPANTUNDProperty_ChannelManagerDelay);
		properties.insert(kWPANTUNDProperty_ChannelManagerAutoSelectEnabled);
		properties.insert(kWPANTUNDProperty_ChannelManagerAutoSelectInterval);
		properties.insert(kWPANTUNDProperty_ChannelManagerSupportedChannelMask);
		properties.insert(kWPANTUNDProperty_ChannelManagerFavoredChannelMask);
	}

	if (mCapabilities.count(SPINEL_CAP_THREAD_TMF_PROXY)) {
		properties.insert(kWPANTUNDProperty_TmfProxyEnabled);
	}

	if (mCapabilities.count(SPINEL_CAP_NEST_LEGACY_INTERFACE))
	{
		properties.insert(kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix);
	}

	{
		const std::set<std::string> vendor_props(mVendorCustom.get_supported_property_keys());
		properties.insert(vendor_props.begin(), vendor_props.end());
	}

	return properties;
}

cms_t
SpinelNCPInstance::get_ms_to_next_event(void)
{
	cms_t cms = NCPInstanceBase::get_ms_to_next_event();

	if (ncp_state_is_detached_from_ncp(get_ncp_state())) {
		return CMS_DISTANT_FUTURE;
	}

	// If the control protothread hasn't even started, set cms to zero.
	if (0 == mControlPT.lc) {
		cms = 0;
	}

	if (!mTaskQueue.empty()) {
		int tmp_cms = mTaskQueue.front()->get_ms_to_next_event();
		if (tmp_cms < cms) {
			cms = tmp_cms;
		}
	}

	if (cms > mVendorCustom.get_ms_to_next_event()) {
		cms = mVendorCustom.get_ms_to_next_event();
	}

	if (cms < 0) {
		cms = 0;
	}

	return cms;
}

static void
convert_rloc16_to_router_id(CallbackWithStatusArg1 cb, int status, const boost::any& value)
{
	uint8_t router_id = 0;

	if (status == kWPANTUNDStatus_Ok) {
		uint16_t rloc16 = any_to_int(value);
		router_id = rloc16 >> 10;
	}
	cb(status, router_id);
}

static int
unpack_channel_mask(const uint8_t *data_in, spinel_size_t data_len, boost::any& value)
{
	spinel_ssize_t len;
	uint32_t channel_mask = 0;
	uint8_t channel = 0xff;
	int ret = kWPANTUNDStatus_Ok;

	while (data_len > 0)
	{
		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_UINT8_S,
			&channel
		);

		if ((len <= 0) || (channel >= 32)) {
			ret = kWPANTUNDStatus_Failure;
			break;
		}

		channel_mask |= (1U << channel);

		data_in += len;
		data_len -= len;
	}

	if (ret == kWPANTUNDStatus_Ok) {
		value = channel_mask;
	}

	return ret;
}

static int
unpack_mac_whitelist_entries(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	spinel_ssize_t len;
	ValueMap entry;
	std::list<ValueMap> result_as_val_map;
	std::list<std::string> result_as_string;
	const spinel_eui64_t *eui64 = NULL;
	int8_t rssi = 0;

	int ret = kWPANTUNDStatus_Ok;

	while (data_len > 0)
	{
		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_EUI64_S   // Extended address
				SPINEL_DATATYPE_INT8_S    // Rssi
			),
			&eui64,
			&rssi
		);

		if (len <= 0)
		{
			ret = kWPANTUNDStatus_Failure;
			break;
		}

		if (as_val_map) {
			entry.clear();
			entry[kWPANTUNDValueMapKey_Whitelist_ExtAddress] = Data(eui64->bytes, sizeof(spinel_eui64_t));

			if (rssi != kWPANTUND_Whitelist_RssiOverrideDisabled) {
				entry[kWPANTUNDValueMapKey_Whitelist_Rssi] = rssi;
			}

			result_as_val_map.push_back(entry);

		} else {
			char c_string[500];
			int index;

			index = snprintf(c_string, sizeof(c_string), "%02X%02X%02X%02X%02X%02X%02X%02X",
							 eui64->bytes[0], eui64->bytes[1], eui64->bytes[2], eui64->bytes[3],
							 eui64->bytes[4], eui64->bytes[5], eui64->bytes[6], eui64->bytes[7]);

			if (rssi != kWPANTUND_Whitelist_RssiOverrideDisabled) {
				if (index >= 0 && index < sizeof(c_string)) {
					snprintf(c_string + index, sizeof(c_string) - index, "   fixed-rssi:%d", rssi);
				}
			}

			result_as_string.push_back(std::string(c_string));
		}

		data_len -= len;
		data_in += len;
	}

	if (ret == kWPANTUNDStatus_Ok) {

		if (as_val_map) {
			value = result_as_val_map;
		} else {
			value = result_as_string;
		}
	}

	return ret;
}

static int
unpack_mac_blacklist_entries(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	spinel_ssize_t len;
	ValueMap entry;
	std::list<ValueMap> result_as_val_map;
	std::list<std::string> result_as_string;
	const spinel_eui64_t *eui64 = NULL;

	int ret = kWPANTUNDStatus_Ok;

	while (data_len > 0)
	{
		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_EUI64_S   // Extended address
			),
			&eui64
		);

		if (len <= 0)
		{
			ret = kWPANTUNDStatus_Failure;
			break;
		}

		if (as_val_map) {
			entry.clear();
			entry[kWPANTUNDValueMapKey_Whitelist_ExtAddress] = Data(eui64->bytes, sizeof(spinel_eui64_t));
			result_as_val_map.push_back(entry);

		} else {
			char c_string[500];
			int index;

			index = snprintf(c_string, sizeof(c_string), "%02X%02X%02X%02X%02X%02X%02X%02X",
							 eui64->bytes[0], eui64->bytes[1], eui64->bytes[2], eui64->bytes[3],
							 eui64->bytes[4], eui64->bytes[5], eui64->bytes[6], eui64->bytes[7]);

			result_as_string.push_back(std::string(c_string));
		}

		data_len -= len;
		data_in += len;
	}

	if (ret == kWPANTUNDStatus_Ok) {

		if (as_val_map) {
			value = result_as_val_map;
		} else {
			value = result_as_string;
		}
	}

	return ret;
}

static int
unpack_channel_monitor_channel_quality(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	std::list<std::string> result_as_string;
	std::list<ValueMap> result_as_val_map;
	int ret = kWPANTUNDStatus_Ok;

	while (data_len > 0)
	{
		spinel_ssize_t len;
		uint8_t channel;
		uint16_t quality;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_UINT8_S         // Channel
				SPINEL_DATATYPE_UINT16_S        // Quality
			),
			&channel,
			&quality
		);

		require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		if (!as_val_map) {
			char c_string[100];

			snprintf(c_string, sizeof(c_string), "ch %d (0x%04x) %.2f%% busy ", channel, quality,
				static_cast<double>(quality) * 100.0 / 0xffff);

			result_as_string.push_back(std::string(c_string));
		} else {
			ValueMap entry;

			entry[kWPANTUNDValueMapKey_ChannelMonitor_Channel] = boost::any((int)channel);
			entry[kWPANTUNDValueMapKey_ChannelMonitor_Quality] = boost::any((int)quality);
			result_as_val_map.push_back(entry);
		}

		data_in += len;
		data_len -= len;
	}

	if (as_val_map) {
		value = result_as_val_map;
	} else {
		value = result_as_string;
	}

bail:
	return ret;
}

static int
unpack_ncp_counters_all_mac(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	std::list<std::string> result_as_string;
	ValueMap result_as_val_map;
	int ret = kWPANTUNDStatus_Ok;
	spinel_ssize_t len;

	const char *tx_counter_names[] = {
		kWPANTUNDValueMapKey_Counter_TxTotal,
		kWPANTUNDValueMapKey_Counter_TxUnicast,
		kWPANTUNDValueMapKey_Counter_TxBroadcast,
		kWPANTUNDValueMapKey_Counter_TxAckRequested,
		kWPANTUNDValueMapKey_Counter_TxAcked,
		kWPANTUNDValueMapKey_Counter_TxNoAckRequested,
		kWPANTUNDValueMapKey_Counter_TxData,
		kWPANTUNDValueMapKey_Counter_TxDataPoll,
		kWPANTUNDValueMapKey_Counter_TxBeacon,
		kWPANTUNDValueMapKey_Counter_TxBeaconRequest,
		kWPANTUNDValueMapKey_Counter_TxOther,
		kWPANTUNDValueMapKey_Counter_TxRetry,
		kWPANTUNDValueMapKey_Counter_TxErrCca,
		kWPANTUNDValueMapKey_Counter_TxErrAbort,
		kWPANTUNDValueMapKey_Counter_TxErrBusyChannel,
		NULL
	};

	const char *rx_counter_names[] = {
		kWPANTUNDValueMapKey_Counter_RxTotal,
		kWPANTUNDValueMapKey_Counter_RxUnicast,
		kWPANTUNDValueMapKey_Counter_RxBroadcast,
		kWPANTUNDValueMapKey_Counter_RxData,
		kWPANTUNDValueMapKey_Counter_RxDataPoll,
		kWPANTUNDValueMapKey_Counter_RxBeacon,
		kWPANTUNDValueMapKey_Counter_RxBeaconRequest,
		kWPANTUNDValueMapKey_Counter_RxOther,
		kWPANTUNDValueMapKey_Counter_RxAddressFiltered,
		kWPANTUNDValueMapKey_Counter_RxDestAddrFiltered,
		kWPANTUNDValueMapKey_Counter_RxDuplicated,
		kWPANTUNDValueMapKey_Counter_RxErrNoFrame,
		kWPANTUNDValueMapKey_Counter_RxErrUnknownNeighbor,
		kWPANTUNDValueMapKey_Counter_RxErrInvalidSrcAddr,
		kWPANTUNDValueMapKey_Counter_RxErrSec,
		kWPANTUNDValueMapKey_Counter_RxErrFcs,
		kWPANTUNDValueMapKey_Counter_RxErrOther,
		NULL
	};

	for (int struct_index = 0; struct_index < 2; struct_index++)
	{
		const char **counter_names;
		const uint8_t *struct_in = NULL;
		unsigned int struct_len = 0;
		spinel_size_t len;

		counter_names = (struct_index == 0) ? tx_counter_names : rx_counter_names;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_DATA_WLEN_S,
			&struct_in,
			&struct_len
		);

		require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		data_in += len;
		data_len -= len;

		while (*counter_names != NULL) {
			uint32_t counter_value;

			len = spinel_datatype_unpack(
				struct_in,
				struct_len,
				SPINEL_DATATYPE_UINT32_S,
				&counter_value
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

			struct_in  += len;
			struct_len -= len;

			if (!as_val_map) {
				char c_string[200];
				snprintf(c_string, sizeof(c_string), "%-20s = %d", *counter_names, counter_value);
				result_as_string.push_back(std::string(c_string));
			} else {
				result_as_val_map[*counter_names] = counter_value;
			}

			counter_names++;
		}
	}

	if (as_val_map) {
		value = result_as_val_map;
	} else {
		value = result_as_string;
	}

bail:
	return ret;
}

static int
unpack_jam_detect_history_bitmap(const uint8_t *data_in, spinel_size_t data_len, boost::any& value)
{
	spinel_ssize_t len;
	uint32_t lower, higher;
	uint64_t val;
	int ret = kWPANTUNDStatus_Failure;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		SPINEL_DATATYPE_UINT32_S SPINEL_DATATYPE_UINT32_S,
		&lower,
		&higher
	);

	if (len > 0)
	{
		ret = kWPANTUNDStatus_Ok;
		value = (static_cast<uint64_t>(higher) << 32) + static_cast<uint64_t>(lower);
	}

	return ret;
}

static int
unpack_mcu_power_state(const uint8_t *data_in, spinel_size_t data_len, boost::any& value)
{
	spinel_ssize_t len;
	uint8_t power_state;
	int ret = kWPANTUNDStatus_Ok;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		SPINEL_DATATYPE_UINT8_S,
		&power_state
	);

	require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

	switch (power_state)
	{
	case SPINEL_MCU_POWER_STATE_ON:
		value = std::string(kWPANTUNDNCPMCUPowerState_On);
		break;

	case SPINEL_MCU_POWER_STATE_LOW_POWER:
		value = std::string(kWPANTUNDNCPMCUPowerState_LowPower);
		break;

	case SPINEL_MCU_POWER_STATE_OFF:
		value = std::string(kWPANTUNDNCPMCUPowerState_Off);
		break;

	default:
		value = std::string("unknown");
		break;
	}

bail:
	return ret;
}

static int
convert_string_to_spinel_mcu_power_state(const char *str, spinel_mcu_power_state_t &power_state)
{
	int ret = kWPANTUNDStatus_Ok;

	if (strcaseequal(str, kWPANTUNDNCPMCUPowerState_On)) {
		power_state = SPINEL_MCU_POWER_STATE_ON;

	} else if (strcaseequal(str, kWPANTUNDNCPMCUPowerState_LowPower) || strcaseequal(str, "lp")) {
		power_state = SPINEL_MCU_POWER_STATE_LOW_POWER;

	} else if (strcaseequal(str, "kWPANTUNDNCPMCUPowerState_Off")) {
		power_state = SPINEL_MCU_POWER_STATE_OFF;

	} else {
		ret = kWPANTUNDStatus_InvalidArgument;
	}

	return ret;
}

static int
unpack_dataset(const uint8_t *data_in, spinel_size_t data_len, boost::any &value, bool as_val_map)
{
	int ret = kWPANTUNDStatus_Ok;
	ThreadDataset dataset;
	ValueMap map;
	std::list<std::string> list;

	ret = dataset.set_from_spinel_frame(data_in, data_len);
	require_noerr(ret, bail);

	if (as_val_map) {
		dataset.convert_to_valuemap(map);
		value = map;
	} else {
		dataset.convert_to_string_list(list);
		value = list;
	}

bail:
	return ret;
}

void
SpinelNCPInstance::get_dataset_command_help(std::list<std::string> &list)
{
	list.clear();
	list.push_back("List of valid commands:");
	list.push_back("   - `" kWPANTUNDDatasetCommand_Erase "`: Erase the local Dataset (all fields are un-set)");
	list.push_back("   - `" kWPANTUNDDatasetCommand_GetActive "`: Get the NCP's Active Operational Dataset and populate the local Dataset from it");
	list.push_back("   - `" kWPANTUNDDatasetCommand_SetActive "`: Set the NCP's Active Operational Dataset from the current local Dataset");
	list.push_back("   - `" kWPANTUNDDatasetCommand_MgmtSendActive "`: Send the current local Dataset to leader with a MGMT_SEND_ACTIVE meshcop command");
	list.push_back("   - `" kWPANTUNDDatasetCommand_GetPending "`: Get the NCP's Pending Operational Dataset and populate the local DataSet from it");
	list.push_back("   - `" kWPANTUNDDatasetCommand_SetPending "`: Set the NCP's Pending Operational Dataset from the current local Dataset");
	list.push_back("   - `" kWPANTUNDDatasetCommand_MgmtSendPending "`: Send the current local Dataset to leader with MGMT_SEND_PENDING meshcop command");
}

int
SpinelNCPInstance::unpack_and_set_local_dataset(const uint8_t *data_in, spinel_size_t data_len)
{
	return mLocalDataset.set_from_spinel_frame(data_in, data_len);
}

void
SpinelNCPInstance::perform_dataset_command(const std::string &command, CallbackWithStatus cb)
{
	if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_Erase)) {
		mLocalDataset.clear();
		cb(kWPANTUNDStatus_Ok);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_GetActive)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_ACTIVE_DATASET)
			)
			.set_reply_unpacker(boost::bind(&SpinelNCPInstance::unpack_and_set_local_dataset, this, _1, _2))
			.finish()
		);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SetActive)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
					SPINEL_PROP_THREAD_ACTIVE_DATASET,
					frame.data(),
					frame.size()
				)
			)
			.finish()
		);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_MgmtSendActive)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
					SPINEL_PROP_THREAD_MGMT_ACTIVE_DATASET,
					frame.data(),
					frame.size()
				)
			)
			.finish()
		);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_GetPending)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_PENDING_DATASET)
			)
			.set_reply_unpacker(boost::bind(&SpinelNCPInstance::unpack_and_set_local_dataset, this, _1, _2))
			.finish()
		);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SetPending)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
					SPINEL_PROP_THREAD_PENDING_DATASET,
					frame.data(),
					frame.size()
				)
			)
			.finish()
		);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_MgmtSendPending)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
					SPINEL_PROP_THREAD_MGMT_PENDING_DATASET,
					frame.data(),
					frame.size()
				)
			)
			.finish()
		);

	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::update_node_type(NodeType new_node_type)
{
	if (mNodeType != new_node_type) {
		syslog(
			LOG_NOTICE,
			"Node type change: \"%s\" -> \"%s\"",
			node_type_to_string(mNodeType).c_str(),
			node_type_to_string(new_node_type).c_str()
		);

		mNodeType = new_node_type;
		signal_property_changed(kWPANTUNDProperty_NetworkNodeType, node_type_to_string(mNodeType));
	}
}

void
SpinelNCPInstance::update_link_local_address(struct in6_addr *addr)
{
	if (NULL != addr
	  && (0 != memcmp(mNCPLinkLocalAddress.s6_addr, addr->s6_addr, sizeof(mNCPLinkLocalAddress)))
	) {
		memcpy((void*)mNCPLinkLocalAddress.s6_addr, (void*)addr->s6_addr, sizeof(mNCPLinkLocalAddress));
		signal_property_changed(kWPANTUNDProperty_IPv6LinkLocalAddress, in6_addr_to_string(*addr));
	}
}

void
SpinelNCPInstance::update_mesh_local_address(struct in6_addr *addr)
{
	if (addr
	 && buffer_is_nonzero(addr->s6_addr, 8)
	 && (0 != memcmp(mNCPMeshLocalAddress.s6_addr, addr->s6_addr, sizeof(mNCPMeshLocalAddress)))
	) {
		memcpy((void*)mNCPMeshLocalAddress.s6_addr, (void*)addr->s6_addr, sizeof(mNCPMeshLocalAddress));
		signal_property_changed(kWPANTUNDProperty_IPv6MeshLocalAddress, in6_addr_to_string(*addr));

		// If mesh-local prefix gets changed we go through the
		// list of IPv6 addresses and filter/remove any previously
		// added RLOC addresses.
		filter_addresses();
	}
}

void
SpinelNCPInstance::update_mesh_local_prefix(struct in6_addr *addr)
{
	if (addr
	 && buffer_is_nonzero(addr->s6_addr, 8)
	 && (0 != memcmp(mNCPV6Prefix, addr, sizeof(mNCPV6Prefix)))
	) {
		memcpy((void*)mNCPV6Prefix, (void*)addr, sizeof(mNCPV6Prefix));
		struct in6_addr prefix_addr (mNCPMeshLocalAddress);
		// Zero out the lower 64 bits.
		memset(prefix_addr.s6_addr+8, 0, 8);
		signal_property_changed(kWPANTUNDProperty_IPv6MeshLocalPrefix, in6_addr_to_string(prefix_addr) + "/64");

		// If mesh-local prefix gets changed we go through the
		// list of IPv6 addresses and filter/remove any previously
		// added RLOC addresses.
		filter_addresses();
	}
}

void
SpinelNCPInstance::property_get_value(
	const std::string& key,
	CallbackWithStatusArg1 cb
) {
	if (!is_initializing_ncp()) {
		syslog(LOG_INFO, "property_get_value: key: \"%s\"", key.c_str());
	}

#define SIMPLE_SPINEL_GET(prop__, type__)                                \
	start_new_task(SpinelNCPTaskSendCommand::Factory(this)               \
		.set_callback(cb)                                                \
		.add_command(                                                    \
			SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, prop__) \
		)                                                                \
		.set_reply_format(type__)                                        \
		.finish()                                                        \
	)

	if (strcaseequal(key.c_str(), kWPANTUNDProperty_ConfigNCPDriverName)) {
		cb(0, boost::any(std::string("spinel")));

	} else if (mVendorCustom.is_property_key_supported(key)) {
		mVendorCustom.property_get_value(key, cb);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPChannelMask)) {
		cb(0, boost::any(get_default_channel_mask()));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPCCAThreshold)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_PHY_CCA_THRESHOLD, SPINEL_DATATYPE_INT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPTXPower)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_PHY_TX_POWER, SPINEL_DATATYPE_INT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPFrequency)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_PHY_FREQ, SPINEL_DATATYPE_INT32_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKey)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_NET_MASTER_KEY, SPINEL_DATATYPE_DATA_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkPSKc)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_NET_PSKC, SPINEL_DATATYPE_DATA_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPExtendedAddress)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_MAC_EXTENDED_ADDR, SPINEL_DATATYPE_EUI64_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPSleepyPollInterval)) {
		if (!mCapabilities.count(SPINEL_CAP_ROLE_SLEEPY)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Sleepy role is not supported by NCP")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_MAC_DATA_POLL_PERIOD, SPINEL_DATATYPE_UINT32_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPMCUPowerState)) {
		if (!mCapabilities.count(SPINEL_CAP_MCU_POWER_STATE)) {
			cb(kWPANTUNDStatus_FeatureNotSupported,
				boost::any(std::string("Getting MCU power state is not supported by NCP")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MCU_POWER_STATE)
				)
				.set_reply_unpacker(unpack_mcu_power_state)
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKeyIndex)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_NET_KEY_SEQUENCE_COUNTER, SPINEL_DATATYPE_UINT32_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkIsCommissioned)) {
		cb(kWPANTUNDStatus_Ok, boost::any(mIsCommissioned));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkRole)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_NET_ROLE, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkPartitionId)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_NET_PARTITION_ID, SPINEL_DATATYPE_UINT32_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPRSSI)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_PHY_RSSI, SPINEL_DATATYPE_INT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadRLOC16)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_RLOC16, SPINEL_DATATYPE_UINT16_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadRouterID)) {
		cb = boost::bind(convert_rloc16_to_router_id, cb, _1, _2);
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_RLOC16, SPINEL_DATATYPE_UINT16_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderAddress)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_LEADER_ADDR, SPINEL_DATATYPE_IPv6ADDR_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderRouterID)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_LEADER_RID, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderWeight)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_LEADER_WEIGHT, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderLocalWeight)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_LOCAL_LEADER_WEIGHT, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNetworkData)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNetworkDataVersion)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_NETWORK_DATA_VERSION, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadStableNetworkData)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_STABLE_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderNetworkData)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_LEADER_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadStableLeaderNetworkData)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_STABLE_LEADER_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadStableNetworkDataVersion)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_STABLE_NETWORK_DATA_VERSION, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadCommissionerEnabled)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_COMMISSIONER_ENABLED, SPINEL_DATATYPE_BOOL_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadRouterRoleEnabled)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_ROUTER_ROLE_ENABLED, SPINEL_DATATYPE_BOOL_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadDeviceMode)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_MODE, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadConfigFilterRLOCAddresses)) {
		cb(kWPANTUNDStatus_Ok, boost::any(mFilterRLOCAddresses));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadActiveDataset)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_ACTIVE_DATASET)
			)
			.set_reply_unpacker(boost::bind(unpack_dataset, _1, _2, _3, false))
			.finish()
		);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadActiveDatasetAsValMap)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_ACTIVE_DATASET)
			)
			.set_reply_unpacker(boost::bind(unpack_dataset, _1, _2, _3, true))
			.finish()
		);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadPendingDataset)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_PENDING_DATASET)
			)
			.set_reply_unpacker(boost::bind(unpack_dataset, _1, _2, _3, false))
			.finish()
		);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadPendingDatasetAsValMap)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_PENDING_DATASET)
			)
			.set_reply_unpacker(boost::bind(unpack_dataset, _1, _2, _3, true))
			.finish()
		);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_IPv6MeshLocalPrefix) && !buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix))) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_IPV6_ML_PREFIX, SPINEL_DATATYPE_IPv6ADDR_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_IPv6MeshLocalAddress) && !buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix))) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_IPV6_ML_ADDR, SPINEL_DATATYPE_IPv6ADDR_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_IPv6LinkLocalAddress) && !IN6_IS_ADDR_LINKLOCAL(&mNCPLinkLocalAddress)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_IPV6_LL_ADDR, SPINEL_DATATYPE_IPv6ADDR_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadDebugTestAssert)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_DEBUG_TEST_ASSERT, SPINEL_DATATYPE_BOOL_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadDebugTestWatchdog)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_DEBUG_TEST_WATCHDOG, SPINEL_DATATYPE_BOOL_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACWhitelistEnabled)) {
		if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("MAC whitelist feature not supported by NCP")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_MAC_WHITELIST_ENABLED, SPINEL_DATATYPE_BOOL_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACWhitelistEntries)) {
		if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("MAC whitelist feature not supported by NCP")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_WHITELIST)
				)
				.set_reply_unpacker(boost::bind(unpack_mac_whitelist_entries, _1, _2, _3, false))
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACWhitelistEntriesAsValMap)) {
		if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("MAC whitelist feature not supported by NCP")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_WHITELIST)
				)
				.set_reply_unpacker(boost::bind(unpack_mac_whitelist_entries, _1, _2, _3, true))
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACBlacklistEntries)) {
		if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("MAC blacklist feature not supported by NCP")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_BLACKLIST)
				)
				.set_reply_unpacker(boost::bind(unpack_mac_blacklist_entries, _1, _2, _3, false))
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACBlacklistEntriesAsValMap)) {
		if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("MAC blacklist feature not supported by NCP")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_BLACKLIST)
				)
				.set_reply_unpacker(boost::bind(unpack_mac_blacklist_entries, _1, _2, _3, true))
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACBlacklistEnabled)) {
		if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("MAC Blacklist feature not supported by NCP")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_MAC_BLACKLIST_ENABLED, SPINEL_DATATYPE_BOOL_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionStatus)) {
		if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Jam Detection Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_JAM_DETECTED, SPINEL_DATATYPE_BOOL_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_TmfProxyEnabled)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_THREAD_TMF_PROXY_ENABLED, SPINEL_DATATYPE_BOOL_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionEnable)) {
		if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Jam Detection Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_JAM_DETECT_ENABLE, SPINEL_DATATYPE_BOOL_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionRssiThreshold)) {
		if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Jam Detection Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_JAM_DETECT_RSSI_THRESHOLD, SPINEL_DATATYPE_INT8_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionWindow)) {
		if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Jam Detection Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_JAM_DETECT_WINDOW, SPINEL_DATATYPE_UINT8_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionBusyPeriod)) {
		if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Jam Detection Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_JAM_DETECT_BUSY, SPINEL_DATATYPE_UINT8_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionDebugHistoryBitmap)) {
		if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Jam Detection Feature Not Supported")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_JAM_DETECT_HISTORY_BITMAP)
				)
				.set_reply_unpacker(unpack_jam_detect_history_bitmap)
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPCCAFailureRate)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_MAC_CCA_FAILURE_RATE, SPINEL_DATATYPE_UINT16_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelMonitorSampleInterval)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MONITOR)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MONITOR_SAMPLE_INTERVAL, SPINEL_DATATYPE_UINT32_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelMonitorRssiThreshold)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MONITOR)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MONITOR_RSSI_THRESHOLD, SPINEL_DATATYPE_INT8_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelMonitorSampleWindow)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MONITOR)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MONITOR_SAMPLE_WINDOW, SPINEL_DATATYPE_UINT32_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelMonitorSampleCount)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MONITOR)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MONITOR_SAMPLE_COUNT, SPINEL_DATATYPE_UINT32_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelMonitorChannelQuality)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MONITOR)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_CHANNEL_MONITOR_CHANNEL_OCCUPANCY)
				)
				.set_reply_unpacker(boost::bind(unpack_channel_monitor_channel_quality, _1, _2, _3, false))
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelMonitorChannelQualityAsValMap)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MONITOR)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_CHANNEL_MONITOR_CHANNEL_OCCUPANCY)
				)
				.set_reply_unpacker(boost::bind(unpack_channel_monitor_channel_quality, _1, _2, _3, true))
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerNewChannel)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Manager Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MANAGER_NEW_CHANNEL, SPINEL_DATATYPE_UINT8_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerDelay)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Manager Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MANAGER_DELAY, SPINEL_DATATYPE_UINT16_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerAutoSelectEnabled)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Manager Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_ENABLED, SPINEL_DATATYPE_BOOL_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerAutoSelectInterval)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Manager Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_INTERVAL, SPINEL_DATATYPE_UINT32_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerChannelSelect)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Manager Feature Not Supported")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_CHANNEL_MANAGER_CHANNEL_SELECT, SPINEL_DATATYPE_BOOL_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerSupportedChannelMask)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Manager Feature Not Supported")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_CHANNEL_MANAGER_SUPPORTED_CHANNELS)
				)
				.set_reply_unpacker(unpack_channel_mask)
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerFavoredChannelMask)) {
		if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Manager Feature Not Supported")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_CHANNEL_MANAGER_FAVORED_CHANNELS)
				)
				.set_reply_unpacker(unpack_channel_mask)
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix)) {
		if (!mCapabilities.count(SPINEL_CAP_NEST_LEGACY_INTERFACE)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Legacy Capability Not Supported by NCP")));
		} else {
			SIMPLE_SPINEL_GET(SPINEL_PROP_NEST_LEGACY_ULA_PREFIX, SPINEL_DATATYPE_DATA_S);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadChildTable)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetNetworkTopology(
				this,
				cb,
				SpinelNCPTaskGetNetworkTopology::kChildTable,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
			)
		));
	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadChildTableAsValMap)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetNetworkTopology(
				this,
				cb,
				SpinelNCPTaskGetNetworkTopology::kChildTable,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadChildTableAddresses)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetNetworkTopology(
				this,
				cb,
				SpinelNCPTaskGetNetworkTopology::kChildTableAddresses,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNeighborTable)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetNetworkTopology(
				this,
				cb,
				SpinelNCPTaskGetNetworkTopology::kNeighborTable,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNeighborTableAsValMap)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetNetworkTopology(
				this,
				cb,
				SpinelNCPTaskGetNetworkTopology::kNeighborTable,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNeighborTableErrorRates)) {
		if (!mCapabilities.count(SPINEL_CAP_ERROR_RATE_TRACKING)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Error Rate Tracking Feature Not Supported")));
		} else {
			start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskGetNetworkTopology(
					this,
					cb,
					SpinelNCPTaskGetNetworkTopology::kNeighborTableErrorRates,
					SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
				)
			));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNeighborTableErrorRatesAsValMap)) {
		if (!mCapabilities.count(SPINEL_CAP_ERROR_RATE_TRACKING)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Error Rate Tracking Feature Not Supported")));
		} else {
			start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskGetNetworkTopology(
					this,
					cb,
					SpinelNCPTaskGetNetworkTopology::kNeighborTableErrorRates,
					SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
				)
			));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadRouterTable)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetNetworkTopology(
				this,
				cb,
				SpinelNCPTaskGetNetworkTopology::kRouterTable,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadRouterTableAsValMap)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetNetworkTopology(
				this,
				cb,
				SpinelNCPTaskGetNetworkTopology::kRouterTable,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadMsgBufferCounters)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetMsgBufferCounters(
				this,
				cb,
				SpinelNCPTaskGetMsgBufferCounters::kResultFormat_StringArray
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadMsgBufferCountersAsString)) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskGetMsgBufferCounters(
				this,
				cb,
				SpinelNCPTaskGetMsgBufferCounters::kResultFormat_String
			)
		));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadLogLevel)) {
		SIMPLE_SPINEL_GET(SPINEL_PROP_DEBUG_NCP_LOG_LEVEL, SPINEL_DATATYPE_UINT8_S);

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadSteeringDataSetWhenJoinable)) {
		cb(0, boost::any(mSetSteeringDataWhenJoinable));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadSteeringDataAddress)) {
		cb(0, boost::any(nl::Data(mSteeringDataAddress, sizeof(mSteeringDataAddress))));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetActiveTimestamp)) {
		if (mLocalDataset.mActiveTimestamp.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mActiveTimestamp.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetPendingTimestamp)) {
		if (mLocalDataset.mPendingTimestamp.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mPendingTimestamp.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetMasterKey)) {
		if (mLocalDataset.mMasterKey.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mMasterKey.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetNetworkName)) {
		if (mLocalDataset.mNetworkName.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mNetworkName.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetExtendedPanId)) {
		if (mLocalDataset.mExtendedPanId.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mExtendedPanId.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetMeshLocalPrefix)) {
		if (mLocalDataset.mMeshLocalPrefix.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(in6_addr_to_string(mLocalDataset.mMeshLocalPrefix.get())));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetDelay)) {
		if (mLocalDataset.mDelay.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mDelay.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetPanId)) {
		if (mLocalDataset.mPanId.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mPanId.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetChannel)) {
		if (mLocalDataset.mChannel.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mChannel.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetPSKc)) {
		if (mLocalDataset.mPSKc.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mPSKc.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetChannelMaskPage0)) {
		if (mLocalDataset.mChannelMaskPage0.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mChannelMaskPage0.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetSecPolicyKeyRotation)) {
		if (mLocalDataset.mSecurityPolicy.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mSecurityPolicy.get().mKeyRotationTime));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetSecPolicyFlags)) {
		if (mLocalDataset.mSecurityPolicy.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mSecurityPolicy.get().mFlags));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetRawTlvs)) {
		if (mLocalDataset.mRawTlvs.has_value()) {
			cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mRawTlvs.get()));
		} else {
			cb(kWPANTUNDStatus_Ok, boost::any(Data()));
		}

	} else if ((strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetAllFileds)) ||
	           (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetAllFileds_AltString))
	) {
		std::list<std::string> list;
		mLocalDataset.convert_to_string_list(list);
		cb(kWPANTUNDStatus_Ok, boost::any(list));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetAllFiledsAsValMap)) {
		ValueMap map;
		mLocalDataset.convert_to_valuemap(map);
		cb(kWPANTUNDStatus_Ok, boost::any(map));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetCommand)) {
		std::list<std::string> help_string;
		get_dataset_command_help(help_string);
		cb(kWPANTUNDStatus_Ok, boost::any(help_string));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DaemonTickleOnHostDidWake)) {
		cb(kWPANTUNDStatus_Ok, boost::any(mTickleOnHostDidWake));

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPCounterAllMac)) {
		if (!mCapabilities.count(SPINEL_CAP_COUNTERS)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_CNTR_ALL_MAC_COUNTERS)
				)
				.set_reply_unpacker(boost::bind(unpack_ncp_counters_all_mac, _1, _2, _3, /* as_val_map */ false))
				.finish()
			);
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPCounterAllMacAsValMap)) {
		if (!mCapabilities.count(SPINEL_CAP_COUNTERS)) {
			cb(kWPANTUNDStatus_FeatureNotSupported, boost::any(std::string("Channel Monitoring Feature Not Supported")));
		} else {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_CNTR_ALL_MAC_COUNTERS)
				)
				.set_reply_unpacker(boost::bind(unpack_ncp_counters_all_mac, _1, _2, _3, /* as_val_map */ true))
				.finish()
			);
		}

	} else if (strncaseequal(key.c_str(), kWPANTUNDProperty_Spinel_CounterPrefix, sizeof(kWPANTUNDProperty_Spinel_CounterPrefix)-1)) {
		int cntr_key = 0;

#define CNTR_KEY(x)	\
	else if (strcaseequal(key.c_str()+sizeof(kWPANTUNDProperty_Spinel_CounterPrefix)-1, # x)) { \
		cntr_key = SPINEL_PROP_CNTR_ ## x; \
	}

		// Check to see if the counter name is an integer.
		cntr_key = (int)strtol(key.c_str()+(int)sizeof(kWPANTUNDProperty_Spinel_CounterPrefix)-1, NULL, 0);

		if ( (cntr_key > 0)
		  && (cntr_key < SPINEL_PROP_CNTR__END-SPINEL_PROP_CNTR__BEGIN)
		) {
			// Counter name was a valid integer. Let's use it.
			cntr_key += SPINEL_PROP_CNTR__BEGIN;
		}

		CNTR_KEY(TX_PKT_TOTAL)
		CNTR_KEY(TX_PKT_UNICAST)
		CNTR_KEY(TX_PKT_BROADCAST)
		CNTR_KEY(TX_PKT_ACK_REQ)
		CNTR_KEY(TX_PKT_ACKED)
		CNTR_KEY(TX_PKT_NO_ACK_REQ)
		CNTR_KEY(TX_PKT_DATA)
		CNTR_KEY(TX_PKT_DATA_POLL)
		CNTR_KEY(TX_PKT_BEACON)
		CNTR_KEY(TX_PKT_BEACON_REQ)
		CNTR_KEY(TX_PKT_OTHER)
		CNTR_KEY(TX_PKT_RETRY)
		CNTR_KEY(TX_ERR_CCA)
		CNTR_KEY(TX_ERR_ABORT)
		CNTR_KEY(RX_PKT_TOTAL)
		CNTR_KEY(RX_PKT_UNICAST)
		CNTR_KEY(RX_PKT_BROADCAST)
		CNTR_KEY(RX_PKT_DATA)
		CNTR_KEY(RX_PKT_DATA_POLL)
		CNTR_KEY(RX_PKT_BEACON)
		CNTR_KEY(RX_PKT_BEACON_REQ)
		CNTR_KEY(RX_PKT_OTHER)
		CNTR_KEY(RX_PKT_FILT_WL)
		CNTR_KEY(RX_PKT_FILT_DA)
		CNTR_KEY(RX_ERR_EMPTY)
		CNTR_KEY(RX_ERR_UKWN_NBR)
		CNTR_KEY(RX_ERR_NVLD_SADDR)
		CNTR_KEY(RX_ERR_SECURITY)
		CNTR_KEY(RX_ERR_BAD_FCS)
		CNTR_KEY(RX_ERR_OTHER)
		CNTR_KEY(TX_IP_SEC_TOTAL)
		CNTR_KEY(TX_IP_INSEC_TOTAL)
		CNTR_KEY(TX_IP_DROPPED)
		CNTR_KEY(RX_IP_SEC_TOTAL)
		CNTR_KEY(RX_IP_INSEC_TOTAL)
		CNTR_KEY(RX_IP_DROPPED)
		CNTR_KEY(TX_SPINEL_TOTAL)
		CNTR_KEY(RX_SPINEL_TOTAL)
		CNTR_KEY(RX_SPINEL_ERR)
		CNTR_KEY(IP_TX_SUCCESS)
		CNTR_KEY(IP_RX_SUCCESS)
		CNTR_KEY(IP_TX_FAILURE)
		CNTR_KEY(IP_RX_FAILURE)

#undef CNTR_KEY

		if (cntr_key != 0) {
			SIMPLE_SPINEL_GET(cntr_key, SPINEL_DATATYPE_UINT32_S);
		} else {
			NCPInstanceBase::property_get_value(key, cb);
		}
	} else {
		NCPInstanceBase::property_get_value(key, cb);
	}
}

void
SpinelNCPInstance::property_set_value(
	const std::string& key,
	const boost::any& value,
	CallbackWithStatus cb
) {
	syslog(LOG_INFO, "property_set_value: key: \"%s\"", key.c_str());

	// If we are disabled, then the only property we
	// are allowed to set is kWPANTUNDProperty_DaemonEnabled.
	if (!mEnabled && !strcaseequal(key.c_str(), kWPANTUNDProperty_DaemonEnabled)) {
		cb(kWPANTUNDStatus_InvalidWhenDisabled);
		return;
	}

	try {
		if (mVendorCustom.is_property_key_supported(key)) {
			mVendorCustom.property_set_value(key, value, cb);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPChannel)) {
			int channel = any_to_int(value);
			mCurrentNetworkInstance.channel = channel;

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_PHY_CHAN, channel)
				)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPCCAThreshold)) {
			int cca = any_to_int(value);
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_INT8_S), SPINEL_PROP_PHY_CCA_THRESHOLD, cca);

			mSettings[kWPANTUNDProperty_NCPCCAThreshold] = SettingsEntry(command);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(command)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPTXPower)) {
			int tx_power = any_to_int(value);
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_INT8_S), SPINEL_PROP_PHY_TX_POWER, tx_power);

			mSettings[kWPANTUNDProperty_NCPTXPower] = SettingsEntry(command);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(command)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPMCUPowerState)) {
			spinel_mcu_power_state_t power_state;
			int ret = convert_string_to_spinel_mcu_power_state(any_to_string(value).c_str(), power_state);

			if (ret != kWPANTUNDStatus_Ok) {
				cb(ret);
			} else {
				Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_MCU_POWER_STATE, power_state);

				mSettings[kWPANTUNDProperty_NCPMCUPowerState] = SettingsEntry(command, SPINEL_CAP_MCU_POWER_STATE);

				if (!mCapabilities.count(SPINEL_CAP_MCU_POWER_STATE))
				{
					cb(kWPANTUNDStatus_FeatureNotSupported);
				} else {
					start_new_task(SpinelNCPTaskSendCommand::Factory(this)
						.set_callback(cb)
						.add_command(command)
						.finish()
					);
				}
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkPANID)) {
			uint16_t panid = any_to_int(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT16_S), SPINEL_PROP_MAC_15_4_PANID, panid)
				)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkPSKc)) {
			Data network_pskc = any_to_data(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S), SPINEL_PROP_NET_PSKC, network_pskc.data(), network_pskc.size())
				)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKey)) {
			Data network_key = any_to_data(value);

			if (!ncp_state_is_joining_or_joined(get_ncp_state())) {
				mNetworkKey = network_key;
				if (mNetworkKeyIndex == 0) {
					mNetworkKeyIndex = 1;
				}
			}

			if (get_ncp_state() == CREDENTIALS_NEEDED) {
				ValueMap options;
				options[kWPANTUNDProperty_NetworkKey] = value;
				start_new_task(boost::shared_ptr<SpinelNCPTask>(
					new SpinelNCPTaskJoin(
						this,
						boost::bind(cb,_1),
						options
					)
				));
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(
						SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S), SPINEL_PROP_NET_MASTER_KEY, network_key.data(), network_key.size())
					)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPMACAddress)) {
			Data eui64_value = any_to_data(value);

			if (eui64_value.size() == sizeof(spinel_eui64_t)) {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(
						SpinelPackData(
							SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_EUI64_S),
							SPINEL_PROP_MAC_15_4_LADDR,
							eui64_value.data()
						)
					)
					.finish()
				);

			} else {
				cb(kWPANTUNDStatus_InvalidArgument);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_InterfaceUp)) {
			bool isup = any_to_bool(value);
			if (isup) {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(SpinelPackData(
						SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
						SPINEL_PROP_NET_IF_UP,
						true
					))
					.add_command(SpinelPackData(
						SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
						SPINEL_PROP_NET_STACK_UP,
						true
					))
					.finish()
				);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(SpinelPackData(
						SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
						SPINEL_PROP_NET_STACK_UP,
						false
					))
					.add_command(SpinelPackData(
						SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
						SPINEL_PROP_NET_IF_UP,
						false
					))
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPExtendedAddress)) {
			Data eui64_value = any_to_data(value);

			if (eui64_value.size() == sizeof(spinel_eui64_t)) {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(
						SpinelPackData(
							SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_EUI64_S),
							SPINEL_PROP_MAC_EXTENDED_ADDR,
							eui64_value.data()
						)
					)
					.finish()
				);

			} else {
				cb(kWPANTUNDStatus_InvalidArgument);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPSleepyPollInterval)) {
			uint32_t period = any_to_int(value);
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT32_S), SPINEL_PROP_MAC_DATA_POLL_PERIOD, period);

			mSettings[kWPANTUNDProperty_NCPSleepyPollInterval] = SettingsEntry(command, SPINEL_CAP_ROLE_SLEEPY);

			if (!mCapabilities.count(SPINEL_CAP_ROLE_SLEEPY))
			{
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkXPANID)) {
			Data xpanid = any_to_data(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S), SPINEL_PROP_NET_XPANID, xpanid.data(), xpanid.size())
				)
				.finish()
			);

			mXPANIDWasExplicitlySet = true;

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKey)) {
			Data network_key = any_to_data(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S), SPINEL_PROP_NET_MASTER_KEY, network_key.data(), network_key.size())
				)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKeyIndex)) {
			uint32_t key_index = any_to_int(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT32_S), SPINEL_PROP_NET_KEY_SEQUENCE_COUNTER, key_index)
				)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkName)) {
			std::string str = any_to_string(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UTF8_S), SPINEL_PROP_NET_NETWORK_NAME, str.c_str()))
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkRole)) {
			uint8_t role = any_to_int(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_NET_ROLE, role))
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadPreferredRouterID)) {
			uint8_t routerId = any_to_int(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_THREAD_PREFERRED_ROUTER_ID, routerId)
				)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadDeviceMode)) {
			uint8_t mode = any_to_int(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_THREAD_MODE, mode))
				.finish()
			);
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_TmfProxyEnabled)) {
			bool isEnabled = any_to_bool(value);
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S), SPINEL_PROP_THREAD_TMF_PROXY_ENABLED, isEnabled);

			mSettings[kWPANTUNDProperty_TmfProxyEnabled] = SettingsEntry(command, SPINEL_CAP_THREAD_TMF_PROXY);

			if (!mCapabilities.count(SPINEL_CAP_THREAD_TMF_PROXY))
			{
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACWhitelistEnabled)) {
			bool isEnabled = any_to_bool(value);

			if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(
						SpinelPackData(
							SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
							SPINEL_PROP_MAC_WHITELIST_ENABLED,
							isEnabled
						)
					)
					.finish()
				);
			}

		}
		else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACBlacklistEnabled)) {
			bool isEnabled = any_to_bool(value);

			if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(
						SpinelPackData(
							SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
							SPINEL_PROP_MAC_BLACKLIST_ENABLED,
							isEnabled
						)
					)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionEnable)) {
			bool isEnabled = any_to_bool(value);
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S), SPINEL_PROP_JAM_DETECT_ENABLE, isEnabled);

			mSettings[kWPANTUNDProperty_JamDetectionEnable] = SettingsEntry(command, SPINEL_CAP_JAM_DETECT);

			if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT))
			{
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionRssiThreshold)) {
			int8_t rssiThreshold = static_cast<int8_t>(any_to_int(value));
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_INT8_S), SPINEL_PROP_JAM_DETECT_RSSI_THRESHOLD, rssiThreshold);

			mSettings[kWPANTUNDProperty_JamDetectionRssiThreshold] = SettingsEntry(command, SPINEL_CAP_JAM_DETECT);

			if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT))
			{
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionWindow)) {
			uint8_t window = static_cast<uint8_t>(any_to_int(value));
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_JAM_DETECT_WINDOW, window);

			mSettings[kWPANTUNDProperty_JamDetectionWindow] = SettingsEntry(command, SPINEL_CAP_JAM_DETECT);

			if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT))
			{
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_JamDetectionBusyPeriod)) {
			uint8_t busyPeriod = static_cast<uint8_t>(any_to_int(value));
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_JAM_DETECT_BUSY, busyPeriod);

			mSettings[kWPANTUNDProperty_JamDetectionBusyPeriod] = SettingsEntry(command, SPINEL_CAP_JAM_DETECT);

			if (!mCapabilities.count(SPINEL_CAP_JAM_DETECT))
			{
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix)) {
			Data legacy_prefix = any_to_data(value);
			Data command =
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
					SPINEL_PROP_NEST_LEGACY_ULA_PREFIX,
					legacy_prefix.data(),
					legacy_prefix.size()
				);

			mSettings[kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix] = SettingsEntry(command, SPINEL_CAP_NEST_LEGACY_INTERFACE);

			if (!mCapabilities.count(SPINEL_CAP_NEST_LEGACY_INTERFACE))
			{
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_IPv6MeshLocalPrefix)) {
			struct in6_addr addr = any_to_ipv6(value);

			Data command =
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_IPv6ADDR_S SPINEL_DATATYPE_UINT8_S),
					SPINEL_PROP_IPV6_ML_PREFIX,
					&addr,
					64
				);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(command)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadCommissionerEnabled)) {
			bool isEnabled = any_to_bool(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
					SPINEL_PROP_THREAD_COMMISSIONER_ENABLED,
					isEnabled
				))
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadRouterRoleEnabled)) {
			bool isEnabled = any_to_bool(value);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
					SPINEL_PROP_THREAD_ROUTER_ROLE_ENABLED,
					isEnabled
				))
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadLogLevel)) {
			uint8_t logLevel = static_cast<uint8_t>(any_to_int(value));
			Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_DEBUG_NCP_LOG_LEVEL, logLevel);

			mSettings[kWPANTUNDProperty_OpenThreadLogLevel] = SettingsEntry(command);

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(command)
				.finish()
			);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadConfigFilterRLOCAddresses)) {
			mFilterRLOCAddresses = any_to_bool(value);
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadSteeringDataSetWhenJoinable)) {
			mSetSteeringDataWhenJoinable = any_to_bool(value);
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_OpenThreadSteeringDataAddress)) {
			Data address = any_to_data(value);
			wpantund_status_t status = kWPANTUNDStatus_Ok;

			if (address.size() != sizeof(mSteeringDataAddress)) {
				status = kWPANTUNDStatus_InvalidArgument;
			} else {
				memcpy(mSteeringDataAddress, address.data(), sizeof(mSteeringDataAddress));
			}

			cb (status);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_TmfProxyStream)) {
			Data packet = any_to_data(value);

			if (packet.size() > sizeof(uint16_t)*2) {
				uint16_t port = (packet[packet.size() - sizeof(port)] << 8 | packet[packet.size() - sizeof(port) + 1]);
				uint16_t locator = (packet[packet.size() - sizeof(locator) - sizeof(port)] << 8 |
						packet[packet.size() - sizeof(locator) - sizeof(port) + 1]);

				packet.resize(packet.size() - sizeof(locator) - sizeof(port));

				Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_WLEN_S SPINEL_DATATYPE_UINT16_S SPINEL_DATATYPE_UINT16_S),
						SPINEL_PROP_THREAD_TMF_PROXY_STREAM, packet.data(), packet.size(), locator, port);

				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
						.set_callback(cb)
						.add_command(command)
						.finish()
						);
			} else {
				cb(kWPANTUNDStatus_InvalidArgument);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerNewChannel)) {
			uint8_t channel = any_to_int(value);
			Data command = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S),
				SPINEL_PROP_CHANNEL_MANAGER_NEW_CHANNEL,
				channel
			);

			mSettings[kWPANTUNDProperty_ChannelManagerNewChannel] = SettingsEntry(command, SPINEL_CAP_CHANNEL_MANAGER);

			if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerDelay)) {
			uint16_t delay = any_to_int(value);
			Data command = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT16_S),
				SPINEL_PROP_CHANNEL_MANAGER_DELAY,
				delay
			);

			mSettings[kWPANTUNDProperty_ChannelManagerDelay] = SettingsEntry(command, SPINEL_CAP_CHANNEL_MANAGER);

			if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerChannelSelect)) {
			bool skip_check = any_to_bool(value);

			if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(SpinelPackData(
						SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
						SPINEL_PROP_CHANNEL_MANAGER_CHANNEL_SELECT,
						skip_check
					))
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerAutoSelectEnabled)) {
			bool enabled = any_to_bool(value);
			Data command = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
				SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_ENABLED,
				enabled
			);

			mSettings[kWPANTUNDProperty_ChannelManagerAutoSelectEnabled] =
				SettingsEntry(command, SPINEL_CAP_CHANNEL_MANAGER);

			if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerAutoSelectInterval)) {
			uint32_t interval = any_to_int(value);
			Data command = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT32_S),
				SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_INTERVAL,
				interval
			);

			mSettings[kWPANTUNDProperty_ChannelManagerAutoSelectInterval] =
				SettingsEntry(command, SPINEL_CAP_CHANNEL_MANAGER);

			if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerSupportedChannelMask)) {
			uint32_t mask = any_to_int(value);
			uint8_t mask_array[32];
			unsigned int mask_array_len = 0;
			Data command;

			for (uint8_t channel = 0; channel < 32; channel++) {
				if (mask & (1U << channel)) {
					mask_array[mask_array_len] = channel;
					mask_array_len++;
				}
			}

			command = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
				SPINEL_PROP_CHANNEL_MANAGER_SUPPORTED_CHANNELS,
				mask_array,
				mask_array_len
			);

			mSettings[kWPANTUNDProperty_ChannelManagerSupportedChannelMask] =
				SettingsEntry(command, SPINEL_CAP_CHANNEL_MANAGER);

			if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ChannelManagerFavoredChannelMask)) {
			uint32_t mask = any_to_int(value);
			uint8_t mask_array[32];
			unsigned int mask_array_len = 0;
			Data command;

			for (uint8_t channel = 0; channel < 32; channel++) {
				if (mask & (1U << channel)) {
					mask_array[mask_array_len] = channel;
					mask_array_len++;
				}
			}

			command = SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S),
				SPINEL_PROP_CHANNEL_MANAGER_FAVORED_CHANNELS,
				mask_array,
				mask_array_len
			);

			mSettings[kWPANTUNDProperty_ChannelManagerFavoredChannelMask] =
				SettingsEntry(command, SPINEL_CAP_CHANNEL_MANAGER);

			if (!mCapabilities.count(SPINEL_CAP_CHANNEL_MANAGER)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				start_new_task(SpinelNCPTaskSendCommand::Factory(this)
					.set_callback(cb)
					.add_command(command)
					.finish()
				);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetActiveTimestamp)) {
			mLocalDataset.mActiveTimestamp = any_to_uint64(value);
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetPendingTimestamp)) {
			mLocalDataset.mPendingTimestamp = any_to_uint64(value);
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetMasterKey)) {
			Data master_key = any_to_data(value);

			if (master_key.size() == NCP_NETWORK_KEY_SIZE) {
				mLocalDataset.mMasterKey = master_key;
				cb(kWPANTUNDStatus_Ok);
			} else {
				cb(kWPANTUNDStatus_InvalidArgument);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetNetworkName)) {
			mLocalDataset.mNetworkName = any_to_string(value);
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetExtendedPanId)) {
			Data xpanid = any_to_data(value);

			if (xpanid.size() == sizeof(spinel_net_xpanid_t)) {
				mLocalDataset.mExtendedPanId = any_to_data(value);
				cb(kWPANTUNDStatus_Ok);
			} else {
				cb(kWPANTUNDStatus_InvalidArgument);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetMeshLocalPrefix)) {
			mLocalDataset.mMeshLocalPrefix = any_to_ipv6(value);
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetDelay)) {
			mLocalDataset.mDelay = static_cast<uint32_t>(any_to_int(value));
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetPanId)) {
			mLocalDataset.mPanId = static_cast<uint16_t>(any_to_int(value));
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetChannel)) {
			mLocalDataset.mChannel = static_cast<uint8_t>(any_to_int(value));
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetPSKc)) {
			Data pskc = any_to_data(value);

			if (pskc.size() <= sizeof(spinel_net_pskc_t)) {
				mLocalDataset.mPSKc = any_to_data(value);
				cb(kWPANTUNDStatus_Ok);
			} else {
				cb(kWPANTUNDStatus_InvalidArgument);
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetChannelMaskPage0)) {
			mLocalDataset.mChannelMaskPage0 = static_cast<uint32_t>(any_to_int(value));
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetSecPolicyKeyRotation)) {
			ThreadDataset::SecurityPolicy policy = mLocalDataset.mSecurityPolicy.get();
			policy.mKeyRotationTime = static_cast<uint16_t>(any_to_int(value));
			mLocalDataset.mSecurityPolicy = policy;
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetSecPolicyFlags)) {
			ThreadDataset::SecurityPolicy policy = mLocalDataset.mSecurityPolicy.get();
			policy.mFlags = static_cast<uint8_t>(any_to_int(value));
			mLocalDataset.mSecurityPolicy = policy;
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetRawTlvs)) {
			mLocalDataset.mRawTlvs = any_to_data(value);
			cb(kWPANTUNDStatus_Ok);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DatasetCommand)) {
			perform_dataset_command(any_to_string(value), cb);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_DaemonTickleOnHostDidWake)) {
			mTickleOnHostDidWake =  any_to_bool(value);
			syslog(LOG_INFO, "TickleOnHostDidWake is %sabled", mTickleOnHostDidWake ? "en" : "dis");
			cb(kWPANTUNDStatus_Ok);

		} else {
			NCPInstanceBase::property_set_value(key, value, cb);
		}

	} catch (const boost::bad_any_cast &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"property_set_value: Bad type for property \"%s\" (%s)", key.c_str(), x.what());
		cb(kWPANTUNDStatus_InvalidArgument);
	} catch (const std::invalid_argument &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"property_set_value: Invalid argument for property \"%s\" (%s)", key.c_str(), x.what());
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::property_insert_value(
	const std::string& key,
	const boost::any& value,
	CallbackWithStatus cb
) {
	syslog(LOG_INFO, "property_insert_value: key: \"%s\"", key.c_str());

	if (!mEnabled) {
		cb(kWPANTUNDStatus_InvalidWhenDisabled);
		return;
	}

	try {
		if (mVendorCustom.is_property_key_supported(key)) {
			mVendorCustom.property_insert_value(key, value, cb);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACWhitelistEntries)) {
			Data ext_address = any_to_data(value);
			int8_t rssi = kWPANTUND_Whitelist_RssiOverrideDisabled;

			if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				if (ext_address.size() == sizeof(spinel_eui64_t)) {
					start_new_task(SpinelNCPTaskSendCommand::Factory(this)
						.set_callback(cb)
						.add_command(
							SpinelPackData(
								SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(SPINEL_DATATYPE_EUI64_S SPINEL_DATATYPE_INT8_S),
								SPINEL_PROP_MAC_WHITELIST,
								ext_address.data(),
								rssi
							)
						)
						.finish()
					);
				} else {
					cb(kWPANTUNDStatus_InvalidArgument);
				}
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACBlacklistEntries)) {
			Data ext_address = any_to_data(value);
			int8_t rssi = kWPANTUND_Whitelist_RssiOverrideDisabled;

			if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				if (ext_address.size() == sizeof(spinel_eui64_t)) {
					start_new_task(SpinelNCPTaskSendCommand::Factory(this)
						.set_callback(cb)
						.add_command(
							SpinelPackData(
								SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(SPINEL_DATATYPE_EUI64_S SPINEL_DATATYPE_INT8_S),
								SPINEL_PROP_MAC_BLACKLIST,
								ext_address.data(),
								rssi
							)
						)
						.finish()
					);
				} else {
					cb(kWPANTUNDStatus_InvalidArgument);
				}
			}
		} else {
			NCPInstanceBase::property_insert_value(key, value, cb);
		}
	} catch (const boost::bad_any_cast &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"property_insert_value: Bad type for property \"%s\" (%s)", key.c_str(), x.what());
		cb(kWPANTUNDStatus_InvalidArgument);
	} catch (const std::invalid_argument &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"property_insert_value: Invalid argument for property \"%s\" (%s)", key.c_str(), x.what());
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::property_remove_value(
	const std::string& key,
	const boost::any& value,
	CallbackWithStatus cb
) {
	syslog(LOG_INFO, "property_remove_value: key: \"%s\"", key.c_str());

	try {
		if (mVendorCustom.is_property_key_supported(key)) {
			mVendorCustom.property_remove_value(key, value, cb);

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACWhitelistEntries)) {
			Data ext_address = any_to_data(value);

			if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				if (ext_address.size() == sizeof(spinel_eui64_t)) {
					start_new_task(SpinelNCPTaskSendCommand::Factory(this)
						.set_callback(cb)
						.add_command(
							SpinelPackData(
								SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(SPINEL_DATATYPE_EUI64_S),
								SPINEL_PROP_MAC_WHITELIST,
								ext_address.data()
							)
						)
						.finish()
					);
				} else {
					cb(kWPANTUNDStatus_InvalidArgument);
				}
			}

		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_MACBlacklistEntries)) {
			Data ext_address = any_to_data(value);

			if (!mCapabilities.count(SPINEL_CAP_MAC_WHITELIST)) {
				cb(kWPANTUNDStatus_FeatureNotSupported);
			} else {
				if (ext_address.size() == sizeof(spinel_eui64_t)) {
					start_new_task(SpinelNCPTaskSendCommand::Factory(this)
						.set_callback(cb)
						.add_command(
							SpinelPackData(
								SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(SPINEL_DATATYPE_EUI64_S),
								SPINEL_PROP_MAC_BLACKLIST,
								ext_address.data()
							)
						)
						.finish()
					);
				} else {
					cb(kWPANTUNDStatus_InvalidArgument);
				}
			}
		} else {
			NCPInstanceBase::property_remove_value(key, value, cb);
		}

	} catch (const boost::bad_any_cast &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"property_remove_value: Bad type for property \"%s\" (%s)", key.c_str(), x.what());
		cb(kWPANTUNDStatus_InvalidArgument);
	} catch (const std::invalid_argument &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"property_remove_value: Invalid argument for property \"%s\" (%s)", key.c_str(), x.what());
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::reset_tasks(wpantund_status_t status)
{
	NCPInstanceBase::reset_tasks(status);
	while(!mTaskQueue.empty()) {
		mTaskQueue.front()->finish(status);
		mTaskQueue.pop_front();
	}
}

void
SpinelNCPInstance::handle_ncp_spinel_value_is_OFF_MESH_ROUTE(const uint8_t* value_data_ptr, spinel_size_t value_data_len)
{
	std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator iter;
	std::multimap<IPv6Prefix, OffMeshRouteEntry> off_mesh_routes(mOffMeshRoutes);
	int num_routes = 0;

	while (value_data_len > 0) {
		spinel_ssize_t len;
		struct in6_addr *route_prefix = NULL;
		uint8_t prefix_len;
		bool is_stable;
		uint8_t flags;
		bool is_local;
		bool next_hop_is_this_device;
		uint16_t rloc16;
		RoutePreference preference;

		len = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_IPv6ADDR_S      // Route Prefix
				SPINEL_DATATYPE_UINT8_S         // Prefix Length (in bits)
				SPINEL_DATATYPE_BOOL_S          // isStable
				SPINEL_DATATYPE_UINT8_S         // Flags
				SPINEL_DATATYPE_BOOL_S          // IsLocal
				SPINEL_DATATYPE_BOOL_S          // NextHopIsThisDevice
				SPINEL_DATATYPE_UINT16_S        // RLOC16
			),
			&route_prefix,
			&prefix_len,
			&is_stable,
			&flags,
			&is_local,
			&next_hop_is_this_device,
			&rloc16
		);

		if (len <= 0) {
			break;
		}

		preference = convert_flags_to_route_preference(flags);

		syslog(LOG_INFO, "[-NCP-]: Off-mesh route [%d] \"%s/%d\" stable:%s local:%s preference:%s, next_hop_is_this_device:%s, rloc16:0x%0x",
			num_routes, in6_addr_to_string(*route_prefix).c_str(), prefix_len, is_stable ? "yes" : "no",
			is_local ? "yes" : "no", NCPControlInterface::external_route_priority_to_string(preference).c_str(),
			next_hop_is_this_device ? "yes" : "no", rloc16);

		num_routes++;

		if (!is_local) {

			// Go through the `off_mesh_routes` list (which is the copy of mOffMeshRoutes)
			// and check if this entry is already on the list, if so remove it.

			IPv6Prefix route(*route_prefix, prefix_len);
			OffMeshRouteEntry entry(kOriginThreadNCP, preference, is_stable, rloc16, next_hop_is_this_device);
			iter = off_mesh_routes.lower_bound(route);

			if (iter != off_mesh_routes.end()) {
				std::multimap<IPv6Prefix, OffMeshRouteEntry>::iterator upper_iter = off_mesh_routes.upper_bound(route);

				for (; iter != upper_iter; ++iter) {
					if (iter->second == entry) {
						off_mesh_routes.erase(iter);
						break;
					}
				}
			}

			route_was_added(kOriginThreadNCP, *route_prefix, prefix_len, preference, is_stable, rloc16,
				next_hop_is_this_device);
		}

		value_data_ptr += len;
		value_data_len -= len;
	}

	// Since this was the whole list, we need to remove any routes
	// which originated from NCP that that weren't in the new list.

	for (iter = off_mesh_routes.begin(); iter != off_mesh_routes.end(); ++iter) {
		if (iter->second.is_from_ncp()) {
			route_was_removed(kOriginThreadNCP, iter->first.get_prefix(), iter->first.get_length(),
				iter->second.get_preference(), iter->second.is_stable(), iter->second.get_rloc());
		}
	}
}


void
SpinelNCPInstance::handle_ncp_spinel_value_is(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len)
{
	const uint8_t *original_value_data_ptr = value_data_ptr;
	spinel_size_t original_value_data_len = value_data_len;

	if (key == SPINEL_PROP_LAST_STATUS) {
		spinel_status_t status = SPINEL_STATUS_OK;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "i", &status);
		syslog(LOG_INFO, "[-NCP-]: Last status (%s, %d)", spinel_status_to_cstr(status), status);
		if ((status >= SPINEL_STATUS_RESET__BEGIN) && (status <= SPINEL_STATUS_RESET__END)) {
			syslog(LOG_NOTICE, "[-NCP-]: NCP was reset (%s, %d)", spinel_status_to_cstr(status), status);
			process_event(EVENT_NCP_RESET, status);
			if (!mResetIsExpected && (mDriverState == NORMAL_OPERATION)) {
				wpantund_status_t wstatus = kWPANTUNDStatus_NCP_Reset;
				switch(status) {
				case SPINEL_STATUS_RESET_CRASH:
				case SPINEL_STATUS_RESET_FAULT:
				case SPINEL_STATUS_RESET_ASSERT:
				case SPINEL_STATUS_RESET_WATCHDOG:
				case SPINEL_STATUS_RESET_OTHER:
					wstatus = kWPANTUNDStatus_NCP_Crashed;
					break;
				default:
					break;
				}
				reset_tasks(wstatus);
			}

			if (mDriverState == NORMAL_OPERATION) {
				reinitialize_ncp();
			}
			mResetIsExpected = false;
			return;
		} else if (status == SPINEL_STATUS_INVALID_COMMAND) {
			syslog(LOG_NOTICE, "[-NCP-]: COMMAND NOT RECOGNIZED");
		}
	} else if (key == SPINEL_PROP_NCP_VERSION) {
		const char* ncp_version = NULL;
		spinel_ssize_t len = spinel_datatype_unpack(value_data_ptr, value_data_len, "U", &ncp_version);
		if ((len <= 0) || (ncp_version == NULL)) {
			syslog(LOG_CRIT, "[-NCP-]: Got a corrupted NCP version");
			// TODO: Properly handle NCP Misbehavior
			change_ncp_state(FAULT);
		} else {
			set_ncp_version_string(ncp_version);
		}

	} else if (key == SPINEL_PROP_INTERFACE_TYPE) {
		unsigned int interface_type = 0;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "i", &interface_type);

		if (interface_type != SPINEL_PROTOCOL_TYPE_THREAD) {
			syslog(LOG_CRIT, "[-NCP-]: NCP is using unsupported protocol type (%d)", interface_type);
			change_ncp_state(FAULT);
		}

	} else if (key == SPINEL_PROP_PROTOCOL_VERSION) {
		unsigned int protocol_version_major = 0;
		unsigned int protocol_version_minor = 0;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "ii", &protocol_version_major, &protocol_version_minor);

		if (protocol_version_major != SPINEL_PROTOCOL_VERSION_THREAD_MAJOR) {
			syslog(LOG_CRIT, "[-NCP-]: NCP is using unsupported protocol version (NCP:%d, wpantund:%d)", protocol_version_major, SPINEL_PROTOCOL_VERSION_THREAD_MAJOR);
			change_ncp_state(FAULT);
		}

		if (protocol_version_minor != SPINEL_PROTOCOL_VERSION_THREAD_MINOR) {
			syslog(LOG_WARNING, "[-NCP-]: NCP is using different protocol minor version (NCP:%d, wpantund:%d)", protocol_version_minor, SPINEL_PROTOCOL_VERSION_THREAD_MINOR);
		}

	} else if (key == SPINEL_PROP_CAPS) {
		const uint8_t* data_ptr = value_data_ptr;
		spinel_size_t data_len = value_data_len;
		std::set<unsigned int> capabilities;

		while(data_len != 0) {
			unsigned int value = 0;
			spinel_ssize_t parse_len = spinel_datatype_unpack(data_ptr, data_len, SPINEL_DATATYPE_UINT_PACKED_S, &value);
			if (parse_len <= 0) {
				syslog(LOG_WARNING, "[-NCP-]: Capability Parse failure");
				break;
			}
			capabilities.insert(value);
			syslog(LOG_INFO, "[-NCP-]: Capability (%s, %d)", spinel_capability_to_cstr(value), value);

			data_ptr += parse_len;
			data_len -= parse_len;
		}

		if (capabilities != mCapabilities) {
			mCapabilities = capabilities;
		}

	} else if (key == SPINEL_PROP_NET_NETWORK_NAME) {
		const char* value = NULL;
		spinel_ssize_t len = spinel_datatype_unpack(value_data_ptr, value_data_len, "U", &value);

		if ((len <= 0) || (value == NULL)) {
			syslog(LOG_CRIT, "[-NCP-]: Got a corrupted NCP version");
			// TODO: Properly handle NCP Misbehavior
			change_ncp_state(FAULT);
		} else {
			syslog(LOG_INFO, "[-NCP-]: Network name \"%s\"", value);
			if (mCurrentNetworkInstance.name != value) {
				mCurrentNetworkInstance.name = value;
				signal_property_changed(kWPANTUNDProperty_NetworkName, mCurrentNetworkInstance.name);
			}
		}

	} else if (key == SPINEL_PROP_MCU_POWER_STATE) {
		uint8_t power_state = 0;
		spinel_ssize_t len = 0;

		len  = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &power_state);

		if (len > 0) {
			syslog(LOG_INFO, "[-NCP-]: MCU power state \"%s\" (%d)",
				spinel_mcu_power_state_to_cstr(static_cast<spinel_mcu_power_state_t>(power_state)), power_state);

			switch (get_ncp_state()) {
			case OFFLINE:
			case COMMISSIONED:
				if (power_state == SPINEL_MCU_POWER_STATE_LOW_POWER) {
					change_ncp_state(DEEP_SLEEP);
				}
				break;

			case DEEP_SLEEP:
				if (power_state == SPINEL_MCU_POWER_STATE_ON) {
					change_ncp_state(mIsCommissioned ? COMMISSIONED : OFFLINE);
				}
				break;

			default:
				break;
			}
		}

	} else if (key == SPINEL_PROP_IPV6_LL_ADDR) {
		struct in6_addr *addr = NULL;

		spinel_datatype_unpack(value_data_ptr, value_data_len, "6", &addr);
		if (addr != NULL) {
			syslog(LOG_INFO, "[-NCP-]: Link-local IPv6 address \"%s\"", in6_addr_to_string(*addr).c_str());
		}
		update_link_local_address(addr);

	} else if (key == SPINEL_PROP_IPV6_ML_ADDR) {
		struct in6_addr *addr = NULL;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "6", &addr);
		if (addr != NULL) {
			syslog(LOG_INFO, "[-NCP-]: Mesh-local IPv6 address \"%s\"", in6_addr_to_string(*addr).c_str());
		}
		update_mesh_local_address(addr);

	} else if (key == SPINEL_PROP_IPV6_ML_PREFIX) {
		struct in6_addr *addr = NULL;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "6", &addr);
		if (addr != NULL) {
			syslog(LOG_INFO, "[-NCP-]: Mesh-local prefix \"%s\"", (in6_addr_to_string(*addr) + "/64").c_str());
		}
		update_mesh_local_prefix(addr);

	} else if (key == SPINEL_PROP_IPV6_ADDRESS_TABLE) {
		std::map<struct in6_addr, UnicastAddressEntry>::const_iterator iter;
		std::map<struct in6_addr, UnicastAddressEntry> unicast_addresses(mUnicastAddresses);
		const struct in6_addr *addr = NULL;
		int num_address = 0;

		while (value_data_len > 0) {
			const uint8_t *entry_ptr = NULL;
			spinel_size_t entry_len = 0;
			spinel_ssize_t len = 0;
			len = spinel_datatype_unpack(value_data_ptr, value_data_len, "D.", &entry_ptr, &entry_len);
			if (len < 1) {
				break;
			}

			addr = reinterpret_cast<const struct in6_addr*>(entry_ptr);
			syslog(LOG_INFO, "[-NCP-]: IPv6 address [%d] \"%s\"", num_address, in6_addr_to_string(*addr).c_str());
			num_address++;
			unicast_addresses.erase(*addr);
			handle_ncp_spinel_value_inserted(key, entry_ptr, entry_len);

			value_data_ptr += len;
			value_data_len -= len;
		}

		syslog(LOG_INFO, "[-NCP-]: IPv6 address: Total %d address%s", num_address, (num_address > 1) ? "es" : "");

		// Since this was the whole list, we need to remove the addresses
		// which originated from NCP that that weren't in the list.
		for (iter = unicast_addresses.begin(); iter != unicast_addresses.end(); ++iter) {
			if (iter->second.is_from_ncp()) {
				unicast_address_was_removed(kOriginThreadNCP, iter->first);
			}
		}

	} else if (key == SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE) {
		std::map<struct in6_addr, MulticastAddressEntry>::const_iterator iter;
		std::map<struct in6_addr, MulticastAddressEntry> multicast_addresses(mMulticastAddresses);
		const struct in6_addr *addr = NULL;
		int num_address = 0;

		while (value_data_len > 0) {
			const uint8_t *entry_ptr = NULL;
			spinel_size_t entry_len = 0;
			spinel_ssize_t len = 0;
			len = spinel_datatype_unpack(value_data_ptr, value_data_len, "D.", &entry_ptr, &entry_len);
			if (len < 1) {
				break;
			}

			addr = reinterpret_cast<const struct in6_addr*>(entry_ptr);
			syslog(LOG_INFO, "[-NCP-]: Multicast IPv6 address [%d] \"%s\"", num_address, in6_addr_to_string(*addr).c_str());
			num_address++;
			multicast_addresses.erase(*addr);
			handle_ncp_spinel_value_inserted(key, entry_ptr, entry_len);

			value_data_ptr += len;
			value_data_len -= len;
		}

		// Since this was the whole list, we need to remove the addresses
		// which originated from NCP that that weren't in the list.
		for (iter = multicast_addresses.begin(); iter != multicast_addresses.end(); ++iter) {
			if (iter->second.is_from_ncp()) {
				multicast_address_was_left(kOriginThreadNCP, iter->first);
			}
		}

	} else if (key == SPINEL_PROP_HWADDR) {
		nl::Data hwaddr(value_data_ptr, value_data_len);
		if (value_data_len == sizeof(mMACHardwareAddress)) {
			set_mac_hardware_address(value_data_ptr);
		}

	} else if (key == SPINEL_PROP_MAC_15_4_LADDR) {
		nl::Data hwaddr(value_data_ptr, value_data_len);
		if (value_data_len == sizeof(mMACAddress)) {
			set_mac_address(value_data_ptr);
		}

	} else if (key == SPINEL_PROP_MAC_15_4_PANID) {
		uint16_t panid;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT16_S, &panid);
		syslog(LOG_INFO, "[-NCP-]: PANID 0x%04X", panid);
		if (panid != mCurrentNetworkInstance.panid) {
			mCurrentNetworkInstance.panid = panid;
			signal_property_changed(kWPANTUNDProperty_NetworkPANID, panid);
		}

	} else if (key == SPINEL_PROP_NET_XPANID) {
		nl::Data xpanid(value_data_ptr, value_data_len);
		char cstr_buf[200];
		encode_data_into_string(value_data_ptr, value_data_len, cstr_buf, sizeof(cstr_buf), 0);
		syslog(LOG_INFO, "[-NCP-] XPANID 0x%s", cstr_buf);

		if ((value_data_len == 8) && 0 != memcmp(xpanid.data(), mCurrentNetworkInstance.xpanid, 8)) {
			memcpy(mCurrentNetworkInstance.xpanid, xpanid.data(), 8);
			signal_property_changed(kWPANTUNDProperty_NetworkXPANID, xpanid);
		}

	} else if (key == SPINEL_PROP_NET_PSKC) {
		nl::Data network_pskc(value_data_ptr, value_data_len);
		if (network_pskc != mNetworkPSKc) {
			mNetworkPSKc = network_pskc;
			signal_property_changed(kWPANTUNDProperty_NetworkPSKc, mNetworkPSKc);
		}

	} else if (key == SPINEL_PROP_NET_MASTER_KEY) {
		nl::Data network_key(value_data_ptr, value_data_len);
		if (ncp_state_is_joining_or_joined(get_ncp_state())) {
			if (network_key != mNetworkKey) {
				mNetworkKey = network_key;
				signal_property_changed(kWPANTUNDProperty_NetworkKey, mNetworkKey);
			}
		}

	} else if (key == SPINEL_PROP_NET_KEY_SEQUENCE_COUNTER) {
		uint32_t network_key_index = 0;
		spinel_ssize_t ret;

		ret = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT32_S, &network_key_index);

		__ASSERT_MACROS_check(ret > 0);

		if ((ret > 0) && (network_key_index != mNetworkKeyIndex)) {
			mNetworkKeyIndex = network_key_index;
			signal_property_changed(kWPANTUNDProperty_NetworkKeyIndex, mNetworkKeyIndex);
		}

	} else if (key == SPINEL_PROP_PHY_CHAN) {
		unsigned int value = 0;
		spinel_ssize_t ret;

		ret = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT_PACKED_S, &value);

		__ASSERT_MACROS_check(ret > 0);

		if (ret > 0) {
			syslog(LOG_INFO, "[-NCP-]: Channel %d", value);
			if (value != mCurrentNetworkInstance.channel) {
				mCurrentNetworkInstance.channel = value;
				signal_property_changed(kWPANTUNDProperty_NCPChannel, mCurrentNetworkInstance.channel);
			}
		}

	} else if (key == SPINEL_PROP_PHY_CHAN_SUPPORTED) {

		uint8_t channel = 0;
		spinel_ssize_t len = 0;

		mSupprotedChannels.clear();

		while (value_data_len > 0)
		{
			len = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &channel);

			if (len <= 0) {
				break;
			}

			mSupprotedChannels.insert(channel);

			value_data_ptr += len;
			value_data_len -= len;
		}

	} else if (key == SPINEL_PROP_PHY_TX_POWER) {
		int8_t value = 0;
		spinel_ssize_t ret;

		ret = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_INT8_S, &value);

		__ASSERT_MACROS_check(ret > 0);

		if (ret > 0) {
			syslog(LOG_INFO, "[-NCP-]: Tx power %d", value);
			if (value != mTXPower) {
				mTXPower = value;
				signal_property_changed(kWPANTUNDProperty_NCPTXPower, mTXPower);
			}
		}

	} else if (key == SPINEL_PROP_STREAM_DEBUG) {
		handle_ncp_log(value_data_ptr, value_data_len);

	} else if (key == SPINEL_PROP_NET_ROLE) {
		uint8_t value = 0;
		spinel_ssize_t ret;

		ret = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &value);

		__ASSERT_MACROS_check(ret > 0);

		if (ret > 0) {
			syslog(LOG_INFO, "[-NCP-]: Net Role \"%s\" (%d)", spinel_net_role_to_cstr(value), value);

			if (ncp_state_is_joining_or_joined(get_ncp_state())
			  && (value != SPINEL_NET_ROLE_DETACHED)
			) {
				change_ncp_state(ASSOCIATED);
			}

			if (value == SPINEL_NET_ROLE_CHILD) {
				if ((mThreadMode & SPINEL_THREAD_MODE_RX_ON_WHEN_IDLE) != 0) {
					update_node_type(END_DEVICE);
				} else {
					update_node_type(SLEEPY_END_DEVICE);
				}

			} else if (value == SPINEL_NET_ROLE_ROUTER) {
				update_node_type(ROUTER);

			} else if (value == SPINEL_NET_ROLE_LEADER) {
				update_node_type(LEADER);

			} else if (value == SPINEL_NET_ROLE_DETACHED) {
				update_node_type(UNKNOWN);
				if (ncp_state_is_associated(get_ncp_state())) {
					change_ncp_state(ISOLATED);
				}
			}
		}

	} else if (key == SPINEL_PROP_THREAD_MODE) {
		uint8_t value = mThreadMode;
		spinel_ssize_t ret;

		ret = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &value);

		__ASSERT_MACROS_check(ret > 0);

		if (ret > 0) {
			syslog(LOG_INFO, "[-NCP-]: Thread Mode \"%s\" (0x%02x)", thread_mode_to_string(value).c_str(), value);
			mThreadMode = value;

			switch (mNodeType)
			{
			case END_DEVICE:
			case SLEEPY_END_DEVICE:
				if ((mThreadMode & SPINEL_THREAD_MODE_RX_ON_WHEN_IDLE) != 0) {
					update_node_type(END_DEVICE);
				} else {
					update_node_type(SLEEPY_END_DEVICE);
				}
				break;

			default:
				break;
			}
		}

	} else if (key == SPINEL_PROP_NET_SAVED) {
		bool is_commissioned = false;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_BOOL_S, &is_commissioned);
		syslog(LOG_INFO, "[-NCP-]: NetSaved (NCP is commissioned?) \"%s\" ", is_commissioned ? "yes" : "no");
		mIsCommissioned = is_commissioned;
		if (mIsCommissioned && (get_ncp_state() == OFFLINE)) {
			change_ncp_state(COMMISSIONED);
		} else if (!mIsCommissioned && (get_ncp_state() == COMMISSIONED)) {
			change_ncp_state(OFFLINE);
		}

	} else if (key == SPINEL_PROP_NET_STACK_UP) {
		bool is_stack_up = false;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_BOOL_S, &is_stack_up);
		syslog(LOG_INFO, "[-NCP-]: Stack is %sup", is_stack_up ? "" : "not ");

		if (is_stack_up) {
			if (!ncp_state_is_joining_or_joined(get_ncp_state())) {
				change_ncp_state(ASSOCIATING);
			}
		} else {
			if (!ncp_state_is_joining(get_ncp_state())) {
				change_ncp_state(mIsCommissioned ? COMMISSIONED : OFFLINE);
			}
		}

	} else if (key == SPINEL_PROP_NET_IF_UP) {
		bool is_if_up = false;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_BOOL_S, &is_if_up);
		syslog(LOG_INFO, "[-NCP-]: Interface is %sup", is_if_up ? "" : "not ");

		if (ncp_state_is_interface_up(get_ncp_state()) && !is_if_up) {
			change_ncp_state(mIsCommissioned ? COMMISSIONED : OFFLINE);
		}

	} else if (key == SPINEL_PROP_THREAD_ON_MESH_NETS) {
		std::map<struct in6_addr, OnMeshPrefixEntry>::const_iterator iter;
		std::map<struct in6_addr, OnMeshPrefixEntry> on_mesh_prefixes(mOnMeshPrefixes);
		int num_prefix = 0;

		while (value_data_len > 0) {
			spinel_ssize_t len = 0;
			struct in6_addr *prefix = NULL;
			uint8_t prefix_len = 0;
			bool stable = false;
			uint8_t flags = 0;
			bool is_local = false;

			len = spinel_datatype_unpack(value_data_ptr, value_data_len, "t(6CbCb)",
						&prefix, &prefix_len, &stable, &flags, &is_local);

			if (len < 1) {
				break;
			}

			syslog(LOG_INFO, "[-NCP-]: On-mesh net [%d] \"%s/%d\" stable:%s local:%s flags:%s",
				num_prefix,	in6_addr_to_string(*prefix).c_str(), prefix_len, stable ? "yes" : "no",
				is_local ? "yes" : "no", on_mesh_prefix_flags_to_string(flags).c_str());

			num_prefix++;

			if (!is_local) {
				on_mesh_prefixes.erase(*prefix);
				on_mesh_prefix_was_added(kOriginThreadNCP, *prefix, prefix_len, flags, stable);
			}

			value_data_ptr += len;
			value_data_len -= len;
		}

		// Since this was the whole list, we need to remove any prefixes
		// which originated from NCP that that weren't in the new list.
		for (iter = on_mesh_prefixes.begin(); iter != on_mesh_prefixes.end(); ++iter) {
			if (iter->second.is_from_ncp()) {
				on_mesh_prefix_was_removed(kOriginThreadNCP, iter->first, iter->second.get_prefix_len());
			}
		}

	} else if (key == SPINEL_PROP_THREAD_OFF_MESH_ROUTES) {
		handle_ncp_spinel_value_is_OFF_MESH_ROUTE(value_data_ptr, value_data_len);

	} else if (key == SPINEL_PROP_THREAD_ASSISTING_PORTS) {
		bool is_assisting = (value_data_len != 0);
		uint16_t assisting_port(0);

		if (is_assisting != get_current_network_instance().joinable) {
			mCurrentNetworkInstance.joinable = is_assisting;
			signal_property_changed(kWPANTUNDProperty_NestLabs_NetworkAllowingJoin, is_assisting);
		}

		if (is_assisting) {
			int i;
			syslog(LOG_NOTICE, "Network is joinable");
			while (value_data_len > 0) {
				i = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT16_S, &assisting_port);
				if (i <= 0) {
					break;
				}
				syslog(LOG_NOTICE, "Assisting on port %d", assisting_port);
				value_data_ptr += i;
				value_data_len -= i;
			}
		} else {
			syslog(LOG_NOTICE, "Network is not joinable");
		}

	} else if (key == SPINEL_PROP_JAM_DETECTED) {
		bool jamDetected = false;

		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_BOOL_S, &jamDetected);
		signal_property_changed(kWPANTUNDProperty_JamDetectionStatus, jamDetected);

		if (jamDetected) {
			syslog(LOG_NOTICE, "Signal jamming is detected");
		} else {
			syslog(LOG_NOTICE, "Signal jamming cleared");
		}

	} else if (key == SPINEL_PROP_CHANNEL_MANAGER_NEW_CHANNEL) {
		uint8_t new_channel = 0;
		spinel_ssize_t len;

		len = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &new_channel);

		if ((len >= 0) && (new_channel != mChannelManagerNewChannel)) {
			mChannelManagerNewChannel = new_channel;
			signal_property_changed(kWPANTUNDProperty_ChannelManagerNewChannel, new_channel);
			syslog(LOG_INFO, "[-NCP-]: ChannelManager about to switch to new channel %d", new_channel);
		}

	} else if (key == SPINEL_PROP_STREAM_RAW) {
		if (mPcapManager.is_enabled()) {
			const uint8_t* frame_ptr(NULL);
			unsigned int frame_len(0);
			const uint8_t* meta_ptr(NULL);
			unsigned int meta_len(0);
			spinel_ssize_t ret;
			PcapPacket packet;
			uint16_t flags = 0;

			packet.set_timestamp().set_dlt(PCAP_DLT_IEEE802_15_4);

			// Unpack the packet.
			ret = spinel_datatype_unpack(
				value_data_ptr,
				value_data_len,
				SPINEL_DATATYPE_DATA_WLEN_S SPINEL_DATATYPE_DATA_S,
				&frame_ptr,
				&frame_len,
				&meta_ptr,
				&meta_len
			);

			require(ret > 0, bail);

			// Unpack the metadata.
			ret = spinel_datatype_unpack(
				meta_ptr,
				meta_len,
				SPINEL_DATATYPE_INT8_S     // RSSI/TXPower
				SPINEL_DATATYPE_INT8_S     // Noise Floor
				SPINEL_DATATYPE_UINT16_S,  // Flags
				NULL,   // Ignore RSSI/TXPower
				NULL,	// Ignore Noise Floor
				&flags
			);

			__ASSERT_MACROS_check(ret > 0);

			if ((flags & SPINEL_MD_FLAG_TX) == SPINEL_MD_FLAG_TX)
			{
				// Ignore FCS for transmitted packets
				frame_len -= 2;
				packet.set_dlt(PCAP_DLT_IEEE802_15_4_NOFCS);
			}

			mPcapManager.push_packet(
				packet
					.append_ppi_field(PCAP_PPI_TYPE_SPINEL, meta_ptr, meta_len)
					.append_payload(frame_ptr, frame_len)
			);
		}

	} else if (key == SPINEL_PROP_THREAD_TMF_PROXY_STREAM) {
		const uint8_t* frame_ptr(NULL);
		unsigned int frame_len(0);
		uint16_t locator = 0;
		uint16_t port = 0;
		spinel_ssize_t ret;
		Data data;

		ret = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			SPINEL_DATATYPE_DATA_S SPINEL_DATATYPE_UINT16_S SPINEL_DATATYPE_UINT16_S,
			&frame_ptr,
			&frame_len,
			&locator,
			&port
		);

		__ASSERT_MACROS_check(ret > 0);

		// Analyze the packet to determine if it should be dropped.
		if ((ret > 0)) {
			// append frame
			data.append(frame_ptr, frame_len);
			// pack the locator in big endian.
			data.push_back(locator >> 8);
			data.push_back(locator & 0xff);
			// pack the port in big endian.
			data.push_back(port >> 8);
			data.push_back(port & 0xff);
			signal_property_changed(kWPANTUNDProperty_TmfProxyStream, data);
		}

	} else if ((key == SPINEL_PROP_STREAM_NET) || (key == SPINEL_PROP_STREAM_NET_INSECURE)) {
		const uint8_t* frame_ptr(NULL);
		unsigned int frame_len(0);
		spinel_ssize_t ret;
		uint8_t frame_data_type = FRAME_TYPE_DATA;

		if (SPINEL_PROP_STREAM_NET_INSECURE == key) {
			frame_data_type = FRAME_TYPE_INSECURE_DATA;
		}

		ret = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			SPINEL_DATATYPE_DATA_S SPINEL_DATATYPE_DATA_S,
			&frame_ptr,
			&frame_len,
			NULL,
			NULL
		);

		__ASSERT_MACROS_check(ret > 0);

		// Analyze the packet to determine if it should be dropped.
		if ((ret > 0) && should_forward_hostbound_frame(&frame_data_type, frame_ptr, frame_len)) {
			if (static_cast<bool>(mLegacyInterface) && (frame_data_type == FRAME_TYPE_LEGACY_DATA)) {
				handle_alt_ipv6_from_ncp(frame_ptr, frame_len);
			} else {
				handle_normal_ipv6_from_ncp(frame_ptr, frame_len);
			}
		}
	} else if (key == SPINEL_PROP_THREAD_CHILD_TABLE) {
		SpinelNCPTaskGetNetworkTopology::Table child_table;
		SpinelNCPTaskGetNetworkTopology::Table::iterator it;
		int num_children = 0;

		SpinelNCPTaskGetNetworkTopology::parse_child_table(value_data_ptr, value_data_len, child_table);

		for (it = child_table.begin(); it != child_table.end(); it++)
		{
			num_children++;
			syslog(LOG_INFO, "[-NCP-] Child: %02d %s", num_children, it->get_as_string().c_str());
		}
		syslog(LOG_INFO, "[-NCP-] Child: Total %d child%s", num_children, (num_children > 1) ? "ren" : "");

	} else if (key == SPINEL_PROP_THREAD_NEIGHBOR_TABLE) {
		SpinelNCPTaskGetNetworkTopology::Table neigh_table;
		SpinelNCPTaskGetNetworkTopology::Table::iterator it;
		int num_neighbor = 0;

		SpinelNCPTaskGetNetworkTopology::parse_neighbor_table(value_data_ptr, value_data_len, neigh_table);

		for (it = neigh_table.begin(); it != neigh_table.end(); it++)
		{
			num_neighbor++;
			syslog(LOG_INFO, "[-NCP-] Neighbor: %02d %s", num_neighbor, it->get_as_string().c_str());
		}
		syslog(LOG_INFO, "[-NCP-] Neighbor: Total %d neighbor%s", num_neighbor, (num_neighbor > 1) ? "s" : "");

	} else if (key == SPINEL_PROP_THREAD_NEIGHBOR_TABLE_ERROR_RATES) {
		SpinelNCPTaskGetNetworkTopology::Table neigh_table;
		SpinelNCPTaskGetNetworkTopology::Table::iterator it;
		int num_neighbor = 0;

		SpinelNCPTaskGetNetworkTopology::prase_neighbor_error_rates_table(value_data_ptr, value_data_len, neigh_table);

		for (it = neigh_table.begin(); it != neigh_table.end(); it++)
		{
			num_neighbor++;
			syslog(LOG_INFO, "[-NCP-] Neighbor: %02d %s", num_neighbor, it->get_as_string().c_str());
		}
		syslog(LOG_INFO, "[-NCP-] Neighbor: Total %d neighbor%s", num_neighbor, (num_neighbor > 1) ? "s" : "");

	} else if (key == SPINEL_PROP_THREAD_ROUTER_TABLE) {
		SpinelNCPTaskGetNetworkTopology::Table router_table;
		SpinelNCPTaskGetNetworkTopology::Table::iterator it;
		int num_router = 0;

		SpinelNCPTaskGetNetworkTopology::parse_router_table(value_data_ptr, value_data_len, router_table);

		for (it = router_table.begin(); it != router_table.end(); it++)
		{
			num_router++;
			syslog(LOG_INFO, "[-NCP-] Router: %02d %s", num_router, it->get_as_string().c_str());
		}
		syslog(LOG_INFO, "[-NCP-] Router: Total %d router%s", num_router, (num_router > 1) ? "s" : "");


	} else if (key == SPINEL_PROP_NET_PARTITION_ID) {
		uint32_t paritition_id = 0;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT32_S, &paritition_id);
		syslog(LOG_INFO, "[-NCP-] Partition id: %u (0x%x)", paritition_id, paritition_id);

	} else if (key == SPINEL_PROP_THREAD_LEADER_NETWORK_DATA) {
		char net_data_cstr_buf[540];
		encode_data_into_string(value_data_ptr, value_data_len, net_data_cstr_buf, sizeof(net_data_cstr_buf), 0);
		syslog(LOG_INFO, "[-NCP-] Leader network data: [%s]", net_data_cstr_buf);
	}

bail:
	process_event(EVENT_NCP_PROP_VALUE_IS, key, original_value_data_ptr, original_value_data_len);
}

void
SpinelNCPInstance::handle_ncp_spinel_value_inserted(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len)
{
	if (key == SPINEL_PROP_IPV6_ADDRESS_TABLE) {
			struct in6_addr *addr = NULL;
			uint8_t prefix_len = 0;
			uint32_t valid_lifetime = 0xFFFFFFFF;
			uint32_t preferred_lifetime = 0xFFFFFFFF;

			spinel_datatype_unpack(value_data_ptr, value_data_len, "6CLL", &addr, &prefix_len, &valid_lifetime, &preferred_lifetime);

			if (addr != NULL) {
				if (!should_filter_address(*addr, prefix_len)) {
					unicast_address_was_added(kOriginThreadNCP, *addr, prefix_len, valid_lifetime, preferred_lifetime);
				}
			}

	} else if (key == SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE) {
		struct in6_addr *addr = NULL;

		spinel_datatype_unpack(value_data_ptr, value_data_len, "6", &addr);

		if ((addr != NULL) && !IN6_IS_ADDR_UNSPECIFIED(addr)) {
			multicast_address_was_joined(kOriginThreadNCP, *addr);
		}

	} else if (key == SPINEL_PROP_THREAD_ON_MESH_NETS) {
		struct in6_addr *prefix = NULL;
		uint8_t prefix_len = 0;
		bool stable = false;
		uint8_t flags = 0;
		bool is_local = false;

		spinel_datatype_unpack(value_data_ptr, value_data_len, "6CbCb",
			&prefix, &prefix_len, &stable, &flags, &is_local);

		if (prefix != NULL) {
			syslog(LOG_INFO, "[-NCP-]: On-mesh net added \"%s/%d\" stable:%s local:%s flags:%s", in6_addr_to_string(*prefix).c_str(),
				prefix_len,	stable ? "yes" : "no", is_local ? "yes" : "no",	on_mesh_prefix_flags_to_string(flags).c_str());

			if (!is_local) {
				on_mesh_prefix_was_added(kOriginThreadNCP, *prefix, prefix_len, flags, stable);
			}
		}

	} else if (key == SPINEL_PROP_THREAD_CHILD_TABLE) {
		SpinelNCPTaskGetNetworkTopology::TableEntry child_entry;
		int status;

		status = SpinelNCPTaskGetNetworkTopology::parse_child_entry(value_data_ptr, value_data_len, child_entry);

		if (status == kWPANTUNDStatus_Ok) {
			syslog(LOG_INFO, "[-NCP-]: ChildTable entry added: %s", child_entry.get_as_string().c_str());
		}

	}

	process_event(EVENT_NCP_PROP_VALUE_INSERTED, key, value_data_ptr, value_data_len);
}

void
SpinelNCPInstance::handle_ncp_spinel_value_removed(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len)
{
	if (key == SPINEL_PROP_THREAD_CHILD_TABLE) {
		SpinelNCPTaskGetNetworkTopology::TableEntry child_entry;
		int status;

		status = SpinelNCPTaskGetNetworkTopology::parse_child_entry(value_data_ptr, value_data_len, child_entry);

		if (status == kWPANTUNDStatus_Ok) {
			syslog(LOG_INFO, "[-NCP-]: ChildTable entry removed: %s", child_entry.get_as_string().c_str());
		}

	}

	process_event(EVENT_NCP_PROP_VALUE_REMOVED, key, value_data_ptr, value_data_len);
}

void
SpinelNCPInstance::handle_ncp_state_change(NCPState new_ncp_state, NCPState old_ncp_state)
{
	NCPInstanceBase::handle_ncp_state_change(new_ncp_state, old_ncp_state);

	if ( ncp_state_is_joining_or_joined(old_ncp_state)
	  && (new_ncp_state == OFFLINE)
	) {
		// Mark this as false so that if we are actually doing
		// a pcap right now it will force the details to be updated
		// on the NCP at the next run through the main loop. This
		// allows us to go back to promiscuous-mode sniffing at
		// disconnect
		mIsPcapInProgress = false;
	}

	if (ncp_state_is_associated(new_ncp_state)
	 && !ncp_state_is_associated(old_ncp_state)
	) {
		mIsCommissioned = true;
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_15_4_LADDR))
			.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ML_ADDR))
			.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_NET_XPANID))
			.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_15_4_PANID))
			.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_PHY_CHAN))
			.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ADDRESS_TABLE))
			.finish()
		);
	} else if (ncp_state_is_joining(new_ncp_state)
	 && !ncp_state_is_joining(old_ncp_state)
	) {
		if (!buffer_is_nonzero(mNCPV6Prefix, 8)) {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ML_PREFIX))
				.finish()
			);
		}
	}
}

void
SpinelNCPInstance::handle_ncp_spinel_callback(unsigned int command, const uint8_t* cmd_data_ptr, spinel_size_t cmd_data_len)
{
	switch (command) {
	case SPINEL_CMD_PROP_VALUE_IS:
		{
			spinel_prop_key_t key = SPINEL_PROP_LAST_STATUS;
			uint8_t* value_data_ptr = NULL;
			spinel_size_t value_data_len = 0;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len);

			__ASSERT_MACROS_check(ret != -1);

			if (ret == -1) {
				return;
			}

			if (key != SPINEL_PROP_STREAM_DEBUG) {
				syslog(LOG_INFO, "[NCP->] CMD_PROP_VALUE_IS(%s) tid:%d", spinel_prop_key_to_cstr(key), SPINEL_HEADER_GET_TID(cmd_data_ptr[0]));
			}

			return handle_ncp_spinel_value_is(key, value_data_ptr, value_data_len);
		}
		break;

	case SPINEL_CMD_PROP_VALUE_INSERTED:
		{
			spinel_prop_key_t key = SPINEL_PROP_LAST_STATUS;
			uint8_t* value_data_ptr = NULL;
			spinel_size_t value_data_len = 0;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len);

			__ASSERT_MACROS_check(ret != -1);

			if (ret == -1) {
				return;
			}

			syslog(LOG_INFO, "[NCP->] CMD_PROP_VALUE_INSERTED(%s) tid:%d", spinel_prop_key_to_cstr(key), SPINEL_HEADER_GET_TID(cmd_data_ptr[0]));

			return handle_ncp_spinel_value_inserted(key, value_data_ptr, value_data_len);
		}
		break;

	case SPINEL_CMD_PROP_VALUE_REMOVED:
		{
			spinel_prop_key_t key = SPINEL_PROP_LAST_STATUS;
			uint8_t* value_data_ptr = NULL;
			spinel_size_t value_data_len = 0;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len);

			__ASSERT_MACROS_check(ret != -1);

			if (ret == -1) {
				return;
			}

			syslog(LOG_INFO, "[NCP->] CMD_PROP_VALUE_REMOVED(%s) tid:%d", spinel_prop_key_to_cstr(key), SPINEL_HEADER_GET_TID(cmd_data_ptr[0]));

			return handle_ncp_spinel_value_removed(key, value_data_ptr, value_data_len);
		}
		break;

	case SPINEL_CMD_PEEK_RET:
		{
			uint32_t address = 0;
			uint16_t count = 0;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiLS", NULL, NULL, &address, &count);

			__ASSERT_MACROS_check(ret != -1);

			if (ret > 0) {
				syslog(LOG_INFO, "[NCP->] CMD_PEEK_RET(0x%x,%d) tid:%d", address, count, SPINEL_HEADER_GET_TID(cmd_data_ptr[0]));
			}
		}
		break;


	default:
		break;
	}

	process_event(EVENT_NCP(command), cmd_data_ptr[0], cmd_data_ptr, cmd_data_len);
}

bool
SpinelNCPInstance::should_filter_address(const struct in6_addr &addr, uint8_t prefix_len)
{
	static const uint8_t rloc_bytes[] = {0x00,0x00,0x00,0xFF,0xFE,0x00};
	bool should_filter = false;

	if (mFilterRLOCAddresses) {
		// Filter RLOC link-local or mesh-local addresses

		if (0 == memcmp(rloc_bytes, addr.s6_addr + 8, sizeof(rloc_bytes))) {
			if (IN6_IS_ADDR_LINKLOCAL(&addr)) {
				should_filter = true;
			}

			if (buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix))
				&& (0 == memcmp(mNCPV6Prefix, &addr, sizeof(mNCPV6Prefix)))
			) {
				should_filter = true;
			}
		}
	}

	return should_filter;
}

void
SpinelNCPInstance::filter_addresses(void)
{
	std::map<struct in6_addr, UnicastAddressEntry> unicast_addresses(mUnicastAddresses);
	std::map<struct in6_addr, UnicastAddressEntry>::iterator iter;

	// We create a copy of mUnicastAddress map to iterate over
	// since `mUnicastAddresses` entries can be removed while
	// we filter and remove addresses.

	for (iter = unicast_addresses.begin(); iter != unicast_addresses.end();	++iter) {
		if (!iter->second.is_from_ncp()) {
			continue;
		}

		if (should_filter_address(iter->first, iter->second.get_prefix_len())) {
			unicast_address_was_removed(kOriginThreadNCP, iter->first);
		}
	}
}


void
SpinelNCPInstance::add_unicast_address_on_ncp(const struct in6_addr &addr, uint8_t prefix_len, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Adding address \"%s/%d\" to NCP", in6_addr_to_string(addr).c_str(), prefix_len);

	factory.set_callback(cb);

	factory.add_command(
		SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(
				SPINEL_DATATYPE_IPv6ADDR_S   // Address
				SPINEL_DATATYPE_UINT8_S      // Prefix Length
				SPINEL_DATATYPE_UINT32_S     // Valid Lifetime
				SPINEL_DATATYPE_UINT32_S     // Preferred Lifetime
			),
			SPINEL_PROP_IPV6_ADDRESS_TABLE,
			&addr,
			prefix_len,
			UINT32_MAX,
			UINT32_MAX
		)
	);

	start_new_task(factory.finish());
}

void
SpinelNCPInstance::remove_unicast_address_on_ncp(const struct in6_addr& addr, uint8_t prefix_len, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Removing address \"%s/%d\" from NCP", in6_addr_to_string(addr).c_str(), prefix_len);

	factory.set_callback(cb);

	factory.add_command(
		SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(
				SPINEL_DATATYPE_IPv6ADDR_S   // Address
				SPINEL_DATATYPE_UINT8_S      // Prefix
			),
			SPINEL_PROP_IPV6_ADDRESS_TABLE,
			&addr,
			prefix_len
		)
	);

	start_new_task(factory.finish());
}

void
SpinelNCPInstance::add_multicast_address_on_ncp(const struct in6_addr &addr, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Adding multicast address \"%s\" to NCP", in6_addr_to_string(addr).c_str());

	factory.set_callback(cb);

	factory.add_command(
		SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(
				SPINEL_DATATYPE_IPv6ADDR_S   // Address
			),
			SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE,
			&addr
		)
	);

	start_new_task(factory.finish());
}

void
SpinelNCPInstance::remove_multicast_address_on_ncp(const struct in6_addr &addr, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Removing multicast address \"%s\" from NCP", in6_addr_to_string(addr).c_str());

	factory.set_callback(cb);

	factory.add_command(
		SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(
				SPINEL_DATATYPE_IPv6ADDR_S   // Address
			),
			SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE,
			&addr
		)
	);

	start_new_task(factory.finish());
}

void
SpinelNCPInstance::add_on_mesh_prefix_on_ncp(const struct in6_addr &prefix, uint8_t prefix_len, uint8_t flags,
	bool stable, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Adding on-mesh prefix \"%s/%d\" to NCP", in6_addr_to_string(prefix).c_str(), prefix_len);

	factory.set_lock_property(SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE);
	factory.set_callback(cb);

	factory.add_command(SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(
			SPINEL_DATATYPE_IPv6ADDR_S
			SPINEL_DATATYPE_UINT8_S
			SPINEL_DATATYPE_BOOL_S
			SPINEL_DATATYPE_UINT8_S
		),
		SPINEL_PROP_THREAD_ON_MESH_NETS,
		&prefix,
		prefix_len,
		stable,
		flags
	));

	start_new_task(factory.finish());
}

void
SpinelNCPInstance::remove_on_mesh_prefix_on_ncp(const struct in6_addr &prefix, uint8_t prefix_len, uint8_t flags,
	bool stable, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Removing on-mesh prefix \"%s/%d\" from NCP", in6_addr_to_string(prefix).c_str(), prefix_len);

	factory.set_lock_property(SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE);
	factory.set_callback(cb);

	factory.add_command(SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(
			SPINEL_DATATYPE_IPv6ADDR_S
			SPINEL_DATATYPE_UINT8_S
			SPINEL_DATATYPE_BOOL_S
			SPINEL_DATATYPE_UINT8_S
		),
		SPINEL_PROP_THREAD_ON_MESH_NETS,
		&prefix,
		prefix_len,
		stable,
		flags
	));

	start_new_task(factory.finish());
}

void
SpinelNCPInstance::add_route_on_ncp(const struct in6_addr &route, uint8_t prefix_len, RoutePreference preference,
	bool stable, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Adding off-mesh route \"%s/%d\" with preference %s to NCP", in6_addr_to_string(route).c_str(),
		prefix_len, NCPControlInterface::external_route_priority_to_string(preference).c_str());

	factory.set_lock_property(SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE);
	factory.set_callback(cb);

	factory.add_command(SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(
			SPINEL_DATATYPE_IPv6ADDR_S
			SPINEL_DATATYPE_UINT8_S
			SPINEL_DATATYPE_BOOL_S
			SPINEL_DATATYPE_UINT8_S
		),
		SPINEL_PROP_THREAD_OFF_MESH_ROUTES,
		&route,
		prefix_len,
		stable,
		convert_route_preference_to_flags(preference)
	));

	start_new_task(factory.finish());
}

void
SpinelNCPInstance::remove_route_on_ncp(const struct in6_addr &route, uint8_t prefix_len, RoutePreference preference,
	bool stable, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Removing off-mesh route \"%s/%d\" with preference %s from NCP", in6_addr_to_string(route).c_str(),
		prefix_len, NCPControlInterface::external_route_priority_to_string(preference).c_str());

	factory.set_lock_property(SPINEL_PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE);
	factory.set_callback(cb);

	factory.add_command(SpinelPackData(
		SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(
			SPINEL_DATATYPE_IPv6ADDR_S
			SPINEL_DATATYPE_UINT8_S
			SPINEL_DATATYPE_BOOL_S
			SPINEL_DATATYPE_UINT8_S
		),
		SPINEL_PROP_THREAD_OFF_MESH_ROUTES,
		&route,
		prefix_len,
		stable,
		convert_route_preference_to_flags(preference)
	));

	start_new_task(factory.finish());
}

SpinelNCPInstance::RoutePreference
SpinelNCPInstance::convert_flags_to_route_preference(uint8_t flags)
{
	RoutePreference preference = NCPControlInterface::ROUTE_MEDIUM_PREFERENCE;

	switch (flags & SPINEL_NET_FLAG_PREFERENCE_MASK) {
	case SPINEL_ROUTE_PREFERENCE_HIGH:
		preference = NCPControlInterface::ROUTE_HIGH_PREFERENCE;
		break;

	case SPINEL_ROUTE_PREFERENCE_MEDIUM:
		preference = NCPControlInterface::ROUTE_MEDIUM_PREFERENCE;
		break;

	case SPINEL_ROUTE_PREFERENCE_LOW:
		preference = NCPControlInterface::ROUTE_LOW_PREFRENCE;
		break;

	default:
		syslog(LOG_WARNING, "Invalid RoutePreference flag 0x%02x (using MEDIUM instead)", flags);
		break;
	}

	return preference;
}

uint8_t
SpinelNCPInstance::convert_route_preference_to_flags(RoutePreference preference)
{
	uint8_t flags = SPINEL_ROUTE_PREFERENCE_MEDIUM;

	switch (preference) {
	case NCPControlInterface::ROUTE_HIGH_PREFERENCE:
		flags = SPINEL_ROUTE_PREFERENCE_HIGH;
		break;

	case NCPControlInterface::ROUTE_MEDIUM_PREFERENCE:
		flags = SPINEL_ROUTE_PREFERENCE_MEDIUM;
		break;

	case NCPControlInterface::ROUTE_LOW_PREFRENCE:
		flags = SPINEL_ROUTE_PREFERENCE_LOW;
		break;
	}

	return flags;
}

bool
SpinelNCPInstance::is_busy(void)
{
	return NCPInstanceBase::is_busy()
		|| !mTaskQueue.empty();
}

void
SpinelNCPInstance::process(void)
{
	NCPInstanceBase::process();

	mVendorCustom.process();

	if (!is_initializing_ncp() && mTaskQueue.empty()) {
		bool x = mPcapManager.is_enabled();

		if (mIsPcapInProgress != x) {
			SpinelNCPTaskSendCommand::Factory factory(this);

			mIsPcapInProgress = x;

			factory.add_command(SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
				SPINEL_PROP_MAC_RAW_STREAM_ENABLED,
				mIsPcapInProgress
			));

			if (mIsPcapInProgress) {
				factory.add_command(SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S),
					SPINEL_PROP_NET_IF_UP,
					true
				));
				if (!ncp_state_is_joining_or_joined(get_ncp_state())) {
					factory.add_command(SpinelPackData(
						SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S),
						SPINEL_PROP_MAC_PROMISCUOUS_MODE,
						SPINEL_MAC_PROMISCUOUS_MODE_FULL
					));
				}
			} else {
				factory.add_command(SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S),
					SPINEL_PROP_MAC_PROMISCUOUS_MODE,
					SPINEL_MAC_PROMISCUOUS_MODE_OFF
				));
			}

			start_new_task(factory.finish());
			NCPInstanceBase::process();
		}
	}
}
