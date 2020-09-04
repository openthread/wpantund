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

#include <algorithm>
#include <inttypes.h>
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

#define kWPANTUND_Allowlist_RssiOverrideDisabled    127
#define kWPANTUND_SpinelPropValueDumpLen            8

using namespace nl;
using namespace wpantund;

WPANTUND_DEFINE_NCPINSTANCE_PLUGIN(spinel, SpinelNCPInstance);

void
SpinelNCPInstance::handle_ncp_debug_stream(const uint8_t* data_ptr, int data_len)
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

static const char *
ot_log_level_to_string(uint8_t log_level)
{
	const char *retval = "----";

	switch (log_level)
	{
	case SPINEL_NCP_LOG_LEVEL_EMERG:
		retval = "EMRG";
		break;

	case SPINEL_NCP_LOG_LEVEL_ALERT:
		retval = "ALRT";
		break;

	case SPINEL_NCP_LOG_LEVEL_CRIT:
		retval = "CRIT";
		break;

	case SPINEL_NCP_LOG_LEVEL_ERR:
		retval = "ERR ";
		break;

	case SPINEL_NCP_LOG_LEVEL_WARN:
		retval = "WARN";
		break;

	case SPINEL_NCP_LOG_LEVEL_NOTICE:
		retval = "NOTE";
		break;

	case SPINEL_NCP_LOG_LEVEL_INFO:
		retval = "INFO";
		break;

	case SPINEL_NCP_LOG_LEVEL_DEBUG:
		retval = "DEBG";
		break;
	}

	return retval;
}

static const char *
ot_log_region_to_string(unsigned int log_region)
{
	const char *retval = "---------";

	switch (log_region)
	{
	case SPINEL_NCP_LOG_REGION_OT_API:
		retval = "-API-----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_MLE:
		retval = "-MLE-----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_COAP:
		retval = "-COAP----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_ARP:
		retval = "-ARP-----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_NET_DATA:
		retval = "-N-DATA--";
		break;

	case SPINEL_NCP_LOG_REGION_OT_ICMP:
		retval = "-ICMP----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_IP6:
		retval = "-IP6-----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_MAC:
		retval = "-MAC-----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_MEM:
		retval = "-MEM-----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_NCP:
		retval = "-NCP-----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_MESH_COP:
		retval = "-MESH-CP-";
		break;

	case SPINEL_NCP_LOG_REGION_OT_NET_DIAG:
		retval = "-DIAG----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_PLATFORM:
		retval = "-PLAT----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_CORE:
		retval = "-CORE----";
		break;

	case SPINEL_NCP_LOG_REGION_OT_UTIL:
		retval = "-UTIL----";
		break;
	}

	return retval;
}

void
SpinelNCPInstance::handle_ncp_log_stream(const uint8_t *data_in, int data_len)
{
	spinel_ssize_t len;
	char prefix_string[NCP_DEBUG_LINE_LENGTH_MAX + 1];
	const char *log_string;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		SPINEL_DATATYPE_UTF8_S,
		&log_string
	);
	require(len >= 0, bail);

	data_in += len;
	data_len -= len;

	prefix_string[0] = 0;

	if ((data_len > 0) && mCapabilities.count(SPINEL_CAP_OPENTHREAD_LOG_METADATA)) {
		uint8_t log_level;
		unsigned int log_region;
		uint64_t log_timestamp;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			(
				SPINEL_DATATYPE_UINT8_S
				SPINEL_DATATYPE_UINT_PACKED_S
			),
			&log_level,
			&log_region
		);
		require(len >= 0, bail);

		data_in += len;
		data_len -= len;

		if (data_len >= sizeof(log_timestamp)) {
			len = spinel_datatype_unpack(
				data_in,
				data_len,
				SPINEL_DATATYPE_UINT64_S,
				&log_timestamp
			);
			require(len >= 0, bail);

			snprintf(
				prefix_string,
				sizeof(prefix_string),
				"[%013llu][%s]%s: ",
				static_cast<unsigned long long>(log_timestamp),
				ot_log_level_to_string(log_level),
				ot_log_region_to_string(log_region)
			);
		} else {
			snprintf(
				prefix_string,
				sizeof(prefix_string),
				"[%s]%s: ",
				ot_log_level_to_string(log_level),
				ot_log_region_to_string(log_region)
			);
		}
	}

	syslog(LOG_WARNING, "NCP => %s%s\n", prefix_string, log_string);

bail:
	return;
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
	mFilterALOCAddresses = true;
	mTickleOnHostDidWake = false;
	mIsPcapInProgress = false;
	mLastHeader = 0;
	mLastTID = 0;
	mNetworkKeyIndex = 0;
	mOutboundBufferEscapedLen = 0;
	mOutboundBufferLen = 0;
	mOutboundBufferSent = 0;
	mOutboundBufferType = 0;
#if WPANTUND_NCP_RESET_EXPECTED_ON_START
	mResetIsExpected = true;
#else
	mResetIsExpected = false;
#endif
	mSetSteeringDataWhenJoinable = false;
	mSubPTIndex = 0;
	mTXPower = 0;
	mThreadMode = 0;
	mXPANIDWasExplicitlySet = false;
	mChannelManagerNewChannel = 0;
	mMacFilterFixedRssi = -100;
	mSupportedChannelMask = 0;
	mPreferredChannelMask = 0;
	mJoinerDiscernerBitLength = 0;
	mCommissionerEnergyScanResult.clear();
	mCommissionerPanIdConflictResult.clear();

	mSettings.clear();

	regsiter_all_get_handlers();
	regsiter_all_set_handlers();
	regsiter_all_insert_handlers();
	regsiter_all_remove_handlers();

	memset(mSteeringDataAddress, 0xff, sizeof(mSteeringDataAddress));

	if (!settings.empty()) {
		int status;
		Settings::const_iterator iter;

		for(iter = settings.begin(); iter != settings.end(); iter++) {
			if (!NCPInstanceBase::setup_property_supported_by_class(iter->first)) {
				status = static_cast<NCPControlInterface&>(get_control_interface())
					.property_set_value(iter->first, iter->second);

				if (status != 0 && status != kWPANTUNDStatus_InProgress) {
					syslog(LOG_WARNING, "Attempt to set property \"%s\" failed with err %s", iter->first.c_str(), wpantund_status_to_cstr(status));
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
		"RxOnWhenIdle:%s FTD:%s FullNetData:%s SecDataReq:%s",
		((mode & SPINEL_THREAD_MODE_RX_ON_WHEN_IDLE) != 0)     ? "yes" : "no",
		((mode & SPINEL_THREAD_MODE_FULL_THREAD_DEV) != 0)     ? "yes" : "no",
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

std::set<std::string>
SpinelNCPInstance::get_supported_property_keys()const
{
	std::set<std::string> properties (NCPInstanceBase::get_supported_property_keys());

	properties.insert(kWPANTUNDProperty_ConfigNCPDriverName);
	properties.insert(kWPANTUNDProperty_NCPChannel);
	properties.insert(kWPANTUNDProperty_NCPChannelMask);
	properties.insert(kWPANTUNDProperty_NCPPreferredChannelMask);
	properties.insert(kWPANTUNDProperty_NCPFrequency);
	properties.insert(kWPANTUNDProperty_NCPRSSI);
	properties.insert(kWPANTUNDProperty_NCPExtendedAddress);
	properties.insert(kWPANTUNDProperty_NCPCCAFailureRate);
	properties.insert(kWPANTUNDProperty_NCPCapabilities);

	if (mCapabilities.count(SPINEL_CAP_ROLE_SLEEPY)) {
		properties.insert(kWPANTUNDProperty_NCPSleepyPollInterval);
	}

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
	properties.insert(kWPANTUNDProperty_ThreadChildTimeout);
	properties.insert(kWPANTUNDProperty_ThreadRouterTable);
	properties.insert(kWPANTUNDProperty_ThreadParent);
	properties.insert(kWPANTUNDProperty_ThreadOffMeshRoutes);
	properties.insert(kWPANTUNDProperty_NetworkPartitionId);
	properties.insert(kWPANTUNDProperty_ThreadRouterUpgradeThreshold);
	properties.insert(kWPANTUNDProperty_ThreadRouterDowngradeThreshold);
	properties.insert(kWPANTUNDProperty_ThreadActiveDataset);
	properties.insert(kWPANTUNDProperty_ThreadPendingDataset);
	properties.insert(kWPANTUNDProperty_ThreadAddressCacheTable);

	if (mCapabilities.count(SPINEL_CAP_ERROR_RATE_TRACKING)) {
		properties.insert(kWPANTUNDProperty_ThreadNeighborTableErrorRates);
	}

	if (mCapabilities.count(SPINEL_CAP_THREAD_COMMISSIONER)) {
		properties.insert(kWPANTUNDProperty_CommissionerState);
		properties.insert(kWPANTUNDProperty_CommissionerProvisioningUrl);
		properties.insert(kWPANTUNDProperty_CommissionerSessionId);
		properties.insert(kWPANTUNDProperty_CommissionerJoiners);
	}

	if (mCapabilities.count(SPINEL_CAP_THREAD_JOINER)) {
		properties.insert(kWPANTUNDProperty_JoinerState);
		properties.insert(kWPANTUNDProperty_JoinerDiscernerValue);
		properties.insert(kWPANTUNDProperty_JoinerDiscernerBitLength);
	}

	if (mCapabilities.count(SPINEL_CAP_POSIX)) {
		properties.insert(kWPANTUNDProperty_POSIXAppRCPVersion);
	}

	if (mCapabilities.count(SPINEL_CAP_COUNTERS)) {
		properties.insert(kWPANTUNDProperty_NCPCounterAllMac);
		properties.insert(kWPANTUNDProperty_NCPCounter_TX_IP_SEC_TOTAL);
		properties.insert(kWPANTUNDProperty_NCPCounter_TX_IP_INSEC_TOTAL);
		properties.insert(kWPANTUNDProperty_NCPCounter_TX_IP_DROPPED);
		properties.insert(kWPANTUNDProperty_NCPCounter_RX_IP_SEC_TOTAL);
		properties.insert(kWPANTUNDProperty_NCPCounter_RX_IP_INSEC_TOTAL);
		properties.insert(kWPANTUNDProperty_NCPCounter_RX_IP_DROPPED);
		properties.insert(kWPANTUNDProperty_NCPCounter_TX_SPINEL_TOTAL);
		properties.insert(kWPANTUNDProperty_NCPCounter_RX_SPINEL_TOTAL);
		properties.insert(kWPANTUNDProperty_NCPCounter_RX_SPINEL_ERR);
		properties.insert(kWPANTUNDProperty_NCPCounterThreadMle);
		properties.insert(kWPANTUNDProperty_NCPCounterAllIPv6);
	}

	if (mCapabilities.count(SPINEL_CAP_MAC_ALLOWLIST)) {
		properties.insert(kWPANTUNDProperty_MACAllowlistEnabled);
		properties.insert(kWPANTUNDProperty_MACAllowlistEntries);
		properties.insert(kWPANTUNDProperty_MACDenylistEnabled);
		properties.insert(kWPANTUNDProperty_MACDenylistEntries);
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

	if (mCapabilities.count(SPINEL_CAP_NEST_LEGACY_INTERFACE)) {
		properties.insert(kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix);
	}

	if (mCapabilities.count(SPINEL_CAP_TIME_SYNC)) {
		properties.insert(kWPANTUNDProperty_TimeSync_NetworkTime);
		properties.insert(kWPANTUNDProperty_TimeSync_Period);
		properties.insert(kWPANTUNDProperty_TimeSync_XtalThreshold);
	}

	if (mCapabilities.count(SPINEL_CAP_THREAD_SERVICE)) {
		properties.insert(kWPANTUNDProperty_ThreadServices);
		properties.insert(kWPANTUNDProperty_ThreadLeaderServices);
	}

	if (mCapabilities.count(SPINEL_CAP_RADIO_COEX)) {
		properties.insert(kWPANTUNDProperty_NCPCoexEnable);
		properties.insert(kWPANTUNDProperty_NCPCoexMetrics);
	}

	if (mCapabilities.count(SPINEL_CAP_OPENTHREAD_LOG_METADATA)) {
		properties.insert(kWPANTUNDProperty_OpenThreadLogTimestampBase);
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
unpack_commissioner_state(const uint8_t *data_in, spinel_size_t data_len, boost::any& value)
{
	spinel_ssize_t len;
	uint8_t state;
	int ret = kWPANTUNDStatus_Ok;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		SPINEL_DATATYPE_UINT8_S,
		&state
	);

	if (len > 0) {
		switch (state) {
		case SPINEL_MESHCOP_COMMISSIONER_STATE_DISABLED:
			value = std::string(kWPANTUNDCommissionerState_Disabled);
			break;
		case SPINEL_MESHCOP_COMMISSIONER_STATE_PETITION:
			value = std::string(kWPANTUNDCommissionerState_Petition);
			break;
		case SPINEL_MESHCOP_COMMISSIONER_STATE_ACTIVE:
			value = std::string(kWPANTUNDCommissionerState_Active);
			break;
		default:
			ret = kWPANTUNDStatus_Failure;
			break;
		}
	} else {
		ret = kWPANTUNDStatus_Failure;
	}

	return ret;
}

static int
unpack_commissioner_joiners(const uint8_t *data_in, spinel_size_t data_len, boost::any &value)
{
	spinel_ssize_t len;
	std::list<std::string> result;
	char c_string[300];
	int ret = kWPANTUNDStatus_Ok;

	while (data_len > 0) {
		const uint8_t *joiner_info_in;
		spinel_size_t joiner_info_len;
		uint32_t joiner_timeout;
		const char *joiner_pskd;
		const spinel_eui64_t *joiner_eui64 = NULL;
		uint8_t discerner_bit_len;
		uint64_t discerner_value;
		bool any_joiner = false;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_DATA_WLEN_S // Joiner Info struct (empty or EUI64 or Discerner)
				SPINEL_DATATYPE_UINT32_S
				SPINEL_DATATYPE_UTF8_S
			),
			&joiner_info_in, &joiner_info_len,
			&joiner_timeout,
			&joiner_pskd
		);

		require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		data_in += len;
		data_len -= len;

		switch (joiner_info_len)
		{
		case 0:
			any_joiner = true;
			break;

		case sizeof(spinel_eui64_t):
			joiner_eui64 = (const spinel_eui64_t *)joiner_info_in;
			break;

		default:
			len = spinel_datatype_unpack(
				joiner_info_in,
				joiner_info_len,
				(
					SPINEL_DATATYPE_UINT8_S
					SPINEL_DATATYPE_UINT64_S
				),
				&discerner_bit_len,
				&discerner_value
			);
			joiner_eui64 = NULL;
			break;
		}

		if (any_joiner) {
			 snprintf(c_string, sizeof(c_string), "any joiner, psk:%s, timeout:%.2f", joiner_pskd, joiner_timeout/1000.0);

		} else if (joiner_eui64 != NULL) {
			snprintf(c_string, sizeof(c_string), "eui64:%02X%02X%02X%02X%02X%02X%02X%02X, psk:%s, timeout:%.2f",
				joiner_eui64->bytes[0], joiner_eui64->bytes[1], joiner_eui64->bytes[2], joiner_eui64->bytes[3],
				joiner_eui64->bytes[4], joiner_eui64->bytes[5], joiner_eui64->bytes[6], joiner_eui64->bytes[7],
				joiner_pskd, joiner_timeout/1000.0);

		} else {
			snprintf(c_string, sizeof(c_string), "discerner:%" PRIu64 ", bit-len:%d, psk:%s, timeout:%.2f",
					 discerner_value, discerner_bit_len, joiner_pskd, joiner_timeout/1000.0);
		}

		result.push_back(std::string(c_string));
	}

	value = result;

bail:
	return ret;
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
unpack_mac_allowlist_entries(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
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

		require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		if (as_val_map) {
			entry.clear();
			entry[kWPANTUNDValueMapKey_Allowlist_ExtAddress] = Data(eui64->bytes, sizeof(spinel_eui64_t));

			if (rssi != kWPANTUND_Allowlist_RssiOverrideDisabled) {
				entry[kWPANTUNDValueMapKey_Allowlist_Rssi] = rssi;
			}

			result_as_val_map.push_back(entry);

		} else {
			char c_string[500];
			int index;

			index = snprintf(c_string, sizeof(c_string), "%02X%02X%02X%02X%02X%02X%02X%02X",
							 eui64->bytes[0], eui64->bytes[1], eui64->bytes[2], eui64->bytes[3],
							 eui64->bytes[4], eui64->bytes[5], eui64->bytes[6], eui64->bytes[7]);

			if (rssi != kWPANTUND_Allowlist_RssiOverrideDisabled) {
				if (index >= 0 && index < sizeof(c_string)) {
					snprintf(c_string + index, sizeof(c_string) - index, "   fixed-rssi:%d", rssi);
				}
			}

			result_as_string.push_back(std::string(c_string));
		}

		data_len -= len;
		data_in += len;
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
unpack_mac_denylist_entries(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
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
			entry[kWPANTUNDValueMapKey_Allowlist_ExtAddress] = Data(eui64->bytes, sizeof(spinel_eui64_t));
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
unpack_channel_occupancy(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
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
unpack_ncp_counters_mle(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	std::list<std::string> result_as_string;
	ValueMap result_as_val_map;
	int ret = kWPANTUNDStatus_Ok;
	spinel_ssize_t len;

	const char *mle_counter_names[] = {
		kWPANTUNDValueMapKey_MleCounter_DisabledRole,
		kWPANTUNDValueMapKey_MleCounter_DetachedRole,
		kWPANTUNDValueMapKey_MleCounter_ChildRole,
		kWPANTUNDValueMapKey_MleCounter_RouterRole,
		kWPANTUNDValueMapKey_MleCounter_LeaderRole,
		kWPANTUNDValueMapKey_MleCounter_AttachAttempts,
		kWPANTUNDValueMapKey_MleCounter_PartitionIdChanges,
		kWPANTUNDValueMapKey_MleCounter_BetterPartitionAttaches,
		kWPANTUNDValueMapKey_MleCounter_ParentChanges,
		NULL
	};

	const char **counter_names = mle_counter_names;

	while (*counter_names != NULL) {
		uint16_t counter_value;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_UINT16_S,
			&counter_value
		);

		require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		data_in  += len;
		data_len -= len;

		if (!as_val_map) {
			char c_string[200];
			snprintf(c_string, sizeof(c_string), "%-20s = %d", *counter_names, counter_value);
			result_as_string.push_back(std::string(c_string));
		} else {
			result_as_val_map[*counter_names] = counter_value;
		}

		counter_names++;
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
unpack_ncp_counters_ipv6(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	std::list<std::string> result_as_string;
	ValueMap result_as_val_map;
	int ret = kWPANTUNDStatus_Ok;
	spinel_ssize_t len;

	const char *tx_counter_names[] = {
		kWPANTUNDValueMapKey_IPv6Counter_TxSuccess,
		kWPANTUNDValueMapKey_IPv6Counter_TxFailure,
		NULL
	};

	const char *rx_counter_names[] = {
		kWPANTUNDValueMapKey_IPv6Counter_RxSuccess,
		kWPANTUNDValueMapKey_IPv6Counter_RxFailure,
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
unpack_coex_metrics(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	std::list<std::string> result_as_string;
	ValueMap result_as_val_map;
	int ret = kWPANTUNDStatus_Ok;
	spinel_ssize_t len;
	bool stopped;
	uint32_t num_grant_glitch;

	const char *tx_coex_metrics_names[] = {
		kWPANTUNDValueMapKey_CoexMetrics_NumTxRequest,
		kWPANTUNDValueMapKey_CoexMetrics_NumTxGrantImmediate,
		kWPANTUNDValueMapKey_CoexMetrics_NumTxGrantWait,
		kWPANTUNDValueMapKey_CoexMetrics_NumTxGrantWaitActivated,
		kWPANTUNDValueMapKey_CoexMetrics_NumTxGrantWaitTimeout,
		kWPANTUNDValueMapKey_CoexMetrics_NumTxGrantDeactivatedDuringRequest,
		kWPANTUNDValueMapKey_CoexMetrics_NumTxDelayedGrant,
		kWPANTUNDValueMapKey_CoexMetrics_AvgTxRequestToGrantTime,
		NULL
	};

	const char *rx_coex_metrics_names[] = {
		kWPANTUNDValueMapKey_CoexMetrics_NumRxRequest,
		kWPANTUNDValueMapKey_CoexMetrics_NumRxGrantImmediate,
		kWPANTUNDValueMapKey_CoexMetrics_NumRxGrantWait,
		kWPANTUNDValueMapKey_CoexMetrics_NumRxGrantWaitActivated,
		kWPANTUNDValueMapKey_CoexMetrics_NumRxGrantWaitTimeout,
		kWPANTUNDValueMapKey_CoexMetrics_NumRxGrantDeactivatedDuringRequest,
		kWPANTUNDValueMapKey_CoexMetrics_NumRxDelayedGrant,
		kWPANTUNDValueMapKey_CoexMetrics_AvgRxRequestToGrantTime,
		kWPANTUNDValueMapKey_CoexMetrics_NumRxGrantNone,
		NULL
	};

	for (int index = 0; index < 2; index++)
	{
		const char **counter_names;
		const uint8_t *struct_in = NULL;
		unsigned int struct_len = 0;
		spinel_size_t len;

		counter_names = (index == 0) ? tx_coex_metrics_names : rx_coex_metrics_names;

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
				snprintf(c_string, sizeof(c_string), "%-20s = %u", *counter_names, counter_value);
				result_as_string.push_back(std::string(c_string));
			} else {
				result_as_val_map[*counter_names] = counter_value;
			}

			counter_names++;
		}
	}

	len = spinel_datatype_unpack(data_in, data_len, SPINEL_DATATYPE_BOOL_S, &stopped);
	require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
	data_in += len;
	data_len -= len;

	len = spinel_datatype_unpack(data_in, data_len, SPINEL_DATATYPE_UINT32_S, &num_grant_glitch);
	require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
	data_in += len;
	data_len -= len;

	if (!as_val_map) {
		char c_string[200];
		snprintf(c_string, sizeof(c_string), "%-20s = %u", kWPANTUNDValueMapKey_CoexMetrics_Stopped, stopped);
		result_as_string.push_back(std::string(c_string));

		snprintf(c_string, sizeof(c_string), "%-20s = %u", kWPANTUNDValueMapKey_CoexMetrics_NumGrantGlitch, num_grant_glitch);
		result_as_string.push_back(std::string(c_string));
	} else {
		result_as_val_map[kWPANTUNDValueMapKey_CoexMetrics_Stopped] = stopped;
		result_as_val_map[kWPANTUNDValueMapKey_CoexMetrics_NumGrantGlitch] = num_grant_glitch;
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
unpack_parent_info(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	std::string result_as_string;
	ValueMap result_as_val_map;
	int ret = kWPANTUNDStatus_Ok;
	spinel_ssize_t len;
	const spinel_eui64_t *eui64 = NULL;
	uint16_t rloc16;
	uint32_t age;
	int8_t average_rssi;
	int8_t last_rssi;
	uint8_t lqin;
	uint8_t lqout;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		(
			SPINEL_DATATYPE_EUI64_S         // EUI64 Address
			SPINEL_DATATYPE_UINT16_S        // Rloc16
			SPINEL_DATATYPE_UINT32_S        // Age
			SPINEL_DATATYPE_INT8_S          // Average RSSI
			SPINEL_DATATYPE_INT8_S          // Last RSSI
			SPINEL_DATATYPE_UINT8_S         // LinkQuality In
			SPINEL_DATATYPE_UINT8_S         // LinkQuality Out
		),
		&eui64,
		&rloc16,
		&age,
		&average_rssi,
		&last_rssi,
		&lqin,
		&lqout
	);

	require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

	if (!as_val_map) {
		char c_string[200];

		snprintf(c_string, sizeof(c_string),
			"%02X%02X%02X%02X%02X%02X%02X%02X, "
			"RLOC16:%04x, "
			"Age:%u, "
			"AveRssi:%d, "
			"LastRssi:%d, "
			"LQIn:%d, "
			"LQOut:%d",
			eui64->bytes[0], eui64->bytes[1], eui64->bytes[2], eui64->bytes[3],
			eui64->bytes[4], eui64->bytes[5], eui64->bytes[6], eui64->bytes[7],
			rloc16,
			age,
			average_rssi,
			last_rssi,
			lqin,
			lqout
		);

		value = std::string(c_string);

	} else {
		ValueMap map;
		uint64_t ext_addr;

		ext_addr  = (uint64_t) eui64->bytes[7];
		ext_addr |= (uint64_t) eui64->bytes[6] << 8;
		ext_addr |= (uint64_t) eui64->bytes[5] << 16;
		ext_addr |= (uint64_t) eui64->bytes[4] << 24;
		ext_addr |= (uint64_t) eui64->bytes[3] << 32;
		ext_addr |= (uint64_t) eui64->bytes[2] << 40;
		ext_addr |= (uint64_t) eui64->bytes[1] << 48;
		ext_addr |= (uint64_t) eui64->bytes[0] << 56;

		map[kWPANTUNDValueMapKey_NetworkTopology_ExtAddress]    = boost::any(ext_addr);
		map[kWPANTUNDValueMapKey_NetworkTopology_RLOC16]        = boost::any(rloc16);
		map[kWPANTUNDValueMapKey_NetworkTopology_Age]           = boost::any(age);
		map[kWPANTUNDValueMapKey_NetworkTopology_AverageRssi]   = boost::any(average_rssi);
		map[kWPANTUNDValueMapKey_NetworkTopology_LastRssi]      = boost::any(last_rssi);
		map[kWPANTUNDValueMapKey_NetworkTopology_LinkQualityIn] = boost::any(lqin);

		value = map;
	}

bail:
	return ret;
}

static const char *
cache_table_entry_state_to_string(uint8_t state)
{
	const char *str;

	switch (state)
	{
	case SPINEL_ADDRESS_CACHE_ENTRY_STATE_CACHED:
		str = kWPANTUNDCacheTableEntryState_Cached;
		break;
	case SPINEL_ADDRESS_CACHE_ENTRY_STATE_SNOOPED:
		str = kWPANTUNDCacheTableEntryState_Snooped;
		break;
	case SPINEL_ADDRESS_CACHE_ENTRY_STATE_QUERY:
		str = kWPANTUNDCacheTableEntryState_Query;
		break;
	case SPINEL_ADDRESS_CACHE_ENTRY_STATE_RETRY_QUERY:
		str = kWPANTUNDCacheTableEntryState_RetryQuery;
		break;
	default:
		str = "unknown";
		break;
	}

	return str;
}

static int
unpack_address_cache_table(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	std::list<std::string> result_as_string;
	std::list<ValueMap> result_as_val_map;
	int ret = kWPANTUNDStatus_Ok;

	while (data_len > 0)
	{
		spinel_ssize_t len;
		struct in6_addr *target_address = NULL;
		uint16_t target_rloc16;
		uint8_t age;
		uint8_t state;
		bool valid_last_trans;
		uint32_t last_trans_time;
		struct in6_addr *ml_eid = NULL;
		bool can_evict;
		uint16_t timeout;
		uint16_t retry_delay;
		const uint8_t *cached_struct_in = NULL;
		unsigned int cached_struct_len = 0;
		const uint8_t *other_struct_in = NULL;
		unsigned int other_struct_len = 0;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_IPv6ADDR_S    // Target address
				SPINEL_DATATYPE_UINT16_S      // RLOC16
				SPINEL_DATATYPE_UINT8_S       // Age
				SPINEL_DATATYPE_UINT8_S       // State
				SPINEL_DATATYPE_DATA_WLEN_S   // Cached struct info
				SPINEL_DATATYPE_DATA_WLEN_S   // Other struct info
			),
			&target_address,
			&target_rloc16,
			&age,
			&state,
			&cached_struct_in, &cached_struct_len,
			&other_struct_in, &other_struct_len
		);

		require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		data_in += len;
		data_len -= len;

		if (state == SPINEL_ADDRESS_CACHE_ENTRY_STATE_CACHED) {

			len = spinel_datatype_unpack(
				cached_struct_in,
				cached_struct_len,
				(
					SPINEL_DATATYPE_BOOL_S      // Is Last Transaction Time valid?
					SPINEL_DATATYPE_UINT32_S    // Last Transaction Time
					SPINEL_DATATYPE_IPv6ADDR_S  // Mesh-local EID
				),
				&valid_last_trans,
				&last_trans_time,
				&ml_eid
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

		} else {

			len = spinel_datatype_unpack(
				other_struct_in,
				other_struct_len,
				(
					SPINEL_DATATYPE_BOOL_S      // Can evict?
					SPINEL_DATATYPE_UINT16_S    // Timeout
					SPINEL_DATATYPE_UINT16_S    // Retry delay
				),
				&can_evict,
				&timeout,
				&retry_delay
			);

			require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);
		}

		if (!as_val_map) {
			char c_string[500];
			int index = 0;

			index += snprintf(
				c_string + index, sizeof(c_string) - index,
				"%s -> 0x%04x, Age:%d, State:%s",
				in6_addr_to_string(*target_address).c_str(),
				target_rloc16,
				age,
				cache_table_entry_state_to_string(state)
			);

			if (state == SPINEL_ADDRESS_CACHE_ENTRY_STATE_CACHED) {
				if (valid_last_trans) {
					index += snprintf(
						c_string + index, sizeof(c_string) - index,
						", LastTrans:%u, ML-EID:%s",
						last_trans_time,
						in6_addr_to_string(*ml_eid).c_str()
					);
				}
			} else {
				index += snprintf(
					c_string + index, sizeof(c_string) - index,
					", CanEvict:%s, Timeout:%d, RetryDelay:%d",
					can_evict ? "yes" : "no",
					timeout,
					retry_delay
				);
			}

			result_as_string.push_back(std::string(c_string));

		} else {
			ValueMap entry;

			entry[kWPANTUNDValueMapKey_AddressCacheTable_Address] = boost::any(in6_addr_to_string(*target_address));
			entry[kWPANTUNDValueMapKey_AddressCacheTable_RLOC16]  = boost::any(target_rloc16);
			entry[kWPANTUNDValueMapKey_AddressCacheTable_Age]     = boost::any(age);
			entry[kWPANTUNDValueMapKey_AddressCacheTable_State]   = boost::any(std::string(cache_table_entry_state_to_string(state)));

			if (state == SPINEL_ADDRESS_CACHE_ENTRY_STATE_CACHED) {
				if (valid_last_trans) {
					entry[kWPANTUNDValueMapKey_AddressCacheTable_LastTrans]    = boost::any(last_trans_time);
					entry[kWPANTUNDValueMapKey_AddressCacheTable_MeshLocalEID] = boost::any(in6_addr_to_string(*ml_eid));
				}
			} else {
				entry[kWPANTUNDValueMapKey_AddressCacheTable_CanEvict]   = boost::any(can_evict);
				entry[kWPANTUNDValueMapKey_AddressCacheTable_Timeout]    = boost::any(timeout);
				entry[kWPANTUNDValueMapKey_AddressCacheTable_RetryDelay] = boost::any(retry_delay);
			}

			result_as_val_map.push_back(entry);
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
unpack_mesh_local_prefix(const uint8_t *data_in, spinel_size_t data_len, boost::any &value)
{
	spinel_ssize_t len;
	struct in6_addr *addr;
	uint8_t prefix_len;
	int ret = kWPANTUNDStatus_Failure;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		(
			SPINEL_DATATYPE_IPv6ADDR_S
			SPINEL_DATATYPE_UINT8_S
		),
		&addr,
		&prefix_len
	);

	if (len > 0)
	{
		char str[10];
		snprintf(str, sizeof(str), "/%d", prefix_len);

		value = boost::any(in6_addr_to_string(*addr) + std::string(str));
		ret = kWPANTUNDStatus_Ok;
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

static int
unpack_server_leader_services_as_any(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	int ret = kWPANTUNDStatus_Ok;
	spinel_ssize_t len;
	uint8_t service_id;
	uint32_t enterprise_number;
	const uint8_t *service_data;
	spinel_size_t service_data_len;
	bool stable;
	const uint8_t *server_data;
	spinel_size_t server_data_len;
	uint16_t rloc16;
	int num_service = 0;
	char c_string[500];

	std::list<ValueMap> result_as_val_map_list;
	std::list<std::string> result_as_string_list;

	while (data_len > 0) {
		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_UINT8_S		// Service ID
				SPINEL_DATATYPE_UINT32_S    // Enterprise Number
				SPINEL_DATATYPE_DATA_WLEN_S // Service Data
				SPINEL_DATATYPE_BOOL_S      // stable
				SPINEL_DATATYPE_DATA_WLEN_S // Server Data
				SPINEL_DATATYPE_UINT16_S    // RLOC
			),
			&service_id,
			&enterprise_number,
			&service_data,
			&service_data_len,
			&stable,
			&server_data,
			&server_data_len,
			&rloc16
		);

		if (len <= 0) {
			break;
		}

		if (as_val_map) {
			ValueMap result_as_val_map;
			result_as_val_map[kWPANTUNDValueMapKey_Service_ServiceId] = service_id;
			result_as_val_map[kWPANTUNDValueMapKey_Service_EnterpriseNumber] = enterprise_number;
			result_as_val_map[kWPANTUNDValueMapKey_Service_ServiceData] = Data(service_data, service_data_len);
			result_as_val_map[kWPANTUNDValueMapKey_Service_Stable] = stable;
			result_as_val_map[kWPANTUNDValueMapKey_Service_ServerData] = Data(server_data, server_data_len);
			result_as_val_map[kWPANTUNDValueMapKey_Service_RLOC16] = rloc16;
			result_as_val_map_list.push_back(result_as_val_map);
		} else {
			snprintf(c_string, sizeof(c_string), "ServiceId:%01x, EnterpriseNumber:%u, Stable:%d, RLOC16:%04x", service_id, enterprise_number, stable, rloc16);
			result_as_string_list.push_back(std::string(c_string));
		}

		num_service++;

		data_in += len;
		data_len -= len;
	}

	if (as_val_map) {
		value = result_as_val_map_list;
	} else {
		value = result_as_string_list;
	}

	return ret;
}

static int
unpack_meshcop_joiner_state(const uint8_t *data_in, spinel_size_t data_len, boost::any &value)
{
	spinel_ssize_t len;
	uint8_t joiner_state;
	int ret = kWPANTUNDStatus_Ok;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		SPINEL_DATATYPE_UINT8_S,
		&joiner_state
	);

	require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

	switch (joiner_state) {
	case SPINEL_MESHCOP_JOINER_STATE_IDLE:
		value = std::string(kWPANTUNDThreadJoinerState_Idle);
		break;

	case SPINEL_MESHCOP_JOINER_STATE_DISCOVER:
		value = std::string(kWPANTUNDThreadJoinerState_Discover);
		break;

	case SPINEL_MESHCOP_JOINER_STATE_CONNECTING:
		value = std::string(kWPANTUNDThreadJoinerState_Connecting);
		break;

	case SPINEL_MESHCOP_JOINER_STATE_CONNECTED:
		value = std::string(kWPANTUNDThreadJoinerState_Connected);
		break;

	case SPINEL_MESHCOP_JOINER_STATE_ENTRUST:
		value = std::string(kWPANTUNDThreadJoinerState_Entrust);
		break;

	case SPINEL_MESHCOP_JOINER_STATE_JOINED:
		value = std::string(kWPANTUNDThreadJoinerState_Joined);
		break;

	default:
		value = std::string("unknown");
		break;
	}

bail:
	return ret;
}

static int
unpack_meshcop_joiner_discerner_value(const uint8_t *data_in, spinel_size_t data_len, boost::any &value)
{
	spinel_ssize_t len;
	uint8_t discerner_len;
	uint64_t discerner_value = 0;
	int ret = kWPANTUNDStatus_Ok;

	len = spinel_datatype_unpack(
		data_in,
		data_len,
		SPINEL_DATATYPE_UINT8_S,
		&discerner_len
	);

	require_action(len > 0, bail, ret = kWPANTUNDStatus_Failure);

	if (discerner_len != 0) {
		data_in += len;
		data_len -= len;

		len = spinel_datatype_unpack(
			data_in,
			data_len,
			SPINEL_DATATYPE_UINT64_S,
			&discerner_value
		);
	}

	value = discerner_value;

bail:
	return ret;
}

static int
unpack_thread_network_time_spinel(const uint8_t *data_in, spinel_size_t data_len, uint64_t &time, int8_t &time_sync_status)
{
	return spinel_datatype_unpack(
		data_in,
		data_len,
		(
			SPINEL_DATATYPE_UINT64_S   // time
			SPINEL_DATATYPE_INT8_S     // time sync status
		),
		&time,
		&time_sync_status
	);
}

static int
unpack_thread_network_time_as_string(const uint8_t *data_in, spinel_size_t data_len, std::string &result)
{
	spinel_ssize_t len;
	uint64_t time;
	int8_t time_sync_status;
	char c_string[500];
	int ret = kWPANTUNDStatus_Failure;

	len = unpack_thread_network_time_spinel(data_in, data_len, time, time_sync_status);

	if (len > 0)
	{
		ret = kWPANTUNDStatus_Ok;
		snprintf(c_string, sizeof(c_string), "ThreadNetworkTime: %" PRIu64 ", TimeSyncStatus:%d", time, time_sync_status);
		result.assign(c_string);
	}

	return ret;
}

static int
unpack_thread_network_time_as_valmap(const uint8_t *data_in, spinel_size_t data_len, ValueMap &result)
{
	spinel_ssize_t len;
	ValueMap entry;
	uint64_t time;
	int8_t time_sync_status;
	int ret = kWPANTUNDStatus_Failure;

	len = unpack_thread_network_time_spinel(data_in, data_len, time, time_sync_status);

	if (len > 0)
	{
		ret = kWPANTUNDStatus_Ok;
		result.clear();
		result[kWPANTUNDValueMapKey_TimeSync_Time] = time;
		result[kWPANTUNDValueMapKey_TimeSync_Status] = time_sync_status;
#if APPEND_NETWORK_TIME_RECEIVED_MONOTONIC_TIMESTAMP
		result[kWPANTUNDValueMapKey_TimeSync_ReceivedMonoTimeUs] = time_get_monotonic_us();
#endif // APPEND_NETWORK_TIME_RECEIVED_MONOTONIC_TIMESTAMP
	}

	return ret;
}

static int
unpack_thread_network_time_as_any(const uint8_t *data_in, spinel_size_t data_len, boost::any& value, bool as_val_map)
{
	ValueMap result_as_val_map;
	std::list<ValueMap> result_as_val_map_list;
	std::string result_as_string;
	std::list<std::string> result_as_string_list;
	int ret;

	if (as_val_map)
	{
		ret = unpack_thread_network_time_as_valmap(data_in, data_len, result_as_val_map);

		if (ret == kWPANTUNDStatus_Ok)
		{
			result_as_val_map_list.push_back(result_as_val_map);
			value = result_as_val_map_list;
		}
	}
	else
	{
		ret = unpack_thread_network_time_as_string(data_in, data_len, result_as_string);

		if (ret == kWPANTUNDStatus_Ok)
		{
			result_as_string_list.push_back(result_as_string);
			value = result_as_string_list;
		}
	}

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
	list.push_back("   - `" kWPANTUNDDatasetCommand_SendMgmtGetActive "`: Send MGMT_GET_ACTIVE meshcop command requesting TLVs in current local Dataset");
	list.push_back("   - `" kWPANTUNDDatasetCommand_SendMgmtSetActive "`: Send MGMT_SET_ACTIVE meshcop command along with the current local Dataset");
	list.push_back("   - `" kWPANTUNDDatasetCommand_GetPending "`: Get the NCP's Pending Operational Dataset and populate the local DataSet from it");
	list.push_back("   - `" kWPANTUNDDatasetCommand_SetPending "`: Set the NCP's Pending Operational Dataset from the current local Dataset");
	list.push_back("   - `" kWPANTUNDDatasetCommand_SendMgmtGetPending "`: Send MGMT_GET_PENDING meshcop command requesting TLVs in the current local Dataset");
	list.push_back("   - `" kWPANTUNDDatasetCommand_SendMgmtSetPending "`: Send MGMT_SET_PENDING meshcop command along with the current local Dataset");
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
		get_spinel_prop_with_unpacker(
			boost::bind(cb, _1),
			SPINEL_PROP_THREAD_ACTIVE_DATASET,
			boost::bind(&SpinelNCPInstance::unpack_and_set_local_dataset, this, _1, _2));

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SetActive)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		set_spinel_prop(frame, cb, SPINEL_PROP_THREAD_ACTIVE_DATASET, SPINEL_DATATYPE_DATA_C);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SendMgmtGetActive)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame, /* include_values */ false);
		set_spinel_prop(frame, cb, SPINEL_PROP_THREAD_MGMT_GET_ACTIVE_DATASET, SPINEL_DATATYPE_DATA_C);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SendMgmtSetActive)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		set_spinel_prop(frame, cb, SPINEL_PROP_THREAD_MGMT_SET_ACTIVE_DATASET, SPINEL_DATATYPE_DATA_C);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_GetPending)) {
		get_spinel_prop_with_unpacker(
			boost::bind(cb, _1),
			SPINEL_PROP_THREAD_PENDING_DATASET,
			boost::bind(&SpinelNCPInstance::unpack_and_set_local_dataset, this, _1, _2));

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SetPending)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		set_spinel_prop(frame, cb, SPINEL_PROP_THREAD_PENDING_DATASET, SPINEL_DATATYPE_DATA_C);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SendMgmtGetPending)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame, /* include_values */ false);
		set_spinel_prop(frame, cb, SPINEL_PROP_THREAD_MGMT_GET_PENDING_DATASET, SPINEL_DATATYPE_DATA_C);

	} else if (strcaseequal(command.c_str(), kWPANTUNDDatasetCommand_SendMgmtSetPending)) {
		Data frame;
		mLocalDataset.convert_to_spinel_frame(frame);
		set_spinel_prop(frame, cb, SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET, SPINEL_DATATYPE_DATA_C);

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

// ----------------------------------------------------------------------------
// Property Get Handlers

void
SpinelNCPInstance::get_spinel_prop(CallbackWithStatusArg1 cb, spinel_prop_key_t prop_key,
	const std::string &reply_format)
{
	start_new_task(SpinelNCPTaskSendCommand::Factory(this)
		.set_callback(cb)
		.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, prop_key))
		.set_reply_format(reply_format)
		.finish()
	);
}

void
SpinelNCPInstance::get_spinel_prop_with_unpacker(CallbackWithStatusArg1 cb, spinel_prop_key_t prop_key,
	ReplyUnpacker unpacker)
{
	start_new_task(SpinelNCPTaskSendCommand::Factory(this)
		.set_callback(cb)
		.add_command(SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, prop_key))
		.set_reply_unpacker(unpacker)
		.finish()
	);
}

void SpinelNCPInstance::check_capability_prop_get(CallbackWithStatusArg1 cb, const std::string &prop_name,
	unsigned int capability, PropGetHandler handler)
{
	if (mCapabilities.count(capability)) {
		handler(cb, prop_name);
	} else {
		char error_msg[200];
		snprintf(error_msg, sizeof(error_msg),
			"Capability %s (required for \"%s\") is not supported by NCP", spinel_capability_to_cstr(capability),
			prop_name.c_str());
		cb(kWPANTUNDStatus_FeatureNotSupported, std::string(error_msg));
	}
}

void
SpinelNCPInstance::register_get_handler(const char *prop_name, PropGetHandler handler)
{
	NCPInstanceBase::register_prop_get_handler(prop_name, handler);
}

void
SpinelNCPInstance::register_get_handler_capability(const char *prop_name, unsigned int capability,
	PropGetHandler handler)
{
	register_get_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::check_capability_prop_get, this, _1, _2, capability, handler));
}

void
SpinelNCPInstance::register_get_handler_spinel_simple(const char *prop_name, spinel_prop_key_t prop_key,
	const char *reply_format)
{
	register_get_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::get_spinel_prop, this, _1, prop_key, std::string(reply_format)));
}

void
SpinelNCPInstance::register_get_handler_spinel_unpacker(const char *prop_name, spinel_prop_key_t prop_key,
	ReplyUnpacker unpacker)
{
	register_get_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::get_spinel_prop_with_unpacker, this, _1, prop_key, unpacker));
}

void
SpinelNCPInstance::register_get_handler_capability_spinel_simple(const char *prop_name, unsigned int capability,
	spinel_prop_key_t prop_key,	const char *reply_format)
{
	register_get_handler_capability(
		prop_name,
		capability,
		boost::bind(&SpinelNCPInstance::get_spinel_prop, this, _1, prop_key, std::string(reply_format)));
}

void
SpinelNCPInstance::register_get_handler_capability_spinel_unpacker(const char *prop_name, unsigned int capability,
	spinel_prop_key_t prop_key,	ReplyUnpacker unpacker)
{
	register_get_handler_capability(
		prop_name,
		capability,
		boost::bind(&SpinelNCPInstance::get_spinel_prop_with_unpacker, this, _1, prop_key, unpacker));
}

void
SpinelNCPInstance::regsiter_all_get_handlers(void)
{
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties associated with a spinel property with simple packing format

	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NCPCCAThreshold,
		SPINEL_PROP_PHY_CCA_THRESHOLD, SPINEL_DATATYPE_INT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NCPTXPower,
		SPINEL_PROP_PHY_TX_POWER, SPINEL_DATATYPE_INT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NCPFrequency,
		SPINEL_PROP_PHY_FREQ, SPINEL_DATATYPE_INT32_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NetworkKey,
		SPINEL_PROP_NET_MASTER_KEY, SPINEL_DATATYPE_DATA_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NetworkPSKc,
		SPINEL_PROP_NET_PSKC, SPINEL_DATATYPE_DATA_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NCPExtendedAddress,
		SPINEL_PROP_MAC_EXTENDED_ADDR, SPINEL_DATATYPE_EUI64_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NetworkKeyIndex,
		SPINEL_PROP_NET_KEY_SEQUENCE_COUNTER, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NetworkKeySwitchGuardTime,
		SPINEL_PROP_NET_KEY_SWITCH_GUARDTIME, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NetworkRole,
		SPINEL_PROP_NET_ROLE, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NetworkPartitionId,
		SPINEL_PROP_NET_PARTITION_ID, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadRouterUpgradeThreshold,
		SPINEL_PROP_THREAD_ROUTER_UPGRADE_THRESHOLD, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadRouterDowngradeThreshold,
		SPINEL_PROP_THREAD_ROUTER_DOWNGRADE_THRESHOLD, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NCPRSSI,
		SPINEL_PROP_PHY_RSSI, SPINEL_DATATYPE_INT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadRLOC16,
		SPINEL_PROP_THREAD_RLOC16, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadRouterSelectionJitter,
		SPINEL_PROP_THREAD_ROUTER_SELECTION_JITTER, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadLeaderAddress,
		SPINEL_PROP_THREAD_LEADER_ADDR, SPINEL_DATATYPE_IPv6ADDR_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadLeaderRouterID,
		SPINEL_PROP_THREAD_LEADER_RID, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadLeaderWeight,
		SPINEL_PROP_THREAD_LEADER_WEIGHT, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadLeaderLocalWeight,
		SPINEL_PROP_THREAD_LOCAL_LEADER_WEIGHT, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadNetworkData,
		SPINEL_PROP_THREAD_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadNetworkDataVersion,
		SPINEL_PROP_THREAD_NETWORK_DATA_VERSION, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadStableNetworkData,
		SPINEL_PROP_THREAD_STABLE_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadLeaderNetworkData,
		SPINEL_PROP_THREAD_LEADER_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadStableLeaderNetworkData,
		SPINEL_PROP_THREAD_STABLE_LEADER_NETWORK_DATA, SPINEL_DATATYPE_DATA_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadStableNetworkDataVersion,
		SPINEL_PROP_THREAD_STABLE_NETWORK_DATA_VERSION, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadRouterRoleEnabled,
		SPINEL_PROP_THREAD_ROUTER_ROLE_ENABLED, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadDeviceMode,
		SPINEL_PROP_THREAD_MODE, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_OpenThreadDebugTestAssert,
		SPINEL_PROP_DEBUG_TEST_ASSERT, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_OpenThreadDebugTestWatchdog,
		SPINEL_PROP_DEBUG_TEST_WATCHDOG, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_TmfProxyEnabled,
		SPINEL_PROP_THREAD_TMF_PROXY_ENABLED, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_NCPCCAFailureRate,
		SPINEL_PROP_MAC_CCA_FAILURE_RATE, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_ThreadChildTimeout,
		SPINEL_PROP_THREAD_CHILD_TIMEOUT, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_OpenThreadLogLevel,
		SPINEL_PROP_DEBUG_NCP_LOG_LEVEL, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_spinel_simple(
		kWPANTUNDProperty_OpenThreadLogTimestampBase,
		SPINEL_PROP_DEBUG_LOG_TIMESTAMP_BASE, SPINEL_DATATYPE_UINT64_S);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties requiring capability check and associated with a spinel property
	// with simple packing format

	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPSleepyPollInterval,
		SPINEL_CAP_ROLE_SLEEPY,
		SPINEL_PROP_MAC_DATA_POLL_PERIOD, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_CommissionerProvisioningUrl,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_PROVISIONING_URL, SPINEL_DATATYPE_UTF8_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_CommissionerSessionId,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_SESSION_ID, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_MACAllowlistEnabled,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_ALLOWLIST_ENABLED, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_MACDenylistEnabled,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_DENYLIST_ENABLED, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_JamDetectionStatus,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECTED, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_JamDetectionEnable,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_ENABLE, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_JamDetectionRssiThreshold,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_RSSI_THRESHOLD, SPINEL_DATATYPE_INT8_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_JamDetectionWindow,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_WINDOW, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_JamDetectionBusyPeriod,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_BUSY, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_JamDetectionDebugHistoryBitmap,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_HISTORY_BITMAP, SPINEL_DATATYPE_UINT64_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChildSupervisionInterval,
		SPINEL_CAP_CHILD_SUPERVISION,
		SPINEL_PROP_CHILD_SUPERVISION_INTERVAL, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChildSupervisionCheckTimeout,
		SPINEL_CAP_CHILD_SUPERVISION,
		SPINEL_PROP_CHILD_SUPERVISION_CHECK_TIMEOUT, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelMonitorSampleInterval,
		SPINEL_CAP_CHANNEL_MONITOR,
		SPINEL_PROP_CHANNEL_MONITOR_SAMPLE_INTERVAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelMonitorRssiThreshold,
		SPINEL_CAP_CHANNEL_MONITOR,
		SPINEL_PROP_CHANNEL_MONITOR_RSSI_THRESHOLD, SPINEL_DATATYPE_INT8_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelMonitorSampleWindow,
		SPINEL_CAP_CHANNEL_MONITOR,
		SPINEL_PROP_CHANNEL_MONITOR_SAMPLE_WINDOW, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelMonitorSampleCount,
		SPINEL_CAP_CHANNEL_MONITOR,
		SPINEL_PROP_CHANNEL_MONITOR_SAMPLE_COUNT, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelManagerNewChannel,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_NEW_CHANNEL, SPINEL_DATATYPE_UINT8_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelManagerDelay,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_DELAY, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelManagerAutoSelectEnabled,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_ENABLED, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelManagerAutoSelectInterval,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_INTERVAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_ChannelManagerChannelSelect,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_CHANNEL_SELECT, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix,
		SPINEL_CAP_NEST_LEGACY_INTERFACE,
		SPINEL_PROP_NEST_LEGACY_ULA_PREFIX, SPINEL_DATATYPE_DATA_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_TimeSync_Period,
		SPINEL_CAP_TIME_SYNC,
		SPINEL_PROP_TIME_SYNC_PERIOD, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_TimeSync_XtalThreshold,
		SPINEL_CAP_TIME_SYNC,
		SPINEL_PROP_TIME_SYNC_XTAL_THRESHOLD, SPINEL_DATATYPE_UINT16_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_UNICAST,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_UNICAST, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_BROADCAST,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_BROADCAST, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_ACK_REQ,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_ACK_REQ, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_ACKED,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_ACKED, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_NO_ACK_REQ,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_NO_ACK_REQ, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_DATA,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_DATA, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_DATA_POLL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_DATA_POLL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_BEACON,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_BEACON, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_BEACON_REQ,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_BEACON_REQ, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_OTHER,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_OTHER, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_PKT_RETRY,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_PKT_RETRY, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_ERR_CCA,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_ERR_CCA, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_ERR_ABORT,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_ERR_ABORT, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_UNICAST,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_UNICAST, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_BROADCAST,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_BROADCAST, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_DATA,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_DATA, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_DATA_POLL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_DATA_POLL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_BEACON,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_BEACON, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_BEACON_REQ,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_BEACON_REQ, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_OTHER,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_OTHER, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_FILT_WL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_FILT_WL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_PKT_FILT_DA,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_PKT_FILT_DA, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_ERR_EMPTY,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_ERR_EMPTY, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_ERR_UKWN_NBR,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_ERR_UKWN_NBR, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_ERR_NVLD_SADDR,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_ERR_NVLD_SADDR, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_ERR_SECURITY,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_ERR_SECURITY, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_ERR_BAD_FCS,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_ERR_BAD_FCS, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_ERR_OTHER,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_ERR_OTHER, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_IP_SEC_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_IP_SEC_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_IP_INSEC_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_IP_INSEC_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_IP_DROPPED,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_IP_DROPPED, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_IP_SEC_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_IP_SEC_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_IP_INSEC_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_IP_INSEC_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_IP_DROPPED,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_IP_DROPPED, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_TX_SPINEL_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_TX_SPINEL_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_SPINEL_TOTAL,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_SPINEL_TOTAL, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_RX_SPINEL_ERR,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RX_SPINEL_ERR, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_IP_TX_SUCCESS,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_IP_TX_SUCCESS, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_IP_RX_SUCCESS,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_IP_RX_SUCCESS, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_IP_TX_FAILURE,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_IP_TX_FAILURE, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCounter_IP_RX_FAILURE,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_IP_RX_FAILURE, SPINEL_DATATYPE_UINT32_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_POSIXAppRCPVersion,
		SPINEL_CAP_POSIX,
		SPINEL_PROP_RCP_VERSION, SPINEL_DATATYPE_UTF8_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_OpenThreadSLAACEnabled,
		SPINEL_CAP_SLAAC,
		SPINEL_PROP_SLAAC_ENABLED, SPINEL_DATATYPE_BOOL_S);
	register_get_handler_capability_spinel_simple(
		kWPANTUNDProperty_NCPCoexEnable,
		SPINEL_CAP_RADIO_COEX,
		SPINEL_PROP_RADIO_COEX_ENABLE, SPINEL_DATATYPE_BOOL_S);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties associated with a spinel property using an unpacker

	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_NCPChannelMask,
		SPINEL_PROP_PHY_CHAN_SUPPORTED, unpack_channel_mask);
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_NCPPreferredChannelMask,
		SPINEL_PROP_PHY_CHAN_PREFERRED, unpack_channel_mask);
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadActiveDataset,
		SPINEL_PROP_THREAD_ACTIVE_DATASET, boost::bind(unpack_dataset, _1, _2, _3, /* as_val_map */ false));
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadActiveDatasetAsValMap,
		SPINEL_PROP_THREAD_ACTIVE_DATASET, boost::bind(unpack_dataset, _1, _2, _3, /* as_val_map */ true));
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadPendingDataset,
		SPINEL_PROP_THREAD_PENDING_DATASET, boost::bind(unpack_dataset, _1, _2, _3, /* as_val_map */ false));
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadPendingDatasetAsValMap,
		SPINEL_PROP_THREAD_PENDING_DATASET, boost::bind(unpack_dataset, _1, _2, _3, /* as_val_map */ true));
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadParent,
		SPINEL_PROP_THREAD_PARENT,
		boost::bind(unpack_parent_info, _1, _2, _3, /* as_val_map */ false));
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadParentAsValMap,
		SPINEL_PROP_THREAD_PARENT,
		boost::bind(unpack_parent_info, _1, _2, _3, /* as_val_map */ true));
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadAddressCacheTable,
		SPINEL_PROP_THREAD_ADDRESS_CACHE_TABLE,
		boost::bind(unpack_address_cache_table, _1, _2, _3, /* as_val_map */ false));
	register_get_handler_spinel_unpacker(
		kWPANTUNDProperty_ThreadAddressCacheTableAsValMap,
		SPINEL_PROP_THREAD_ADDRESS_CACHE_TABLE,
		boost::bind(unpack_address_cache_table, _1, _2, _3, /* as_val_map */ true));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties requiring capability check and associated with a spinel property
	// using an unpacker

	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPMCUPowerState,
		SPINEL_CAP_MCU_POWER_STATE,
		SPINEL_PROP_MCU_POWER_STATE, unpack_mcu_power_state);
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_JoinerState,
		SPINEL_CAP_THREAD_JOINER,
		SPINEL_PROP_MESHCOP_JOINER_STATE, unpack_meshcop_joiner_state);
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_JoinerDiscernerValue,
		SPINEL_CAP_THREAD_JOINER,
		SPINEL_PROP_MESHCOP_JOINER_DISCERNER, unpack_meshcop_joiner_discerner_value);
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_CommissionerState,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_STATE, unpack_commissioner_state);
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_CommissionerJoiners,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_JOINERS, unpack_commissioner_joiners);
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_MACAllowlistEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_ALLOWLIST, boost::bind(unpack_mac_allowlist_entries, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_MACAllowlistEntriesAsValMap,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_ALLOWLIST, boost::bind(unpack_mac_allowlist_entries, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_MACDenylistEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_DENYLIST, boost::bind(unpack_mac_denylist_entries, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_MACDenylistEntriesAsValMap,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_DENYLIST, boost::bind(unpack_mac_denylist_entries, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_MACFilterEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_FIXED_RSS, boost::bind(unpack_mac_allowlist_entries, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_MACFilterEntriesAsValMap,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_FIXED_RSS, boost::bind(unpack_mac_allowlist_entries, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_ChannelMonitorChannelQuality,
		SPINEL_CAP_CHANNEL_MONITOR,
		SPINEL_PROP_CHANNEL_MONITOR_CHANNEL_OCCUPANCY, boost::bind(unpack_channel_occupancy, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_ChannelMonitorChannelQualityAsValMap,
		SPINEL_CAP_CHANNEL_MONITOR,
		SPINEL_PROP_CHANNEL_MONITOR_CHANNEL_OCCUPANCY, boost::bind(unpack_channel_occupancy, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_ChannelManagerSupportedChannelMask,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_SUPPORTED_CHANNELS, unpack_channel_mask);
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_ChannelManagerFavoredChannelMask,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_FAVORED_CHANNELS, unpack_channel_mask);
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCounterAllMac,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_ALL_MAC_COUNTERS, boost::bind(unpack_ncp_counters_all_mac, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCounterAllMacAsValMap,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_ALL_MAC_COUNTERS, boost::bind(unpack_ncp_counters_all_mac, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCounterThreadMle,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_MLE_COUNTERS, boost::bind(unpack_ncp_counters_mle, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCounterThreadMleAsValMap,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_MLE_COUNTERS, boost::bind(unpack_ncp_counters_mle, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCounterAllIPv6,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_ALL_IP_COUNTERS, boost::bind(unpack_ncp_counters_ipv6, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCounterAllIPv6AsValMap,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_ALL_IP_COUNTERS, boost::bind(unpack_ncp_counters_ipv6, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_TimeSync_NetworkTime,
		SPINEL_CAP_TIME_SYNC,
		SPINEL_PROP_THREAD_NETWORK_TIME, boost::bind(unpack_thread_network_time_as_any, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_TimeSync_NetworkTimeAsValMap,
		SPINEL_CAP_TIME_SYNC,
		SPINEL_PROP_THREAD_NETWORK_TIME, boost::bind(unpack_thread_network_time_as_any, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_ThreadLeaderServices,
		SPINEL_CAP_THREAD_SERVICE,
		SPINEL_PROP_SERVER_LEADER_SERVICES, boost::bind(unpack_server_leader_services_as_any, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_ThreadLeaderServicesAsValMap,
		SPINEL_CAP_THREAD_SERVICE,
		SPINEL_PROP_SERVER_LEADER_SERVICES, boost::bind(unpack_server_leader_services_as_any, _1, _2, _3, true));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCoexMetrics,
		SPINEL_CAP_RADIO_COEX,
		SPINEL_PROP_RADIO_COEX_METRICS, boost::bind(unpack_coex_metrics, _1, _2, _3, false));
	register_get_handler_capability_spinel_unpacker(
		kWPANTUNDProperty_NCPCoexMetricsAsValMap,
		SPINEL_CAP_RADIO_COEX,
		SPINEL_PROP_RADIO_COEX_METRICS, boost::bind(unpack_coex_metrics, _1, _2, _3, true));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties with a dedicated handler method

	register_get_handler(
		kWPANTUNDProperty_ConfigNCPDriverName,
		boost::bind(&SpinelNCPInstance::get_prop_ConfigNCPDriverName, this, _1));
	register_get_handler(
		kWPANTUNDProperty_NCPCapabilities,
		boost::bind(&SpinelNCPInstance::get_prop_NCPCapabilities, this, _1));
	register_get_handler(
		kWPANTUNDProperty_NetworkIsCommissioned,
		boost::bind(&SpinelNCPInstance::get_prop_NetworkIsCommissioned, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadRouterID,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadRouterID, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadConfigFilterRLOCAddresses,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadConfigFilterRLOCAddresses, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadConfigFilterALOCAddresses,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadConfigFilterALOCAddresses, this, _1));
	register_get_handler(
		kWPANTUNDProperty_IPv6MeshLocalPrefix,
		boost::bind(&SpinelNCPInstance::get_prop_IPv6MeshLocalPrefix, this, _1));
	register_get_handler(
		kWPANTUNDProperty_IPv6MeshLocalAddress,
		boost::bind(&SpinelNCPInstance::get_prop_IPv6MeshLocalAddress, this, _1));
	register_get_handler(
		kWPANTUNDProperty_IPv6LinkLocalAddress,
		boost::bind(&SpinelNCPInstance::get_prop_IPv6LinkLocalAddress, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadChildTable,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadChildTable, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadChildTableAsValMap,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadChildTableAsValMap, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadChildTableAddresses,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadChildTableAddresses, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadNeighborTable,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadNeighborTable, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadNeighborTableAsValMap,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadNeighborTableAsValMap, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadRouterTable,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadRouterTable, this, _1));
	register_get_handler(
		kWPANTUNDProperty_ThreadRouterTableAsValMap,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadRouterTableAsValMap, this, _1));
	register_get_handler(
		kWPANTUNDProperty_OpenThreadMsgBufferCounters,
		boost::bind(&SpinelNCPInstance::get_prop_OpenThreadMsgBufferCounters, this, _1));
	register_get_handler(
		kWPANTUNDProperty_OpenThreadMsgBufferCountersAsString,
		boost::bind(&SpinelNCPInstance::get_prop_OpenThreadMsgBufferCountersAsString, this, _1));
	register_get_handler(
		kWPANTUNDProperty_OpenThreadSteeringDataSetWhenJoinable,
		boost::bind(&SpinelNCPInstance::get_prop_OpenThreadSteeringDataSetWhenJoinable, this, _1));
	register_get_handler(
		kWPANTUNDProperty_OpenThreadSteeringDataAddress,
		boost::bind(&SpinelNCPInstance::get_prop_OpenThreadSteeringDataAddress, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetActiveTimestamp,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetActiveTimestamp, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetPendingTimestamp,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetPendingTimestamp, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetMasterKey,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetMasterKey, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetNetworkName,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetNetworkName, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetExtendedPanId,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetExtendedPanId, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetMeshLocalPrefix,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetMeshLocalPrefix, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetDelay,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetDelay, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetPanId,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetPanId, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetChannel,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetChannel, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetPSKc,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetPSKc, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetChannelMaskPage0,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetChannelMaskPage0, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetSecPolicyKeyRotation,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetSecPolicyKeyRotation, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetSecPolicyFlags,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetSecPolicyFlags, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetRawTlvs,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetRawTlvs, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetDestIpAddress,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetDestIpAddress, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetAllFileds,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetAllFileds, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetAllFileds_AltString,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetAllFileds, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetAllFiledsAsValMap,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetAllFiledsAsValMap, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DatasetCommand,
		boost::bind(&SpinelNCPInstance::get_prop_DatasetCommand, this, _1));
	register_get_handler(
		kWPANTUNDProperty_DaemonTickleOnHostDidWake,
		boost::bind(&SpinelNCPInstance::get_prop_DaemonTickleOnHostDidWake, this, _1));

	// Properties requiring capability check with a dedicated handler method

	register_get_handler_capability(
		kWPANTUNDProperty_JoinerDiscernerBitLength,
		SPINEL_CAP_THREAD_JOINER,
		boost::bind(&SpinelNCPInstance::get_prop_JoinerDiscernerBitLength, this, _1));
	register_get_handler_capability(
		kWPANTUNDProperty_CommissionerEnergyScanResult,
		SPINEL_CAP_THREAD_COMMISSIONER,
		boost::bind(&SpinelNCPInstance::get_prop_CommissionerEnergyScanResult, this, _1));
	register_get_handler_capability(
		kWPANTUNDProperty_CommissionerPanIdConflictResult,
		SPINEL_CAP_THREAD_COMMISSIONER,
		boost::bind(&SpinelNCPInstance::get_prop_CommissionerPanIdConflictResult, this, _1));
	register_get_handler_capability(
		kWPANTUNDProperty_ThreadNeighborTableErrorRates,
		SPINEL_CAP_ERROR_RATE_TRACKING,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadNeighborTableErrorRates, this, _1));
	register_get_handler_capability(
		kWPANTUNDProperty_ThreadNeighborTableErrorRatesAsValMap,
		SPINEL_CAP_ERROR_RATE_TRACKING,
		boost::bind(&SpinelNCPInstance::get_prop_ThreadNeighborTableErrorRatesAsValMap, this, _1));
	register_get_handler_capability(
		kWPANTUNDProperty_POSIXAppRCPVersionCached,
		SPINEL_CAP_POSIX,
		boost::bind(&SpinelNCPInstance::get_prop_POSIXAppRCPVersionCached, this, _1));
	register_get_handler_capability(
		kWPANTUNDProperty_MACFilterFixedRssi,
		SPINEL_CAP_MAC_ALLOWLIST,
		boost::bind(&SpinelNCPInstance::get_prop_MACFilterFixedRssi, this, _1));
}

void
SpinelNCPInstance::get_prop_ConfigNCPDriverName(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(std::string("spinel")));
}

void
SpinelNCPInstance::get_prop_NCPCapabilities(CallbackWithStatusArg1 cb)
{
	std::list<std::string> capability_list;
	std::set<unsigned int>::iterator iter;

	for (iter = mCapabilities.begin(); iter != mCapabilities.end(); iter++)	{
		char str[200];
		snprintf(str, sizeof(str), "%s (%d)", spinel_capability_to_cstr(*iter), *iter);
		capability_list.push_back(std::string(str));
	}

	cb(kWPANTUNDStatus_Ok, boost::any(capability_list));
}

void
SpinelNCPInstance::get_prop_NetworkIsCommissioned(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mIsCommissioned));
}

void
SpinelNCPInstance::get_prop_ThreadRouterID(CallbackWithStatusArg1 cb)
{
	get_spinel_prop(boost::bind(convert_rloc16_to_router_id, cb, _1, _2), SPINEL_PROP_THREAD_RLOC16,
		SPINEL_DATATYPE_UINT16_S);
}

void
SpinelNCPInstance::get_prop_ThreadConfigFilterRLOCAddresses(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mFilterRLOCAddresses));
}

void
SpinelNCPInstance::get_prop_ThreadConfigFilterALOCAddresses(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mFilterALOCAddresses));
}

void
SpinelNCPInstance::get_prop_JoinerDiscernerBitLength(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mJoinerDiscernerBitLength));
}

void
SpinelNCPInstance::get_prop_CommissionerEnergyScanResult(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mCommissionerEnergyScanResult));
}

void
SpinelNCPInstance::get_prop_CommissionerPanIdConflictResult(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mCommissionerPanIdConflictResult));
}

void
SpinelNCPInstance::get_prop_IPv6MeshLocalPrefix(CallbackWithStatusArg1 cb)
{
	if (!buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix))) {
		get_spinel_prop_with_unpacker(cb, SPINEL_PROP_IPV6_ML_PREFIX, unpack_mesh_local_prefix);
	} else {
		struct in6_addr addr = mNCPMeshLocalAddress;
		memset(addr.s6_addr + 8, 0, 8);
		cb(kWPANTUNDStatus_Ok, boost::any(in6_addr_to_string(addr) + "/64"));
	}
}

void
SpinelNCPInstance::get_prop_IPv6MeshLocalAddress(CallbackWithStatusArg1 cb)
{
	if (!buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix))) {
		get_spinel_prop(cb, SPINEL_PROP_IPV6_ML_ADDR, SPINEL_DATATYPE_IPv6ADDR_S);
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(in6_addr_to_string(mNCPMeshLocalAddress)));
	}
}

void
SpinelNCPInstance::get_prop_IPv6LinkLocalAddress(CallbackWithStatusArg1 cb)
{
	if (!IN6_IS_ADDR_LINKLOCAL(&mNCPLinkLocalAddress)) {
		get_spinel_prop(cb, SPINEL_PROP_IPV6_LL_ADDR, SPINEL_DATATYPE_IPv6ADDR_S);
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(in6_addr_to_string(mNCPLinkLocalAddress)));
	}
}

void
SpinelNCPInstance::get_prop_ThreadChildTable(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kChildTable,
			SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadChildTableAsValMap(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kChildTable,
			SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadChildTableAddresses(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kChildTableAddresses,
			SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadNeighborTable(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kNeighborTable,
			SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadNeighborTableAsValMap(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kNeighborTable,
			SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadNeighborTableErrorRates(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kNeighborTableErrorRates,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadNeighborTableErrorRatesAsValMap(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kNeighborTableErrorRates,
				SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadRouterTable(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kRouterTable,
			SpinelNCPTaskGetNetworkTopology::kResultFormat_StringArray
		)
	));
}

void
SpinelNCPInstance::get_prop_ThreadRouterTableAsValMap(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetNetworkTopology(
			this,
			cb,
			SpinelNCPTaskGetNetworkTopology::kRouterTable,
			SpinelNCPTaskGetNetworkTopology::kResultFormat_ValueMapArray
		)
	));
}

void
SpinelNCPInstance::get_prop_OpenThreadMsgBufferCounters(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetMsgBufferCounters(
			this,
			cb,
			SpinelNCPTaskGetMsgBufferCounters::kResultFormat_StringArray
		)
	));
}

void
SpinelNCPInstance::get_prop_OpenThreadMsgBufferCountersAsString(CallbackWithStatusArg1 cb)
{
	start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskGetMsgBufferCounters(
			this,
			cb,
			SpinelNCPTaskGetMsgBufferCounters::kResultFormat_String
		)
	));
}

void
SpinelNCPInstance::get_prop_OpenThreadSteeringDataSetWhenJoinable(CallbackWithStatusArg1 cb)
{
	cb(0, boost::any(mSetSteeringDataWhenJoinable));
}

void
SpinelNCPInstance::get_prop_OpenThreadSteeringDataAddress(CallbackWithStatusArg1 cb)
{
	cb(0, boost::any(nl::Data(mSteeringDataAddress, sizeof(mSteeringDataAddress))));
}

void
SpinelNCPInstance::get_prop_DatasetActiveTimestamp(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mActiveTimestamp.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mActiveTimestamp.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetPendingTimestamp(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mPendingTimestamp.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mPendingTimestamp.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetMasterKey(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mMasterKey.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mMasterKey.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetNetworkName(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mNetworkName.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mNetworkName.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetExtendedPanId(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mExtendedPanId.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mExtendedPanId.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetMeshLocalPrefix(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mMeshLocalPrefix.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(in6_addr_to_string(mLocalDataset.mMeshLocalPrefix.get())));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetDelay(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mDelay.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mDelay.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetPanId(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mPanId.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mPanId.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetChannel(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mChannel.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mChannel.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetPSKc(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mPSKc.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mPSKc.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetChannelMaskPage0(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mChannelMaskPage0.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mChannelMaskPage0.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetSecPolicyKeyRotation(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mSecurityPolicy.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mSecurityPolicy.get().mKeyRotationTime));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetSecPolicyFlags(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mSecurityPolicy.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mSecurityPolicy.get().mFlags));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetRawTlvs(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mRawTlvs.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(mLocalDataset.mRawTlvs.get()));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetDestIpAddress(CallbackWithStatusArg1 cb)
{
	if (mLocalDataset.mDestIpAddress.has_value()) {
		cb(kWPANTUNDStatus_Ok, boost::any(in6_addr_to_string(mLocalDataset.mDestIpAddress.get())));
	} else {
		cb(kWPANTUNDStatus_Ok, boost::any(Data()));
	}
}

void
SpinelNCPInstance::get_prop_DatasetAllFileds(CallbackWithStatusArg1 cb)
{
	std::list<std::string> list;
	mLocalDataset.convert_to_string_list(list);
	cb(kWPANTUNDStatus_Ok, boost::any(list));
}

void
SpinelNCPInstance::get_prop_DatasetAllFiledsAsValMap(CallbackWithStatusArg1 cb)
{
	ValueMap map;
	mLocalDataset.convert_to_valuemap(map);
	cb(kWPANTUNDStatus_Ok, boost::any(map));
}

void
SpinelNCPInstance::get_prop_DatasetCommand(CallbackWithStatusArg1 cb)
{
	std::list<std::string> help_string;
	get_dataset_command_help(help_string);
	cb(kWPANTUNDStatus_Ok, boost::any(help_string));
}

void
SpinelNCPInstance::get_prop_DaemonTickleOnHostDidWake(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mTickleOnHostDidWake));
}

void
SpinelNCPInstance::get_prop_POSIXAppRCPVersionCached(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mRcpVersion));
}

void
SpinelNCPInstance::get_prop_MACFilterFixedRssi(CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_Ok, boost::any(mMacFilterFixedRssi));
}

void
SpinelNCPInstance::property_get_value(
	const std::string& key,
	CallbackWithStatusArg1 cb
) {
	if (!is_initializing_ncp()) {
		syslog(LOG_INFO, "property_get_value: key: \"%s\"", key.c_str());
	}

	if (mVendorCustom.is_property_key_supported(key)) {
		mVendorCustom.property_get_value(key, cb);
	} else {
		NCPInstanceBase::property_get_value(key, cb);
	}
}

// ----------------------------------------------------------------------------
// Property Set Handlers

void
SpinelNCPInstance::set_spinel_prop(
	const boost::any &value, CallbackWithStatus cb, spinel_prop_key_t prop_key, char pack_type, unsigned int capability,
	bool save_in_settings, const std::string &prop_name)
{
	Data command = SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_NULL_S), prop_key);
	int status = SpinelAppendAny(command, value, pack_type);

	if (status != kWPANTUNDStatus_Ok) {
		cb(status);
	} else {

		if (save_in_settings) {
			mSettings[prop_name] = SettingsEntry(command, capability);
		}

		if (!capability || mCapabilities.count(capability)) {
			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(command)
				.finish()
			);
		} else {
			cb(kWPANTUNDStatus_FeatureNotSupported);
		}
	}
}

void
SpinelNCPInstance::convert_value_prop_set(const boost::any &value, CallbackWithStatus cb, const std::string &prop_name,
	ValueConverter converter, PropUpdateHandler handler)
{
	boost::any converted_value;
	int status = converter(value, converted_value);

	if (status == kWPANTUNDStatus_Ok) {
		handler(converted_value, cb, prop_name);
	} else {
		cb(status);
	}
}

void
SpinelNCPInstance::register_set_handler(const char *prop_name, PropUpdateHandler handler, ValueConverter converter)
{
	if (converter.empty()) {
		NCPInstanceBase::register_prop_set_handler(prop_name, handler);
	} else {

		// If a `converter` function is given, use `convert_value_prop_set`
		// which converts the value using the `converter` then passing the
		// converted value to the original `handler`.
		NCPInstanceBase::register_prop_set_handler(
			prop_name,
			boost::bind(&SpinelNCPInstance::convert_value_prop_set, _1, _2, _3, converter, handler));
	}
}

void
SpinelNCPInstance::register_set_handler_spinel(const char *prop_name, spinel_prop_key_t prop_key, char pack_type,
	ValueConverter converter)
{
	register_set_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::set_spinel_prop, this, _1, _2, prop_key, pack_type, 0, false, _3),
		converter);
}

void
SpinelNCPInstance::register_set_handler_spinel_persist(const char *prop_name, spinel_prop_key_t prop_key,
	char pack_type, ValueConverter converter)
{
	register_set_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::set_spinel_prop, this, _1, _2, prop_key, pack_type, 0, true, _3),
		converter);
}

void
SpinelNCPInstance::register_set_handler_capability_spinel(const char *prop_name, unsigned int capability,
	spinel_prop_key_t prop_key, char pack_type, ValueConverter converter)
{
	register_set_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::set_spinel_prop, this, _1, _2, prop_key, pack_type, capability, false, _3),
		converter);
}

void
SpinelNCPInstance::register_set_handler_capability_spinel_persist(const char *prop_name, unsigned int capability,
	spinel_prop_key_t prop_key, char pack_type, ValueConverter converter)
{
	register_set_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::set_spinel_prop, this, _1, _2, prop_key, pack_type, capability, true, _3),
		converter);
}

void
SpinelNCPInstance::regsiter_all_set_handlers(void)
{
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties associated with a spinel property

	register_set_handler_spinel(
		kWPANTUNDProperty_NCPChannel,
		SPINEL_PROP_PHY_CHAN, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NetworkPANID,
		SPINEL_PROP_MAC_15_4_PANID, SPINEL_DATATYPE_UINT16_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NetworkPSKc,
		SPINEL_PROP_NET_PSKC, SPINEL_DATATYPE_DATA_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NetworkPartitionId,
		SPINEL_PROP_NET_PARTITION_ID, SPINEL_DATATYPE_UINT32_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NCPMACAddress,
		SPINEL_PROP_MAC_15_4_LADDR, SPINEL_DATATYPE_EUI64_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NCPExtendedAddress,
		SPINEL_PROP_MAC_EXTENDED_ADDR, SPINEL_DATATYPE_EUI64_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NetworkKeyIndex,
		SPINEL_PROP_NET_KEY_SEQUENCE_COUNTER, SPINEL_DATATYPE_UINT32_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NetworkKeySwitchGuardTime,
		SPINEL_PROP_NET_KEY_SWITCH_GUARDTIME, SPINEL_DATATYPE_UINT32_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NetworkName,
		SPINEL_PROP_NET_NETWORK_NAME, SPINEL_DATATYPE_UTF8_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_NetworkRole,
		SPINEL_PROP_NET_ROLE, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_ThreadPreferredRouterID,
		SPINEL_PROP_THREAD_PREFERRED_ROUTER_ID, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_ThreadRouterRoleEnabled,
		SPINEL_PROP_THREAD_ROUTER_ROLE_ENABLED, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_ThreadRouterSelectionJitter,
		SPINEL_PROP_THREAD_ROUTER_SELECTION_JITTER, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_ThreadRouterUpgradeThreshold,
		SPINEL_PROP_THREAD_ROUTER_UPGRADE_THRESHOLD, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_spinel(
		kWPANTUNDProperty_ThreadRouterDowngradeThreshold,
		SPINEL_PROP_THREAD_ROUTER_DOWNGRADE_THRESHOLD, SPINEL_DATATYPE_UINT8_C);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties requiring persistence (saving in settings) and associated with a
	// spinel property

	register_set_handler_spinel_persist(
		kWPANTUNDProperty_NCPCCAThreshold,
		SPINEL_PROP_PHY_CCA_THRESHOLD, SPINEL_DATATYPE_INT8_C);
	register_set_handler_spinel_persist(
		kWPANTUNDProperty_NCPTXPower,
		SPINEL_PROP_PHY_TX_POWER, SPINEL_DATATYPE_INT8_C);
	register_set_handler_spinel_persist(
		kWPANTUNDProperty_ThreadChildTimeout,
		SPINEL_PROP_THREAD_CHILD_TIMEOUT, SPINEL_DATATYPE_UINT32_C);
	register_set_handler_spinel_persist(
		kWPANTUNDProperty_ThreadDeviceMode,
		SPINEL_PROP_THREAD_MODE, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_spinel_persist(
		kWPANTUNDProperty_OpenThreadLogLevel,
		SPINEL_PROP_DEBUG_NCP_LOG_LEVEL, SPINEL_DATATYPE_UINT8_C);

	// Properties with a `ValueConverter`
	register_set_handler_spinel_persist(
		kWPANTUNDProperty_NCPChannelMask,
		SPINEL_PROP_PHY_CHAN_SUPPORTED, SPINEL_DATATYPE_DATA_C,
		&SpinelNCPInstance::convert_value_channel_mask);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties requiring capability check and associated with a spinel property

	register_set_handler_capability_spinel(
		kWPANTUNDProperty_MACAllowlistEnabled,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_ALLOWLIST_ENABLED, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_MACDenylistEnabled,
		SPINEL_CAP_MAC_ALLOWLIST,
		SPINEL_PROP_MAC_DENYLIST_ENABLED, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_CommissionerProvisioningUrl,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_PROVISIONING_URL, SPINEL_DATATYPE_UTF8_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_CommissionerSendMgmtGet,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_MGMT_GET, SPINEL_DATATYPE_DATA_WLEN_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_CommissionerSendMgmtSet,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_MGMT_SET, SPINEL_DATATYPE_DATA_WLEN_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_ChannelManagerChannelSelect,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_CHANNEL_SELECT, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_TimeSync_Period,
		SPINEL_CAP_TIME_SYNC,
		SPINEL_PROP_TIME_SYNC_PERIOD, SPINEL_DATATYPE_UINT16_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_TimeSync_XtalThreshold,
		SPINEL_CAP_TIME_SYNC,
		SPINEL_PROP_TIME_SYNC_XTAL_THRESHOLD, SPINEL_DATATYPE_UINT16_C);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_OpenThreadLogTimestampBase,
		SPINEL_CAP_OPENTHREAD_LOG_METADATA,
		SPINEL_PROP_DEBUG_LOG_TIMESTAMP_BASE, SPINEL_DATATYPE_UINT64_C);

	// Properties with a `ValueConverter`
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_CommissionerState,
		SPINEL_CAP_THREAD_COMMISSIONER,
		SPINEL_PROP_MESHCOP_COMMISSIONER_STATE, SPINEL_DATATYPE_UINT8_C,
		&SpinelNCPInstance::convert_value_CommissionerState);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_NCPCounterAllReset,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_RESET, SPINEL_DATATYPE_UINT8_C,
		&SpinelNCPInstance::convert_value_counter_reset);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_NCPCounterAllMac,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_ALL_MAC_COUNTERS, SPINEL_DATATYPE_UINT8_C,
		&SpinelNCPInstance::convert_value_counter_reset);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_NCPCounterThreadMle,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_MLE_COUNTERS, SPINEL_DATATYPE_UINT8_C,
		&SpinelNCPInstance::convert_value_counter_reset);
	register_set_handler_capability_spinel(
		kWPANTUNDProperty_NCPCounterAllIPv6,
		SPINEL_CAP_COUNTERS,
		SPINEL_PROP_CNTR_ALL_IP_COUNTERS, SPINEL_DATATYPE_UINT8_C,
		&SpinelNCPInstance::convert_value_counter_reset);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties requiring capability check and persistence (saving in settings),
	// and associated with a spinel property

	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_NCPSleepyPollInterval,
		SPINEL_CAP_ROLE_SLEEPY,
		SPINEL_PROP_MAC_DATA_POLL_PERIOD, SPINEL_DATATYPE_UINT32_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_TmfProxyEnabled,
		SPINEL_CAP_THREAD_TMF_PROXY,
		SPINEL_PROP_THREAD_TMF_PROXY_ENABLED, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_JamDetectionEnable,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_ENABLE, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_JamDetectionRssiThreshold,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_RSSI_THRESHOLD, SPINEL_DATATYPE_INT8_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_JamDetectionWindow,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_WINDOW, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_JamDetectionBusyPeriod,
		SPINEL_CAP_JAM_DETECT,
		SPINEL_PROP_JAM_DETECT_BUSY, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix,
		SPINEL_CAP_NEST_LEGACY_INTERFACE,
		SPINEL_PROP_NEST_LEGACY_ULA_PREFIX, SPINEL_DATATYPE_DATA_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChildSupervisionInterval,
		SPINEL_CAP_CHILD_SUPERVISION,
		SPINEL_PROP_CHILD_SUPERVISION_INTERVAL, SPINEL_DATATYPE_UINT16_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChildSupervisionCheckTimeout,
		SPINEL_CAP_CHILD_SUPERVISION,
		SPINEL_PROP_CHILD_SUPERVISION_CHECK_TIMEOUT, SPINEL_DATATYPE_UINT16_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChannelManagerNewChannel,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_NEW_CHANNEL, SPINEL_DATATYPE_UINT8_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChannelManagerDelay,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_DELAY, SPINEL_DATATYPE_UINT16_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChannelManagerAutoSelectEnabled,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_ENABLED, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChannelManagerAutoSelectInterval,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_AUTO_SELECT_INTERVAL, SPINEL_DATATYPE_UINT32_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_OpenThreadSLAACEnabled,
		SPINEL_CAP_SLAAC,
		SPINEL_PROP_SLAAC_ENABLED, SPINEL_DATATYPE_BOOL_C);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_NCPCoexEnable,
		SPINEL_CAP_RADIO_COEX,
		SPINEL_PROP_RADIO_COEX_ENABLE, SPINEL_DATATYPE_BOOL_C);

	// Properties with a `ValueConverter`
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_NCPMCUPowerState,
		SPINEL_PROP_MCU_POWER_STATE,
		SPINEL_PROP_MCU_POWER_STATE, SPINEL_DATATYPE_UINT8_C,
		&SpinelNCPInstance::convert_value_NCPMCUPowerState);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChannelManagerSupportedChannelMask,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_SUPPORTED_CHANNELS, SPINEL_DATATYPE_DATA_C,
		&SpinelNCPInstance::convert_value_channel_mask);
	register_set_handler_capability_spinel_persist(
		kWPANTUNDProperty_ChannelManagerFavoredChannelMask,
		SPINEL_CAP_CHANNEL_MANAGER,
		SPINEL_PROP_CHANNEL_MANAGER_FAVORED_CHANNELS, SPINEL_DATATYPE_DATA_C,
		&SpinelNCPInstance::convert_value_channel_mask);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Properties with a dedicated handler method

	register_set_handler(
		kWPANTUNDProperty_NetworkKey,
		boost::bind(&SpinelNCPInstance::set_prop_NetworkKey, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_InterfaceUp,
		boost::bind(&SpinelNCPInstance::set_prop_InterfaceUp, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_NetworkXPANID,
		boost::bind(&SpinelNCPInstance::set_prop_NetworkXPANID, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_IPv6MeshLocalPrefix,
		boost::bind(&SpinelNCPInstance::set_prop_IPv6MeshLocalPrefix, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_ThreadConfigFilterRLOCAddresses,
		boost::bind(&SpinelNCPInstance::set_prop_ThreadConfigFilterRLOCAddresses, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_ThreadConfigFilterALOCAddresses,
		boost::bind(&SpinelNCPInstance::set_prop_ThreadConfigFilterALOCAddresses, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_OpenThreadSteeringDataSetWhenJoinable,
		boost::bind(&SpinelNCPInstance::set_prop_OpenThreadSteeringDataSetWhenJoinable, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_OpenThreadSteeringDataAddress,
		boost::bind(&SpinelNCPInstance::set_prop_OpenThreadSteeringDataAddress, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_TmfProxyStream,
		boost::bind(&SpinelNCPInstance::set_prop_TmfProxyStream, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_UdpForwardStream,
		boost::bind(&SpinelNCPInstance::set_prop_UdpForwardStream, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetActiveTimestamp,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetActiveTimestamp, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetPendingTimestamp,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetPendingTimestamp, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetMasterKey,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetMasterKey, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetNetworkName,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetNetworkName, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetExtendedPanId,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetExtendedPanId, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetMeshLocalPrefix,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetMeshLocalPrefix, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetDelay,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetDelay, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetPanId,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetPanId, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetChannel,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetChannel, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetPSKc,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetPSKc, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetChannelMaskPage0,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetChannelMaskPage0, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetSecPolicyKeyRotation,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetSecPolicyKeyRotation, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetSecPolicyFlags,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetSecPolicyFlags, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetRawTlvs,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetRawTlvs, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetDestIpAddress,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetDestIpAddress, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DatasetCommand,
		boost::bind(&SpinelNCPInstance::set_prop_DatasetCommand, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_DaemonTickleOnHostDidWake,
		boost::bind(&SpinelNCPInstance::set_prop_DaemonTickleOnHostDidWake, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_MACFilterFixedRssi,
		boost::bind(&SpinelNCPInstance::set_prop_MACFilterFixedRssi, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_JoinerDiscernerBitLength,
		boost::bind(&SpinelNCPInstance::set_prop_JoinerDiscernerBitLength, this, _1, _2));
	register_set_handler(
		kWPANTUNDProperty_JoinerDiscernerValue,
		boost::bind(&SpinelNCPInstance::set_prop_JoinerDiscernerValue, this, _1, _2));
}

int
SpinelNCPInstance::convert_value_NCPMCUPowerState(const boost::any &value, boost::any &value_out)
{
	int ret = kWPANTUNDStatus_Ok;
	std::string str = any_to_string(value);

	if (strcaseequal(str.c_str(), kWPANTUNDNCPMCUPowerState_On)) {
		value_out = static_cast<uint8_t>(SPINEL_MCU_POWER_STATE_ON);
	} else if (strcaseequal(str.c_str(), kWPANTUNDNCPMCUPowerState_LowPower) || strcaseequal(str.c_str(), "lp")) {
		value_out = static_cast<uint8_t>(SPINEL_MCU_POWER_STATE_LOW_POWER);
	} else if (strcaseequal(str.c_str(), "kWPANTUNDNCPMCUPowerState_Off")) {
		value_out = static_cast<uint8_t>(SPINEL_MCU_POWER_STATE_OFF);
	} else {
		ret = kWPANTUNDStatus_InvalidArgument;
	}

	return ret;
}

int
SpinelNCPInstance::convert_value_channel_mask(const boost::any &value, boost::any &value_out)
{
	uint32_t channel_mask = any_to_int(value);
	Data mask_array(32);

	mask_array.clear();
	for (uint8_t channel = 0; channel < 32; channel++) {
		if (channel_mask & (1U << channel)) {
			mask_array.push_back(channel);
		}
	}

	value_out = mask_array;
	return kWPANTUNDStatus_Ok;
}

int
SpinelNCPInstance::convert_value_counter_reset(const boost::any &value, boost::any &value_out)
{
	// When reseting all/subset of counters, the value written to
	// related spinel property does not matter, so we just write
	// value `1`.

	(void)value;
	value_out = 1;
	return kWPANTUNDStatus_Ok;
}

int
SpinelNCPInstance::convert_value_CommissionerState(const boost::any &value, boost::any &value_out)
{
	int ret = kWPANTUNDStatus_Ok;
	std::string state_str = any_to_string(value);
	const char *str = state_str.c_str();

	if (strcaseequal(str, kWPANTUNDCommissionerState_Disabled) || strcaseequal(str, "stop") || strcaseequal(str, "off")
		|| strcaseequal(str, "0") || strcaseequal(str, "false")
	) {
		value_out = static_cast<uint8_t>(SPINEL_MESHCOP_COMMISSIONER_STATE_DISABLED);

	} else if (strcaseequal(str, kWPANTUNDCommissionerState_Active) || strcaseequal(str, "start") ||
		strcaseequal(str, "on") || strcaseequal(str, "1") || strcaseequal(str, "true")
	) {
		value_out = static_cast<uint8_t>(SPINEL_MESHCOP_COMMISSIONER_STATE_ACTIVE);

	} else {
		ret = kWPANTUNDStatus_InvalidArgument;
	}

	return ret;
}

void
SpinelNCPInstance::set_prop_NetworkKey(const boost::any &value, CallbackWithStatus cb)
{
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
		set_spinel_prop(value, cb, SPINEL_PROP_NET_MASTER_KEY, SPINEL_DATATYPE_DATA_C);
	}
}

void
SpinelNCPInstance::set_prop_InterfaceUp(const boost::any &value, CallbackWithStatus cb)
{
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
}

void
SpinelNCPInstance::set_prop_NetworkXPANID(const boost::any &value, CallbackWithStatus cb)
{
	mXPANIDWasExplicitlySet = true;
	set_spinel_prop(value, cb, SPINEL_PROP_NET_XPANID, SPINEL_DATATYPE_DATA_C);
}

void
SpinelNCPInstance::set_prop_IPv6MeshLocalPrefix(const boost::any &value, CallbackWithStatus cb)
{
	struct in6_addr addr = any_to_ipv6(value);

	start_new_task(SpinelNCPTaskSendCommand::Factory(this)
		.set_callback(cb)
		.add_command(SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_IPv6ADDR_S SPINEL_DATATYPE_UINT8_S),
			SPINEL_PROP_IPV6_ML_PREFIX,
			&addr,
			64
		))
		.finish()
	);
}

void
SpinelNCPInstance::set_prop_ThreadConfigFilterRLOCAddresses(const boost::any &value, CallbackWithStatus cb)
{
	mFilterRLOCAddresses = any_to_bool(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_ThreadConfigFilterALOCAddresses(const boost::any &value, CallbackWithStatus cb)
{
	mFilterALOCAddresses = any_to_bool(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_OpenThreadSteeringDataSetWhenJoinable(const boost::any &value, CallbackWithStatus cb)
{
	mSetSteeringDataWhenJoinable = any_to_bool(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_OpenThreadSteeringDataAddress(const boost::any &value, CallbackWithStatus cb)
{
	Data address = any_to_data(value);
	wpantund_status_t status = kWPANTUNDStatus_Ok;

	if (address.size() != sizeof(mSteeringDataAddress)) {
		status = kWPANTUNDStatus_InvalidArgument;
	} else {
		memcpy(mSteeringDataAddress, address.data(), sizeof(mSteeringDataAddress));
	}

	cb (status);
}

void
SpinelNCPInstance::set_prop_TmfProxyStream(const boost::any &value, CallbackWithStatus cb)
{
	Data packet = any_to_data(value);

	if (packet.size() > sizeof(uint16_t)*2) {
		uint16_t port = (packet[packet.size() - sizeof(port)] << 8 | packet[packet.size() - sizeof(port) + 1]);
		uint16_t locator = (packet[packet.size() - sizeof(locator) - sizeof(port)] << 8 |
				packet[packet.size() - sizeof(locator) - sizeof(port) + 1]);

		packet.resize(packet.size() - sizeof(locator) - sizeof(port));

		Data command = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(
				SPINEL_DATATYPE_DATA_WLEN_S
				SPINEL_DATATYPE_UINT16_S
				SPINEL_DATATYPE_UINT16_S
			),
			SPINEL_PROP_THREAD_TMF_PROXY_STREAM,
			packet.data(),
			packet.size(),
			locator,
			port
		);

		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(command)
			.finish()
		);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::set_prop_UdpForwardStream(const boost::any &value, CallbackWithStatus cb)
{
	Data packet = any_to_data(value);

	if (packet.size() > sizeof(uint16_t) * 2 + sizeof(in6_addr)) {
		in6_addr peer_addr;
		const size_t payload_len = packet.size() - sizeof(uint16_t) * 2 - sizeof(struct in6_addr);
		size_t i = payload_len;
		const uint16_t peer_port = (packet[i] << 8 | packet[i + 1]);
		i += sizeof(uint16_t);
		memcpy(peer_addr.s6_addr, &packet[i], sizeof(peer_addr));
		i += sizeof(peer_addr);
		const uint16_t sock_port = (packet[i] << 8 | packet[i + 1]);

		Data command = SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(
				SPINEL_DATATYPE_DATA_WLEN_S
				SPINEL_DATATYPE_UINT16_S    // Peer port
				SPINEL_DATATYPE_IPv6ADDR_S  // Peer address
				SPINEL_DATATYPE_UINT16_S    // Sock port
			),
			SPINEL_PROP_THREAD_UDP_FORWARD_STREAM,
			packet.data(),
			payload_len,
			peer_port,
			&peer_addr,
			sock_port
		);

		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(command)
			.finish()
		);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::set_prop_DatasetActiveTimestamp(const boost::any &value, CallbackWithStatus cb)
{
		mLocalDataset.mActiveTimestamp = any_to_uint64(value);
		cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetPendingTimestamp(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mPendingTimestamp = any_to_uint64(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetMasterKey(const boost::any &value, CallbackWithStatus cb)
{
	Data master_key = any_to_data(value);

	if (master_key.size() == NCP_NETWORK_KEY_SIZE) {
		mLocalDataset.mMasterKey = master_key;
		cb(kWPANTUNDStatus_Ok);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::set_prop_DatasetNetworkName(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mNetworkName = any_to_string(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetExtendedPanId(const boost::any &value, CallbackWithStatus cb)
{
	Data xpanid = any_to_data(value);

	if (xpanid.size() == sizeof(spinel_net_xpanid_t)) {
		mLocalDataset.mExtendedPanId = any_to_data(value);
		cb(kWPANTUNDStatus_Ok);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::set_prop_DatasetMeshLocalPrefix(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mMeshLocalPrefix = any_to_ipv6(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetDelay(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mDelay = static_cast<uint32_t>(any_to_int(value));
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetPanId(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mPanId = static_cast<uint16_t>(any_to_int(value));
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetChannel(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mChannel = static_cast<uint8_t>(any_to_int(value));
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetPSKc(const boost::any &value, CallbackWithStatus cb)
{
	Data pskc = any_to_data(value);

	if (pskc.size() <= sizeof(spinel_net_pskc_t)) {
		mLocalDataset.mPSKc = any_to_data(value);
		cb(kWPANTUNDStatus_Ok);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::set_prop_DatasetChannelMaskPage0(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mChannelMaskPage0 = static_cast<uint32_t>(any_to_int(value));
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetSecPolicyKeyRotation(const boost::any &value, CallbackWithStatus cb)
{
	ThreadDataset::SecurityPolicy policy = mLocalDataset.mSecurityPolicy.get();
	policy.mKeyRotationTime = static_cast<uint16_t>(any_to_int(value));
	mLocalDataset.mSecurityPolicy = policy;
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetSecPolicyFlags(const boost::any &value, CallbackWithStatus cb)
{
	ThreadDataset::SecurityPolicy policy = mLocalDataset.mSecurityPolicy.get();
	policy.mFlags = static_cast<uint8_t>(any_to_int(value));
	mLocalDataset.mSecurityPolicy = policy;
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetRawTlvs(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mRawTlvs = any_to_data(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetDestIpAddress(const boost::any &value, CallbackWithStatus cb)
{
	mLocalDataset.mDestIpAddress = any_to_ipv6(value);
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_DatasetCommand(const boost::any &value, CallbackWithStatus cb)
{
	perform_dataset_command(any_to_string(value), cb);
}

void
SpinelNCPInstance::set_prop_DaemonTickleOnHostDidWake(const boost::any &value, CallbackWithStatus cb)
{
	mTickleOnHostDidWake =  any_to_bool(value);
	syslog(LOG_INFO, "TickleOnHostDidWake is %sabled", mTickleOnHostDidWake ? "en" : "dis");
	cb(kWPANTUNDStatus_Ok);
}

void
SpinelNCPInstance::set_prop_MACFilterFixedRssi(const boost::any &value, CallbackWithStatus cb)
{
	if (mCapabilities.count(SPINEL_CAP_MAC_ALLOWLIST)) {
		mMacFilterFixedRssi = static_cast<int8_t>(any_to_int(value));
		cb(kWPANTUNDStatus_Ok);
	} else {
		cb(kWPANTUNDStatus_FeatureNotSupported);
	}
}

void
SpinelNCPInstance::set_prop_JoinerDiscernerBitLength(const boost::any &value, CallbackWithStatus cb)
{
	if (mCapabilities.count(SPINEL_CAP_THREAD_JOINER)) {
		mJoinerDiscernerBitLength = static_cast<uint8_t>(any_to_int(value));

		// Setting Discerner length to zero is to clear any previous set Discerner value
		if (mJoinerDiscernerBitLength == 0) {

			start_new_task(SpinelNCPTaskSendCommand::Factory(this)
				.set_callback(cb)
				.add_command(SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S),
					SPINEL_PROP_MESHCOP_JOINER_DISCERNER,
					mJoinerDiscernerBitLength
				))
				.finish()
			);

		} else {
			cb(kWPANTUNDStatus_Ok);
		}

	} else {
		cb(kWPANTUNDStatus_FeatureNotSupported);
	}
}

void
SpinelNCPInstance::set_prop_JoinerDiscernerValue(const boost::any &value, CallbackWithStatus cb)
{
	if (mCapabilities.count(SPINEL_CAP_THREAD_JOINER)) {
		uint64_t discerner_value = any_to_uint64(value);

		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(
					SPINEL_DATATYPE_UINT8_S
					SPINEL_DATATYPE_UINT64_S
				),
				SPINEL_PROP_MESHCOP_JOINER_DISCERNER,
				mJoinerDiscernerBitLength,
				discerner_value
			))
			.finish()
		);

	} else {
		cb(kWPANTUNDStatus_FeatureNotSupported);
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

// ----------------------------------------------------------------------------
// Property Insert Handlers

void
SpinelNCPInstance::check_capability_prop_update(const boost::any &value, CallbackWithStatus cb,
	const std::string &prop_name, unsigned int capability, PropUpdateHandler handler)
{
	if (mCapabilities.count(capability)) {
		handler(value, cb, prop_name);
	} else {
		cb(kWPANTUNDStatus_FeatureNotSupported);
	}
}

void
SpinelNCPInstance::register_insert_handler(const char *prop_name, PropUpdateHandler handler)
{
	NCPInstanceBase::register_prop_insert_handler(prop_name, handler);
}

void
SpinelNCPInstance::register_insert_handler_capability(const char *prop_name, unsigned int capability,
	PropUpdateHandler handler)
{
	register_insert_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::check_capability_prop_update, this, _1, _2, _3, capability, handler));
}

void
SpinelNCPInstance::regsiter_all_insert_handlers(void)
{
	register_insert_handler_capability(
		kWPANTUNDProperty_MACAllowlistEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		boost::bind(&SpinelNCPInstance::insert_prop_MACAllowlistEntries, this, _1, _2));
	register_insert_handler_capability(
		kWPANTUNDProperty_MACDenylistEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		boost::bind(&SpinelNCPInstance::insert_prop_MACDenylistEntries, this, _1, _2));
	register_insert_handler_capability(
		kWPANTUNDProperty_MACFilterEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		boost::bind(&SpinelNCPInstance::insert_prop_MACFilterEntries, this, _1, _2));
}

void
SpinelNCPInstance::insert_prop_MACAllowlistEntries(const boost::any &value, CallbackWithStatus cb)
{
	Data ext_address = any_to_data(value);
	int8_t rssi = kWPANTUND_Allowlist_RssiOverrideDisabled;

	if (ext_address.size() == sizeof(spinel_eui64_t)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(SPINEL_DATATYPE_EUI64_S SPINEL_DATATYPE_INT8_S),
					SPINEL_PROP_MAC_ALLOWLIST,
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

void
SpinelNCPInstance::insert_prop_MACDenylistEntries(const boost::any &value, CallbackWithStatus cb)
{
	Data ext_address = any_to_data(value);
	int8_t rssi = kWPANTUND_Allowlist_RssiOverrideDisabled;

	if (ext_address.size() == sizeof(spinel_eui64_t)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(SPINEL_DATATYPE_EUI64_S SPINEL_DATATYPE_INT8_S),
					SPINEL_PROP_MAC_DENYLIST,
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

void
SpinelNCPInstance::insert_prop_MACFilterEntries(const boost::any &value, CallbackWithStatus cb)
{
	Data ext_address = any_to_data(value);

	if (ext_address.size() == sizeof(spinel_eui64_t)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(SPINEL_DATATYPE_EUI64_S SPINEL_DATATYPE_INT8_S),
					SPINEL_PROP_MAC_FIXED_RSS,
					ext_address.data(),
					mMacFilterFixedRssi
				)
			)
			.finish()
		);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::property_insert_value(const std::string &key, const boost::any &value, CallbackWithStatus cb)
{
	syslog(LOG_INFO, "property_insert_value: key: \"%s\"", key.c_str());

	if (!mEnabled) {
		cb(kWPANTUNDStatus_InvalidWhenDisabled);
		return;
	}

	try {
		if (mVendorCustom.is_property_key_supported(key)) {
			mVendorCustom.property_insert_value(key, value, cb);

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

// ----------------------------------------------------------------------------
// Property Remove Handlers

void
SpinelNCPInstance::register_remove_handler(const char *prop_name, PropUpdateHandler handler)
{
	NCPInstanceBase::register_prop_remove_handler(prop_name, handler);
}

void
SpinelNCPInstance::register_remove_handler_capability(const char *prop_name, unsigned int capability,
	PropUpdateHandler handler)
{
	register_remove_handler(
		prop_name,
		boost::bind(&SpinelNCPInstance::check_capability_prop_update, this, _1, _2, _3, capability, handler));
}

void
SpinelNCPInstance::regsiter_all_remove_handlers(void)
{
	register_remove_handler_capability(
		kWPANTUNDProperty_MACAllowlistEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		boost::bind(&SpinelNCPInstance::remove_prop_MACAllowlistEntries, this, _1, _2));
	register_remove_handler_capability(
		kWPANTUNDProperty_MACDenylistEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		boost::bind(&SpinelNCPInstance::remove_prop_MACDenylistEntries, this, _1, _2));
	register_remove_handler_capability(
		kWPANTUNDProperty_MACFilterEntries,
		SPINEL_CAP_MAC_ALLOWLIST,
		boost::bind(&SpinelNCPInstance::remove_prop_MACFilterEntries, this, _1, _2));
}

void
SpinelNCPInstance::remove_prop_MACAllowlistEntries(const boost::any &value, CallbackWithStatus cb)
{
	Data ext_address = any_to_data(value);

	if (ext_address.size() == sizeof(spinel_eui64_t)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(SPINEL_DATATYPE_EUI64_S),
					SPINEL_PROP_MAC_ALLOWLIST,
					ext_address.data()
				)
			)
			.finish()
		);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::remove_prop_MACDenylistEntries(const boost::any &value, CallbackWithStatus cb)
{
	Data ext_address = any_to_data(value);

	if (ext_address.size() == sizeof(spinel_eui64_t)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(SPINEL_DATATYPE_EUI64_S),
					SPINEL_PROP_MAC_DENYLIST,
					ext_address.data()
				)
			)
			.finish()
		);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::remove_prop_MACFilterEntries(const boost::any &value, CallbackWithStatus cb)
{
	Data ext_address = any_to_data(value);

	if (ext_address.size() == sizeof(spinel_eui64_t)) {
		start_new_task(SpinelNCPTaskSendCommand::Factory(this)
			.set_callback(cb)
			.add_command(
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(SPINEL_DATATYPE_EUI64_S),
					SPINEL_PROP_MAC_FIXED_RSS,
					ext_address.data()
				)
			)
			.finish()
		);
	} else {
		cb(kWPANTUNDStatus_InvalidArgument);
	}
}

void
SpinelNCPInstance::property_remove_value(const std::string &key, const boost::any &value, CallbackWithStatus cb)
{
	syslog(LOG_INFO, "property_remove_value: key: \"%s\"", key.c_str());

	try {
		if (mVendorCustom.is_property_key_supported(key)) {
			mVendorCustom.property_remove_value(key, value, cb);

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
SpinelNCPInstance::handle_ncp_spinel_value_is_ON_MESH_NETS(const uint8_t *value_data_ptr, spinel_size_t value_data_len)
{
	std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator iter;
	std::multimap<IPv6Prefix, OnMeshPrefixEntry> on_mesh_prefixes(mOnMeshPrefixes);
	int num_prefix = 0;

	while (value_data_len > 0) {
		spinel_ssize_t len = 0;
		struct in6_addr *prefix_addr = NULL;
		uint8_t prefix_len = 0;
		bool stable = false;
		uint8_t flags = 0;
		bool is_local = false;
		uint16_t rloc16 = 0;

		len = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_IPv6ADDR_S // Prefix
				SPINEL_DATATYPE_UINT8_S    // Prefix length (in bits)
				SPINEL_DATATYPE_BOOL_S     // stable
				SPINEL_DATATYPE_UINT8_S    // flags
				SPINEL_DATATYPE_BOOL_S     // is_local
				SPINEL_DATATYPE_UINT16_S   // RLOC16
			),
			&prefix_addr,
			&prefix_len,
			&stable,
			&flags,
			&is_local,
			&rloc16
		);

		if (len <= 0) {
			break;
		}

		syslog(
			LOG_INFO,
			"[-NCP-]: On-mesh net [%d] \"%s/%d\" stable:%s local:%s flags:%s, rloc16:0x%04x",
			num_prefix,
			in6_addr_to_string(*prefix_addr).c_str(),
			prefix_len,
			stable ? "yes" : "no",
			is_local ? "yes" : "no",
			on_mesh_prefix_flags_to_string(flags).c_str(),
			rloc16
		);

		num_prefix++;

		if (!is_local) {

			// Go through the `on_mesh_prefixes` list (which is the copy of mOnMeshPrefixes)
			// and check if this entry is already on the list, if so remove it.

			IPv6Prefix prefix(*prefix_addr, prefix_len);
			OnMeshPrefixEntry entry(kOriginThreadNCP, flags, stable, rloc16);

			iter = on_mesh_prefixes.lower_bound(prefix);

			if (iter != on_mesh_prefixes.end()) {
				std::multimap<IPv6Prefix, OnMeshPrefixEntry>::iterator upper_iter = on_mesh_prefixes.upper_bound(prefix);

				for (; iter != upper_iter; ++iter) {
					if (iter->second == entry) {
						on_mesh_prefixes.erase(iter);
						break;
					}
				}
			}

			on_mesh_prefix_was_added(kOriginThreadNCP, *prefix_addr, prefix_len, flags, stable, rloc16);
		}

		value_data_ptr += len;
		value_data_len -= len;
	}

	// Since this was the whole list, we need to remove any prefixes
	// which originated from NCP that that weren't in the new list.

	for (iter = on_mesh_prefixes.begin(); iter != on_mesh_prefixes.end(); ++iter) {
		if (iter->second.is_from_ncp()) {
			on_mesh_prefix_was_removed(
				kOriginThreadNCP,
				iter->first.get_prefix(),
				iter->first.get_length(),
				iter->second.get_flags(),
				iter->second.is_stable(),
				iter->second.get_rloc()
			);
		}
	}
}

void
SpinelNCPInstance::handle_ncp_spinel_value_is_OFF_MESH_ROUTES(const uint8_t* value_data_ptr, spinel_size_t value_data_len)
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
SpinelNCPInstance::handle_ncp_spinel_value_is_SERVICES(const uint8_t* value_data_ptr, spinel_size_t value_data_len)
{
	uint32_t enterprise_number;
	const uint8_t *service_data_ptr = NULL;
	spinel_size_t service_data_len = 0;
	bool stable = false;
	const uint8_t *server_data_ptr = NULL;
	spinel_size_t server_data_len = 0;
	uint16_t rloc16;
	int num_services = 0;
	spinel_ssize_t len;

	std::vector<ServiceEntry> entries(mServiceEntries);
	std::vector<ServiceEntry>::iterator iter;

	while (value_data_len > 0) {
		len = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			SPINEL_DATATYPE_STRUCT_S(
				SPINEL_DATATYPE_UINT32_S    // Enterprise Number
				SPINEL_DATATYPE_DATA_WLEN_S // Service Data
				SPINEL_DATATYPE_BOOL_S      // stable
				SPINEL_DATATYPE_DATA_WLEN_S // Server Data
				SPINEL_DATATYPE_UINT16_S    // RLOC
			),
			&enterprise_number,
			&service_data_ptr,
			&service_data_len,
			&stable,
			&server_data_ptr,
			&server_data_len,
			&rloc16
		);

		if (len <= 0) {
			break;
		}

		syslog(LOG_INFO, "[-NCP-]: Service [%d] enterprise_number:%u stable:%s RLOC16:%04x",
			num_services, enterprise_number, stable ? "yes" : "no", rloc16);

		Data service_data(service_data_ptr, service_data_len);
		Data server_data(server_data_ptr, server_data_len);

		ServiceEntry entry(kOriginThreadNCP, enterprise_number, service_data, stable, server_data);

		iter = std::find(entries.begin(), entries.end(), entry);
		if (iter != entries.end()) {
			entries.erase(iter);
		}

		service_was_added(kOriginThreadNCP, enterprise_number, service_data, stable, server_data);

		value_data_ptr += len;
		value_data_len -= len;
		num_services += 1;
	}

	for (iter = entries.begin(); iter != entries.end(); ++iter) {
		if (iter->is_from_ncp()) {
			service_was_removed(kOriginThreadNCP, iter->get_enterprise_number(), iter->get_service_data());
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
		} else if ((status >= SPINEL_STATUS_JOIN__BEGIN) && (status <= SPINEL_STATUS_JOIN__END)) {
			if (status == SPINEL_STATUS_JOIN_SUCCESS) {
				change_ncp_state(COMMISSIONED);
			}
			else {
				change_ncp_state(CREDENTIALS_NEEDED);
			}
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
		boost::any mask_value;
		int ret = unpack_channel_mask(value_data_ptr, value_data_len, mask_value);

		if (ret == kWPANTUNDStatus_Ok) {
			mSupportedChannelMask = any_to_int(mask_value);
			syslog(LOG_INFO, "[-NCP-]: Supported Channel Mask 0x%x", mSupportedChannelMask);
		}

	} else if (key == SPINEL_PROP_PHY_CHAN_PREFERRED) {
		boost::any mask_value;
		int ret = unpack_channel_mask(value_data_ptr, value_data_len, mask_value);

		if (ret == kWPANTUNDStatus_Ok) {
			mPreferredChannelMask = any_to_int(mask_value);
			syslog(LOG_INFO, "[-NCP-]: Preferred Channel Mask 0x%x", mPreferredChannelMask);
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
		handle_ncp_debug_stream(value_data_ptr, value_data_len);

	} else if (key == SPINEL_PROP_STREAM_LOG) {
		handle_ncp_log_stream(value_data_ptr, value_data_len);

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

			switch (get_ncp_state())
			{
			case ISOLATED:
				if ((mThreadMode & SPINEL_THREAD_MODE_RX_ON_WHEN_IDLE) != 0) {
					change_ncp_state(ASSOCIATING);
				}
				break;

			case ASSOCIATING:
				if (mIsCommissioned && ((mThreadMode & SPINEL_THREAD_MODE_RX_ON_WHEN_IDLE) == 0)) {
					change_ncp_state(ISOLATED);
				}
				break;

			default:
				break;
			}

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
				if (mIsCommissioned && ((mThreadMode & SPINEL_THREAD_MODE_RX_ON_WHEN_IDLE) == 0)) {
					change_ncp_state(ISOLATED);
				} else {
					change_ncp_state(ASSOCIATING);
				}
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

	} else if (key == SPINEL_PROP_MESHCOP_COMMISSIONER_STATE) {
		boost::any value;
		int status;
		status = unpack_commissioner_state(value_data_ptr, value_data_len, value);
		if (status == kWPANTUNDStatus_Ok) {
			syslog(LOG_INFO, "[-NCP-]: Thread Commissioner state is \"%s\"", any_to_string(value).c_str());
		}

	} else if (key == SPINEL_PROP_THREAD_ON_MESH_NETS) {
		handle_ncp_spinel_value_is_ON_MESH_NETS(value_data_ptr, value_data_len);

	} else if (key == SPINEL_PROP_THREAD_OFF_MESH_ROUTES) {
		handle_ncp_spinel_value_is_OFF_MESH_ROUTES(value_data_ptr, value_data_len);

	} else if (key == SPINEL_PROP_SERVER_SERVICES) {
		handle_ncp_spinel_value_is_SERVICES(value_data_ptr, value_data_len);

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

	} else if (key == SPINEL_PROP_THREAD_UDP_FORWARD_STREAM) {
		const uint8_t* frame_ptr(NULL);
		unsigned int frame_len(0);
		uint16_t peer_port = 0;
		in6_addr *peer_addr;
		uint16_t sock_port = 0;
		spinel_ssize_t ret;
		Data data;

		ret = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			SPINEL_DATATYPE_DATA_S
			SPINEL_DATATYPE_UINT16_S    // Peer port
			SPINEL_DATATYPE_IPv6ADDR_S  // Peer address
			SPINEL_DATATYPE_UINT16_S,   // Sock port
			&frame_ptr,
			&frame_len,
			&peer_port,
			&peer_addr,
			&sock_port
		);

		__ASSERT_MACROS_check(ret > 0);

		// Analyze the packet to determine if it should be dropped.
		if (ret > 0) {
			// append frame
			data.append(frame_ptr, frame_len);
			// pack the locator in big endian.
			data.push_back(peer_port >> 8);
			data.push_back(peer_port & 0xff);
			data.append(peer_addr->s6_addr, sizeof(*peer_addr));
			// pack the port in big endian.
			data.push_back(sock_port >> 8);
			data.push_back(sock_port & 0xff);
			signal_property_changed(kWPANTUNDProperty_UdpForwardStream, data);
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


	} else if (key == SPINEL_PROP_THREAD_ADDRESS_CACHE_TABLE) {
		boost::any value;
		if ((unpack_address_cache_table(value_data_ptr, value_data_len, value, false) == kWPANTUNDStatus_Ok)
			&& (value.type() == typeid(std::list<std::string>))
		) {
			std::list<std::string> list = boost::any_cast<std::list<std::string> >(value);
			int num_entries = 0;

			for (std::list<std::string>::iterator it = list.begin(); it != list.end(); it++) {
				num_entries++;
				syslog(LOG_INFO, "[-NCP-] AddressCache: %02d %s", num_entries, it->c_str());
			}
			syslog(LOG_INFO, "[-NCP-] AddressCache: Total %d entr%s", num_entries, (num_entries > 1) ? "ies" : "y");
		}

	} else if (key == SPINEL_PROP_NET_PARTITION_ID) {
		uint32_t paritition_id = 0;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT32_S, &paritition_id);
		syslog(LOG_INFO, "[-NCP-] Partition id: %u (0x%x)", paritition_id, paritition_id);

	} else if (key == SPINEL_PROP_THREAD_LEADER_NETWORK_DATA) {
		char net_data_cstr_buf[540];
		encode_data_into_string(value_data_ptr, value_data_len, net_data_cstr_buf, sizeof(net_data_cstr_buf), 0);
		syslog(LOG_INFO, "[-NCP-] Leader network data: [%s]", net_data_cstr_buf);

	} else if (key == SPINEL_PROP_RCP_VERSION) {
		const char *rcp_version = NULL;
		spinel_ssize_t len;

		len = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UTF8_S, &rcp_version);

		if (len > 0) {
			mRcpVersion = std::string(rcp_version);
			syslog(LOG_NOTICE, "[-NCP-]: RCP is running \"%s\"", rcp_version);
		}

	} else if (key == SPINEL_PROP_SLAAC_ENABLED) {
		bool enabled;
		spinel_ssize_t len;

		len = spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_BOOL_S, &enabled);

		if (len > 0) {
			syslog(LOG_NOTICE, "[-NCP-]: SLAAC %sabled", enabled ? "en" : "dis");
			mNCPHandlesSLAAC = enabled;
		}

	} else if (key == SPINEL_PROP_MESHCOP_JOINER_STATE) {
		boost::any value;

		if (unpack_meshcop_joiner_state(value_data_ptr, value_data_len, value) == kWPANTUNDStatus_Ok) {
			syslog(LOG_NOTICE, "[-NCP-]: Joiner state \"%s\"", any_to_string(value).c_str());
		}

	} else if (key == SPINEL_PROP_THREAD_NETWORK_TIME) {
		ValueMap result;
		std::string result_as_string;

		if (unpack_thread_network_time_as_valmap(value_data_ptr, value_data_len, result) == kWPANTUNDStatus_Ok) {
			if (unpack_thread_network_time_as_string(value_data_ptr, value_data_len, result_as_string) == kWPANTUNDStatus_Ok) {
				syslog(LOG_INFO, "[-NCP-]: Network time update: %s", result_as_string.c_str());
			} else {
				syslog(LOG_WARNING, "[-NCP-]: Failed to extract network time update for logging");
			}

			handle_network_time_update(result);
		} else {
			syslog(LOG_WARNING, "[-NCP-]: Failed to unpack network time update");
		}
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

	} else if (key == SPINEL_PROP_THREAD_CHILD_TABLE) {
		SpinelNCPTaskGetNetworkTopology::TableEntry child_entry;
		int status;

		status = SpinelNCPTaskGetNetworkTopology::parse_child_entry(value_data_ptr, value_data_len, child_entry);

		if (status == kWPANTUNDStatus_Ok) {
			syslog(LOG_INFO, "[-NCP-]: ChildTable entry added: %s", child_entry.get_as_string().c_str());
		}

	} else if (key == SPINEL_PROP_THREAD_NEIGHBOR_TABLE) {
		SpinelNCPTaskGetNetworkTopology::TableEntry neighbor_entry;
		int status;

		status = SpinelNCPTaskGetNetworkTopology::parse_neighbor_entry(value_data_ptr, value_data_len, neighbor_entry);

		if (status == kWPANTUNDStatus_Ok) {
			syslog(LOG_INFO, "[-NCP-]: Neighbor(Router) entry added: %s", neighbor_entry.get_as_string().c_str());
		}

	} else if (key == SPINEL_PROP_MESHCOP_COMMISSIONER_ENERGY_SCAN_RESULT) {
		spinel_ssize_t len;
		uint32_t channel_mask;
		const uint8_t *energy_data = NULL;
		unsigned int energy_data_len = 0;
		ValueMap entry;

		len = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			(
				SPINEL_DATATYPE_UINT32_S
				SPINEL_DATATYPE_DATA_WLEN_S
			),
			&channel_mask,
			&energy_data,
			&energy_data_len
		);

		__ASSERT_MACROS_check(len > 0);

		entry[kWPANTUNDValueMapKey_CommrEnergyScanResult_ChannelMask] = channel_mask;
		entry[kWPANTUNDValueMapKey_CommrEnergyScanResult_Data] = Data(energy_data, energy_data_len);

		if (mCommissionerEnergyScanResult.size() == kMaxCommissionerEnergyScanResultEntries) {
			mCommissionerEnergyScanResult.pop_front();
		}

		mCommissionerEnergyScanResult.push_back(entry);

	} else if (key == SPINEL_PROP_MESHCOP_COMMISSIONER_PAN_ID_CONFLICT_RESULT) {
		spinel_ssize_t len;
		uint16_t panid;
		uint32_t channel_mask;
		ValueMap entry;

		len = spinel_datatype_unpack(
			value_data_ptr,
			value_data_len,
			(
				SPINEL_DATATYPE_UINT16_S
				SPINEL_DATATYPE_UINT32_S
			),
			&panid,
			&channel_mask
		);

		__ASSERT_MACROS_check(len > 0);

		entry[kWPANTUNDValueMapKey_CommrPanIdConflict_PanId] = panid;
		entry[kWPANTUNDValueMapKey_CommrPanIdConflict_ChannelMask] = channel_mask;

		if (mCommissionerPanIdConflictResult.size() == kMaxCommissionerPanIdConflictResultEntries) {
			mCommissionerPanIdConflictResult.pop_front();
		}

		mCommissionerPanIdConflictResult.push_back(entry);
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

	} else if (key == SPINEL_PROP_THREAD_NEIGHBOR_TABLE) {
		SpinelNCPTaskGetNetworkTopology::TableEntry neighbor_entry;
		int status;

		status = SpinelNCPTaskGetNetworkTopology::parse_neighbor_entry(value_data_ptr, value_data_len, neighbor_entry);

		if (status == kWPANTUNDStatus_Ok) {
			syslog(LOG_INFO, "[-NCP-]: Neighbor(Router) entry removed: %s", neighbor_entry.get_as_string().c_str());
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
	case SPINEL_CMD_PROP_VALUE_INSERTED:
	case SPINEL_CMD_PROP_VALUE_REMOVED:
		{
			spinel_prop_key_t key = SPINEL_PROP_LAST_STATUS;
			uint8_t* value_data_ptr = NULL;
			spinel_size_t value_data_len = 0;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len);

			__ASSERT_MACROS_check(ret != -1);

			if (ret == -1) {
				break;
			}

			switch (command) {
			case SPINEL_CMD_PROP_VALUE_IS:
				handle_ncp_spinel_value_is(key, value_data_ptr, value_data_len);
				break;
			case SPINEL_CMD_PROP_VALUE_INSERTED:
				handle_ncp_spinel_value_inserted(key, value_data_ptr, value_data_len);
				break;
			case SPINEL_CMD_PROP_VALUE_REMOVED:
				handle_ncp_spinel_value_removed(key, value_data_ptr, value_data_len);
				break;
			}
		}
		break;

	default:
		process_event(EVENT_NCP(command), cmd_data_ptr[0], cmd_data_ptr, cmd_data_len);
	}
}

bool
SpinelNCPInstance::should_filter_address(const struct in6_addr &addr, uint8_t prefix_len)
{
	static const uint8_t service_aloc_start = 0x10;
	static const uint8_t service_aloc_end = 0x2F;
	static const uint8_t rloc_bytes[] = {0x00,0x00,0x00,0xFF,0xFE,0x00};
	bool should_filter = false;

	if (mFilterRLOCAddresses) {
		// Filter RLOC link-local or mesh-local addresses

		if (0 == memcmp(rloc_bytes, addr.s6_addr + 8, sizeof(rloc_bytes))) {
			if( addr.s6_addr[ 14 ] == 0xFC ) {
				if (addr.s6_addr[15] < service_aloc_start || addr.s6_addr[15] > service_aloc_end)
				{
					should_filter = mFilterALOCAddresses;
				}
			} else {
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
SpinelNCPInstance::add_service_on_ncp(uint32_t enterprise_number, const Data& service_data, bool stable,
	const Data& server_data, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Adding service with enterprise number:%u to NCP", enterprise_number);

	if (mCapabilities.count(SPINEL_CAP_THREAD_SERVICE) > 0) {
		factory.set_lock_property(SPINEL_PROP_SERVER_ALLOW_LOCAL_DATA_CHANGE);
		factory.set_callback(cb);

		factory.add_command(SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(
				SPINEL_DATATYPE_UINT32_S    // Enterprise Number
				SPINEL_DATATYPE_DATA_WLEN_S // Service Data
				SPINEL_DATATYPE_BOOL_S      // stable
				SPINEL_DATATYPE_DATA_WLEN_S // Server Data
			),
			SPINEL_PROP_SERVER_SERVICES,
			enterprise_number,
			service_data.data(),
			service_data.size(),
			stable,
			server_data.data(),
			server_data.size()
		));

		start_new_task(factory.finish());
	} else {
		syslog(LOG_ERR, "%s capability not supported", spinel_capability_to_cstr(SPINEL_CAP_THREAD_SERVICE));
		cb(kWPANTUNDStatus_FeatureNotSupported);
	}
}

void
SpinelNCPInstance::remove_service_on_ncp(uint32_t enterprise_number, const Data& service_data, CallbackWithStatus cb)
{
	SpinelNCPTaskSendCommand::Factory factory(this);

	syslog(LOG_NOTICE, "Removing service with enterprise number:%u from NCP", enterprise_number);

	if (mCapabilities.count(SPINEL_CAP_THREAD_SERVICE) > 0) {
		factory.set_lock_property(SPINEL_PROP_SERVER_ALLOW_LOCAL_DATA_CHANGE);
		factory.set_callback(cb);

		factory.add_command(SpinelPackData(
			SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(
				SPINEL_DATATYPE_UINT32_S    // Enterprise Number
				SPINEL_DATATYPE_DATA_WLEN_S // Service Data
			),
			SPINEL_PROP_SERVER_SERVICES,
			enterprise_number,
			service_data.data(),
			service_data.size()
		));

		start_new_task(factory.finish());
	} else {
		syslog(LOG_ERR, "%s capability not supported", spinel_capability_to_cstr(SPINEL_CAP_THREAD_SERVICE));
		cb(kWPANTUNDStatus_FeatureNotSupported);
	}
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

void
SpinelNCPInstance::log_spinel_frame(SpinelFrameOrigin origin, const uint8_t *frame_ptr, spinel_size_t frame_len)
{
	int logmask = setlogmask(0);

	setlogmask(logmask);

	if (logmask & LOG_MASK(LOG_INFO)) {
		std::string log;
		uint8_t header = 0;
		unsigned int command = 0;
		const uint8_t *cmd_payload_ptr = NULL;
		spinel_size_t cmd_payload_len = 0;
		spinel_ssize_t read_len;
		uint8_t tid;
		const char *command_str;
		const char *origin_str = (origin == kDriverToNCP) ? "[->NCP]" : "[NCP->]";

		read_len = spinel_datatype_unpack(frame_ptr, frame_len, "CiD", &header, &command, &cmd_payload_ptr,
			&cmd_payload_len);
		require_quiet(read_len > 0, bail);

		tid = SPINEL_HEADER_GET_TID(header);
		command_str = spinel_command_to_cstr(command);

		switch (command) {
		case SPINEL_CMD_NOOP:
		case SPINEL_CMD_RESET:
		case SPINEL_CMD_NET_CLEAR:
			syslog(LOG_INFO, "%s (%d) %s", origin_str, tid, command_str);
			break;

		case SPINEL_CMD_PROP_VALUE_GET:
		case SPINEL_CMD_PROP_VALUE_SET:
		case SPINEL_CMD_PROP_VALUE_INSERT:
		case SPINEL_CMD_PROP_VALUE_REMOVE:
		case SPINEL_CMD_PROP_VALUE_IS:
		case SPINEL_CMD_PROP_VALUE_INSERTED:
		case SPINEL_CMD_PROP_VALUE_REMOVED:
			{
				spinel_prop_key_t prop_key = SPINEL_PROP_LAST_STATUS;
				const uint8_t *value_ptr = NULL;
				spinel_size_t value_len = 0;
				const char *prop_str;
				bool skip_value_dump = false;
				char value_dump_str[2 * kWPANTUND_SpinelPropValueDumpLen + 1];

				read_len = spinel_datatype_unpack(cmd_payload_ptr, cmd_payload_len, "iD", &prop_key, &value_ptr,
					&value_len);
				require_quiet(read_len > 0, bail);

				prop_str = spinel_prop_key_to_cstr(prop_key);

				switch (prop_key) {
				case SPINEL_PROP_STREAM_DEBUG:           // Handled by `handle_ncp_debug_stream()`
				case SPINEL_PROP_STREAM_LOG:             // Handled by `handle_ncp_log_stream()`
				case SPINEL_PROP_STREAM_NET:             // Handled by `handle_normal_ipv6_from_ncp()
				case SPINEL_PROP_STREAM_NET_INSECURE:    // Handled by `handle_normal_ipv6_from_ncp()
					// Skip logging any of above properties
					goto bail;

				case SPINEL_PROP_NET_MASTER_KEY:
				case SPINEL_PROP_THREAD_ACTIVE_DATASET:
				case SPINEL_PROP_THREAD_PENDING_DATASET:
				case SPINEL_PROP_MESHCOP_JOINER_COMMISSIONING:
				case SPINEL_PROP_NET_PSKC:
				case SPINEL_PROP_MESHCOP_COMMISSIONER_JOINERS:
					// Hide the value by skipping value dump
					skip_value_dump = true;
					break;

				default:
					skip_value_dump = false;
					encode_data_into_string(value_ptr, value_len, value_dump_str, sizeof(value_dump_str), 0);
					break;
				}

				if (command == SPINEL_CMD_PROP_VALUE_GET) {
					syslog(LOG_INFO, "%s (%d) %s(%s)", origin_str, tid, command_str, prop_str);
				} else {
					syslog(LOG_INFO, "%s (%d) %s(%s) [%s%s]", origin_str, tid, command_str, prop_str,
						skip_value_dump ? "-- value hidden --" : value_dump_str,
						skip_value_dump || (value_len <= kWPANTUND_SpinelPropValueDumpLen) ? "" : "...");
				}
			}
			break;

		case SPINEL_CMD_PEEK:
		case SPINEL_CMD_POKE:
		case SPINEL_CMD_PEEK_RET:
			{
				uint32_t address = 0;
				uint16_t count = 0;
				read_len = spinel_datatype_unpack(cmd_payload_ptr, cmd_payload_len, "LS", &address, &count);
				require_quiet(read_len > 0, bail);
				syslog(LOG_INFO, "%s (%d) %s(0x%x, %d)", origin_str, tid, command_str, address, count);
			}
			break;

		default:
			syslog(LOG_INFO, "%s (%d) %s(cmd_id:%d)", origin_str, tid, command_str, command);
			break;
		}
	}

bail:
	return;
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
