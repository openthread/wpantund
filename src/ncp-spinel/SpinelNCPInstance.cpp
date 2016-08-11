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
#include "any-to.h"
#include "spinel-extra.h"

#define kWPANTUNDProperty_Spinel_CounterPrefix		"NCP:Counter:"

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
            syslog(LOG_INFO, "NCP => %s\n", linebuffer);
            linepos = 0;
        }
    }
}

int
SpinelNCPInstance::start_new_task(const boost::shared_ptr<SpinelNCPTask> &task)
{
	if (ncp_state_is_detached_from_ncp(get_ncp_state())) {
		task->finish(kWPANTUNDStatus_InvalidWhenDisabled);
	} else if (PT_SCHEDULE(task->process_event(EVENT_STARTING_TASK))) {

		if (ncp_state_is_sleeping(get_ncp_state())
			&& (dynamic_cast<const SpinelNCPTaskWake*>(task.get()) == NULL)
		) {
			start_new_task(boost::shared_ptr<SpinelNCPTask>(new SpinelNCPTaskWake(this, NilReturn())));
		}
		mTaskQueue.push_back(task);
		return 0;
	}
	return -1;
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
	NCPInstanceBase(settings), mControlInterface(this)
{
	mOutboundBufferLen = 0;
	mInboundHeader = 0;
	mDefaultChannelMask = 0x07FFF800;

	if (!settings.empty()) {
		int status;
		Settings::const_iterator iter;

		for(iter = settings.begin(); iter != settings.end(); iter++) {
			if (!NCPInstanceBase::setup_property_supported_by_class(iter->first)) {
				status = static_cast<NCPControlInterface&>(get_control_interface())
					.set_property(iter->first, iter->second);

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
	properties.insert(kWPANTUNDProperty_NCPFrequency);
	properties.insert(kWPANTUNDProperty_NCPRSSI);

	if (mCapabilities.count(SPINEL_CAP_NET_THREAD_1_0)) {
		properties.insert(kWPANTUNDProperty_ThreadLeaderAddress);
		properties.insert(kWPANTUNDProperty_ThreadLeaderRouterID);
		properties.insert(kWPANTUNDProperty_ThreadLeaderWeight);
		properties.insert(kWPANTUNDProperty_ThreadLeaderLocalWeight);
		properties.insert(kWPANTUNDProperty_ThreadNetworkData);
		properties.insert(kWPANTUNDProperty_ThreadNetworkDataVersion);
		properties.insert(kWPANTUNDProperty_ThreadStableNetworkDataVersion);
	}

	if (mCapabilities.count(SPINEL_CAP_COUNTERS)) {
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_ACK_REQ");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_ACKED");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_NO_ACK_REQ");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_DATA");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_DATA_POLL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_BEACON");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_BEACON_REQ");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_OTHER");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_PKT_RETRY");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "TX_ERR_CCA");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_TOTAL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_DATA");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_DATA_POLL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_BEACON");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_BEACON_REQ");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_OTHER");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_FILT_WL");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_PKT_FILT_DA");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_ERR_EMPTY");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_ERR_UKWN_NBR");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_ERR_NVLD_SADDR");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_ERR_SECURITY");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_ERR_BAD_FCS");
		properties.insert(kWPANTUNDProperty_Spinel_CounterPrefix "RX_ERR_OTHER");
	}

	return properties;
}

cms_t
SpinelNCPInstance::get_ms_to_next_event(void)
{
	cms_t cms = EventHandler::get_ms_to_next_event();

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

	if (cms < 0) {
		cms = 0;
	}

	return cms;
}

void
SpinelNCPInstance::get_property(
	const std::string& key,
	CallbackWithStatusArg1 cb
) {
	if (strcaseequal(key.c_str(), kWPANTUNDProperty_ConfigNCPDriverName)) {
		cb(0, boost::any(std::string("spinel")));
	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPCCAThreshold)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_PHY_CCA_THRESHOLD),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_INT8_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}
	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPFrequency)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_PHY_FREQ),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_INT32_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}
	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKey)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_NET_MASTER_KEY),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_DATA_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}
	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKeyIndex)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_NET_KEY_SEQUENCE),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_UINT32_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}
	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPRSSI)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_PHY_RSSI),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_INT8_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderAddress)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_LEADER_ADDR),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_IPv6ADDR_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderRouterID)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_LEADER_RID),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_UINT8_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderWeight)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_LEADER_WEIGHT),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_UINT8_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadLeaderLocalWeight)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_LOCAL_LEADER_WEIGHT),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_UINT8_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNetworkData)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_NETWORK_DATA),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_DATA_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadNetworkDataVersion)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_NETWORK_DATA_VERSION),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_UINT8_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadStableNetworkData)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_STABLE_NETWORK_DATA),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_DATA_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_ThreadStableNetworkDataVersion)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_THREAD_STABLE_NETWORK_DATA_VERSION),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_UINT8_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}


	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_IPv6MeshLocalPrefix) && !buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix))) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ML_PREFIX),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_IPv6ADDR_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_IPv6MeshLocalAddress) && !buffer_is_nonzero(mNCPV6Prefix, sizeof(mNCPV6Prefix))) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ML_ADDR),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_IPv6ADDR_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
		}

	} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_IPv6LinkLocalAddress) && !IN6_IS_ADDR_LINKLOCAL(&mNCPLinkLocalAddress)) {
		if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				cb,
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ML_ADDR),
				NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
				SPINEL_DATATYPE_IPv6ADDR_S
			)
		))) {
			cb(kWPANTUNDStatus_InvalidForCurrentState, boost::any());
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
		CNTR_KEY(RX_PKT_TOTAL)
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

#undef CNTR_KEY

		if (cntr_key != 0) {
			start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					cb,
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, cntr_key),
					NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
					SPINEL_DATATYPE_UINT32_S
				)
			));
		} else {
			NCPInstanceBase::get_property(key, cb);
		}
	} else {
		NCPInstanceBase::get_property(key, cb);
	}
}

void
SpinelNCPInstance::set_property(
	const std::string& key,
	const boost::any& value,
	CallbackWithStatus cb
) {
	syslog(LOG_INFO, "set_property: key: \"%s\"", key.c_str());

	// If we are disabled, then the only property we
	// are allowed to set is kWPANTUNDProperty_DaemonEnabled.
	if (!mEnabled && !strcaseequal(key.c_str(), kWPANTUNDProperty_DaemonEnabled)) {
		cb(kWPANTUNDStatus_InvalidWhenDisabled);
		return;
	}

	try {
		if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPChannel)) {
			int channel = any_to_int(value);
			mCurrentNetworkInstance.channel = channel;

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT8_S), SPINEL_PROP_PHY_CHAN, channel)
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NCPCCAThreshold)) {
			int cca = any_to_int(value);

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_INT8_S), SPINEL_PROP_PHY_CCA_THRESHOLD, cca)
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkPANID)) {
			uint16_t panid = any_to_int(value);

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT16_S), SPINEL_PROP_MAC_15_4_PANID, panid)
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKey)) {
			Data network_key = any_to_data(value);

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S), SPINEL_PROP_NET_MASTER_KEY, network_key.data(), network_key.size())
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkXPANID)) {
			Data xpanid = any_to_data(value);

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S), SPINEL_PROP_NET_XPANID, xpanid.data(), xpanid.size())
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKey)) {
			Data network_key = any_to_data(value);

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_DATA_S), SPINEL_PROP_NET_MASTER_KEY, network_key.data(), network_key.size())
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkKeyIndex)) {
			uint32_t key_index = any_to_int(value);

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT32_S), SPINEL_PROP_NET_KEY_SEQUENCE, key_index)
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else if (strcaseequal(key.c_str(), kWPANTUNDProperty_NetworkName)) {
			std::string str = any_to_string(value);

			if (-1 == start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					boost::bind(cb,_1),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UTF8_S), SPINEL_PROP_NET_NETWORK_NAME, str.c_str())
				)
			))) {
				cb(kWPANTUNDStatus_InvalidForCurrentState);
			}
		} else {
			NCPInstanceBase::set_property(key, value, cb);
		}

	} catch (const boost::bad_any_cast &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"set_property: Bad type for property \"%s\" (%s)", key.c_str(), x.what());
		cb(kWPANTUNDStatus_InvalidArgument);
	} catch (const std::invalid_argument &x) {
		// We will get a bad_any_cast exception if the property is of
		// the wrong type.
		syslog(LOG_ERR,"set_property: Invalid argument for property \"%s\" (%s)", key.c_str(), x.what());
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
SpinelNCPInstance::handle_ncp_spinel_value_is(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len)
{
	if (key == SPINEL_PROP_LAST_STATUS) {
		spinel_status_t status = SPINEL_STATUS_OK;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "i", &status);
		if ((status >= SPINEL_STATUS_RESET__BEGIN) && (status <= SPINEL_STATUS_RESET__END)) {
			syslog(LOG_NOTICE, "[-NCP-]: NCP was reset (%s, %d)", spinel_status_to_cstr(status), status);
			process_event(EVENT_NCP_RESET, status);
			if (!mResetIsExpected && (mDriverState == NORMAL_OPERATION)) {
				wpantund_status_t wstatus = kWPANTUNDStatus_NCP_Reset;
				switch(status) {
				case SPINEL_STATUS_RESET_CRASH:
				case SPINEL_STATUS_RESET_FAULT:
				case SPINEL_STATUS_RESET_ASSERT:
				case SPINEL_STATUS_RESET_OTHER:
					wstatus = kWPANTUNDStatus_NCP_Crashed;
					break;
				default:
					break;
				}
				reinitialize_ncp();
				reset_tasks(wstatus);
			}
			return;
		} else if (status == SPINEL_STATUS_INVALID_COMMAND) {
			syslog(LOG_NOTICE, "[-NCP-]: COMMAND NOT RECOGNIZED");
		}
	} else if (key == SPINEL_PROP_NCP_VERSION) {
		const char* ncp_version = NULL;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "U", &ncp_version);

		set_ncp_version_string(ncp_version);


	} else if (key == SPINEL_PROP_INTERFACE_TYPE) {
		unsigned int interface_type = 0;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "i", &interface_type);

		if (interface_type != SPINEL_PROTOCOL_TYPE_THREAD) {
			syslog(LOG_CRIT, "[-NCP-]: NCP is using unsupported protocol type (%d)", interface_type);
			change_ncp_state(FAULT);
			// TODO: Possible firmware update
		}


	} else if (key == SPINEL_PROP_PROTOCOL_VERSION) {
		unsigned int protocol_version_major = 0;
		unsigned int protocol_version_minor = 0;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "ii", &protocol_version_major, &protocol_version_minor);

		if (protocol_version_major != SPINEL_PROTOCOL_VERSION_THREAD_MAJOR) {
			syslog(LOG_CRIT, "[-NCP-]: NCP is using unsupported protocol version (NCP:%d, wpantund:%d)", protocol_version_major, SPINEL_PROTOCOL_VERSION_THREAD_MAJOR);
			change_ncp_state(FAULT);
			// TODO: Possible firmware update
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

			data_ptr += parse_len;
			data_len -= parse_len;
		}

		if (capabilities != mCapabilities) {
			mCapabilities = capabilities;
		}

	} else if (key == SPINEL_PROP_NET_NETWORK_NAME) {
		const char* value = NULL;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "U", &value);
		if (value && (mCurrentNetworkInstance.name != value)) {
			mCurrentNetworkInstance.name = value;
			signal_property_changed(kWPANTUNDProperty_NetworkName, mCurrentNetworkInstance.name);
		}

	} else if (key == SPINEL_PROP_IPV6_LL_ADDR) {
		struct in6_addr *addr = NULL;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "6", &addr);
		if (addr) {
			memcpy(mNCPLinkLocalAddress.s6_addr, addr->s6_addr, sizeof(mNCPLinkLocalAddress));
			signal_property_changed(kWPANTUNDProperty_IPv6LinkLocalAddress, in6_addr_to_string(*addr));
		}

	} else if (key == SPINEL_PROP_IPV6_ML_ADDR) {
		struct in6_addr *addr = NULL;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "6", &addr);
		if (addr
		 && buffer_is_nonzero(addr->s6_addr, 8)
		 && (0 != memcmp(mNCPMeshLocalAddress.s6_addr, addr->s6_addr, sizeof(mNCPMeshLocalAddress)))
		) {
			memcpy(mNCPMeshLocalAddress.s6_addr, addr->s6_addr, sizeof(mNCPMeshLocalAddress));
			signal_property_changed(kWPANTUNDProperty_IPv6MeshLocalAddress, in6_addr_to_string(*addr));
			mPrimaryInterface->set_realm_local_address(addr);
		}

	} else if (key == SPINEL_PROP_IPV6_ML_PREFIX) {
		struct in6_addr *addr = NULL;
		spinel_datatype_unpack(value_data_ptr, value_data_len, "6", &addr);
		if (addr
		 && buffer_is_nonzero(addr->s6_addr, 8)
		 && (0 != memcmp(mNCPV6Prefix, addr, sizeof(mNCPV6Prefix)))
		) {
			memcpy(mNCPV6Prefix, addr, sizeof(mNCPV6Prefix));
			struct in6_addr prefix_addr (mNCPMeshLocalAddress);
			// Zero out the lower 64 bits.
			memset(prefix_addr.s6_addr+8, 0, 8);
			signal_property_changed(kWPANTUNDProperty_IPv6MeshLocalPrefix, in6_addr_to_string(prefix_addr) + "/64");
		}

	} else if (key == SPINEL_PROP_IPV6_ADDRESS_TABLE) {
		std::map<struct in6_addr, GlobalAddressEntry>::const_iterator iter;
		std::map<struct in6_addr, GlobalAddressEntry> global_addresses(mGlobalAddresses);
		clear_nonpermanent_global_addresses();

		while(value_data_len > 0) {
			const uint8_t *entry_ptr = NULL;
			spinel_size_t entry_len = 0;
			spinel_ssize_t len = 0;
			len = spinel_datatype_unpack(value_data_ptr, value_data_len, "D.", &entry_ptr, &entry_len);
			if (len < 1) {
				break;
			}
			global_addresses.erase(*reinterpret_cast<const struct in6_addr*>(entry_ptr));
			handle_ncp_spinel_value_inserted(key, entry_ptr, entry_len);

			value_data_ptr += len;
			value_data_len -= len;
		}

		// Since this was the whole list, we need
		// to remove the addresses that weren't in
		// the list.
		for (iter = global_addresses.begin(); iter!= global_addresses.end(); ++iter) {
			if (!iter->second.mUserAdded) {
				update_global_address(iter->first, 0, 0, 0);
			}
		}
	} else if (key == SPINEL_PROP_HWADDR) {
		nl::Data hwaddr(value_data_ptr, value_data_len);
		if (value_data_len == sizeof(mNCPHardwareAddress)) {
			if (0 != memcmp(value_data_ptr, mNCPHardwareAddress, sizeof(mNCPHardwareAddress))) {
				set_hardware_address(value_data_ptr);
			}
		}

	} else if (key == SPINEL_PROP_MAC_15_4_PANID) {
		uint16_t panid;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT16_S, &panid);
		if (panid != mCurrentNetworkInstance.panid) {
			mCurrentNetworkInstance.panid = panid;
			signal_property_changed(kWPANTUNDProperty_NetworkPANID, panid);
		}

	} else if (key == SPINEL_PROP_NET_XPANID) {
		nl::Data xpanid(value_data_ptr, value_data_len);
		if ((value_data_len == 8) && 0 != memcmp(xpanid.data(), mCurrentNetworkInstance.xpanid, 8)) {
			memcpy(mCurrentNetworkInstance.xpanid, xpanid.data(), 8);
			signal_property_changed(kWPANTUNDProperty_NetworkXPANID, xpanid);
		}

	} else if (key == SPINEL_PROP_NET_MASTER_KEY) {
		nl::Data network_key(value_data_ptr, value_data_len);
		if (network_key != mNetworkKey) {
			mNetworkKey = network_key;
			signal_property_changed(kWPANTUNDProperty_NetworkKey, mNetworkKey);
		}

	} else if (key == SPINEL_PROP_NET_KEY_SEQUENCE) {
		uint32_t network_key_index;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT32_S, &network_key_index);
		if (network_key_index != mNetworkKeyIndex) {
			mNetworkKeyIndex = network_key_index;
			signal_property_changed(kWPANTUNDProperty_NetworkKeyIndex, mNetworkKeyIndex);
		}

	} else if (key == SPINEL_PROP_PHY_CHAN) {
		unsigned int value;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT_PACKED_S, &value);
		if (value != mCurrentNetworkInstance.channel) {
			mCurrentNetworkInstance.channel = value;
			signal_property_changed(kWPANTUNDProperty_NCPChannel, mCurrentNetworkInstance.channel);
		}

	} else if (key == SPINEL_PROP_PHY_TX_POWER) {
		int8_t value;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_INT8_S, &value);
		if (value != mTXPower) {
			mTXPower = value;
			signal_property_changed(kWPANTUNDProperty_NCPTXPower, mTXPower);
		}

	} else if (key == SPINEL_PROP_STREAM_DEBUG) {
        handle_ncp_log(value_data_ptr, value_data_len);

	} else if (key == SPINEL_PROP_NET_ROLE) {
		uint8_t value;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &value);

		if (value == SPINEL_NET_ROLE_CHILD) {
			if (mNodeType != END_DEVICE) {
				mNodeType = END_DEVICE;
				signal_property_changed(kWPANTUNDProperty_NetworkNodeType, node_type_to_string(mNodeType));
			}
		} else if (value == SPINEL_NET_ROLE_ROUTER) {
			if (mNodeType != ROUTER) {
				mNodeType = ROUTER;
				signal_property_changed(kWPANTUNDProperty_NetworkNodeType, node_type_to_string(mNodeType));
			}
		} else if (value == SPINEL_NET_ROLE_LEADER) {
			if (mNodeType != LEADER) {
				mNodeType = LEADER;
				signal_property_changed(kWPANTUNDProperty_NetworkNodeType, node_type_to_string(mNodeType));
			}
		}
	} else if (key == SPINEL_PROP_NET_STATE) {
		uint8_t value;
		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &value);

		if (value == SPINEL_NET_STATE_OFFLINE) {
			change_ncp_state(OFFLINE);
		} else if (value == SPINEL_NET_STATE_DETACHED) {
			change_ncp_state(COMMISSIONED);
		} else if (value == SPINEL_NET_STATE_ATTACHING) {
			change_ncp_state(ASSOCIATING);
		} else if (value == SPINEL_NET_STATE_ATTACHED) {
			if (!ncp_state_is_associated(get_ncp_state())) {
				change_ncp_state(ASSOCIATED);
			}
		}

	} else if (key == SPINEL_PROP_THREAD_ASSISTING_PORTS) {
		bool is_assisting = (value_data_len != 0);
		uint16_t assisting_port(0);

		spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT16_S, &assisting_port);

		if (is_assisting != get_current_network_instance().joinable) {
			mCurrentNetworkInstance.joinable = is_assisting;
			signal_property_changed(kWPANTUNDProperty_NestLabs_NetworkAllowingJoin, is_assisting);
			if (is_assisting) {
				syslog(LOG_NOTICE, "Network is joinable, assisting on port %d", assisting_port);
			} else {
				syslog(LOG_NOTICE, "Network is no longer joinable");
			}
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
	}
	process_event(EVENT_NCP_PROP_VALUE_IS, key, value_data_ptr, value_data_len);
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

			if (addr != NULL
				&& buffer_is_nonzero(addr->s6_addr, 8)
				&& !IN6_IS_ADDR_UNSPECIFIED(addr)
			) {
				static const uint8_t rloc_bytes[] = {0x00,0x00,0x00,0xFF,0xFE,0x00};
				if (IN6_IS_ADDR_LINKLOCAL(addr)) {
					if (0 != memcmp(rloc_bytes, addr->s6_addr+8, sizeof(rloc_bytes))) {
						handle_ncp_spinel_value_is(SPINEL_PROP_IPV6_LL_ADDR, addr->s6_addr, sizeof(*addr));
					}
				} else if (0 == memcmp(mNCPV6Prefix, addr, sizeof(mNCPV6Prefix))) {
					if (0 != memcmp(rloc_bytes, addr->s6_addr+8, sizeof(rloc_bytes))) {
						handle_ncp_spinel_value_is(SPINEL_PROP_IPV6_ML_ADDR, addr->s6_addr, sizeof(*addr));
					}
				} else {
					update_global_address(*addr, valid_lifetime, preferred_lifetime, 0);
				}
			}
	}


	process_event(EVENT_NCP_PROP_VALUE_INSERTED, key, value_data_ptr, value_data_len);
}

void
SpinelNCPInstance::handle_ncp_state_change(NCPState new_ncp_state, NCPState old_ncp_state)
{
	NCPInstanceBase::handle_ncp_state_change(new_ncp_state, old_ncp_state);

	if (ncp_state_is_associated(new_ncp_state)
	 && !ncp_state_is_associated(old_ncp_state)
	) {
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				NilReturn(),
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ML_ADDR)
			)
		));
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				NilReturn(),
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_NET_XPANID)
			)
		));
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				NilReturn(),
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_15_4_PANID)
			)
		));
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				NilReturn(),
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_MAC_15_4_LADDR)
			)
		));
		start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				this,
				NilReturn(),
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_PHY_CHAN)
			)
		));
	} else if (ncp_state_is_joining(new_ncp_state)
	 && !ncp_state_is_joining(old_ncp_state)
	) {
		if (!buffer_is_nonzero(mNCPV6Prefix, 8)) {
			start_new_task(boost::shared_ptr<SpinelNCPTask>(
				new SpinelNCPTaskSendCommand(
					this,
					NilReturn(),
					SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_IPV6_ML_PREFIX)
				)
			));
		}
	}
}

void
SpinelNCPInstance::handle_ncp_spinel_value_removed(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len)
{
	process_event(EVENT_NCP_PROP_VALUE_REMOVED, key, value_data_ptr, value_data_len);
}

void
SpinelNCPInstance::handle_ncp_spinel_callback(unsigned int command, const uint8_t* cmd_data_ptr, spinel_size_t cmd_data_len)
{
	switch (command) {
	case SPINEL_CMD_PROP_VALUE_IS:
		{
			spinel_prop_key_t key;
			uint8_t* value_data_ptr = NULL;
			spinel_size_t value_data_len = 0;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len);

			__ASSERT_MACROS_check(ret != -1);

			if (ret == -1) {
				return;
			}

			syslog(LOG_INFO, "[NCP->] CMD_PROP_VALUE_IS(%s)", spinel_prop_key_to_cstr(key));

			return handle_ncp_spinel_value_is(key, value_data_ptr, value_data_len);
		}
		break;

	case SPINEL_CMD_PROP_VALUE_INSERTED:
		{
			spinel_prop_key_t key;
			uint8_t* value_data_ptr;
			spinel_size_t value_data_len;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len);

			__ASSERT_MACROS_check(ret != -1);

			if (ret == -1) {
				return;
			}

			syslog(LOG_INFO, "[NCP->] CMD_PROP_VALUE_INSERTED(%s)", spinel_prop_key_to_cstr(key));

			return handle_ncp_spinel_value_inserted(key, value_data_ptr, value_data_len);
		}
		break;

	case SPINEL_CMD_PROP_VALUE_REMOVED:
		{
			spinel_prop_key_t key;
			uint8_t* value_data_ptr;
			spinel_size_t value_data_len;
			spinel_ssize_t ret;

			ret = spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len);

			__ASSERT_MACROS_check(ret != -1);

			if (ret == -1) {
				return;
			}

			syslog(LOG_INFO, "[NCP->] CMD_PROP_VALUE_REMOVED(%s)", spinel_prop_key_to_cstr(key));

			return handle_ncp_spinel_value_removed(key, value_data_ptr, value_data_len);
		}
		break;

	default:
		break;
	}

	process_event(EVENT_NCP(command), cmd_data_ptr[0], cmd_data_ptr, cmd_data_len);
}
