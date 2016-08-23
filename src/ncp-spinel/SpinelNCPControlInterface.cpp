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

#include "SpinelNCPControlInterface.h"
#include "SpinelNCPInstance.h"

#include "wpantund.h"
#include "config-file.h"
#include "nlpt.h"
#include "string-utils.h"
#include "any-to.h"
#include "time-utils.h"

#include <cstring>
#include <algorithm>
#include <errno.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/time.h>

#include <boost/bind.hpp>

#include "spinel-extra.h"

#include "SpinelNCPTask.h"
#include "SpinelNCPTaskWake.h"
#include "SpinelNCPTaskJoin.h"
#include "SpinelNCPTaskForm.h"
#include "SpinelNCPTaskLeave.h"
#include "SpinelNCPTaskScan.h"
#include "SpinelNCPTaskChangeNetData.h"
#include "SpinelNCPTaskSendCommand.h"

using namespace nl;
using namespace nl::wpantund;

// ----------------------------------------------------------------------------
// MARK: -

SpinelNCPControlInterface::SpinelNCPControlInterface(SpinelNCPInstance* instance_pointer)
	:mNCPInstance(instance_pointer)
{
}

// ----------------------------------------------------------------------------
// MARK: -

void
SpinelNCPControlInterface::join(
	const ValueMap& options,
    CallbackWithStatus cb
) {
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskJoin(
			mNCPInstance,
			boost::bind(cb,_1),
			options
		)
	));
}

void
SpinelNCPControlInterface::form(
	const ValueMap& options,
    CallbackWithStatus cb
) {
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskForm(
			mNCPInstance,
			boost::bind(cb,_1),
			options
		)
	));
}

void
SpinelNCPControlInterface::leave(CallbackWithStatus cb)
{
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskLeave(
			mNCPInstance,
			boost::bind(cb,_1)
		)
	));
}

void
SpinelNCPControlInterface::attach(CallbackWithStatus cb)
{
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskSendCommand(
			mNCPInstance,
			NilReturn(),
			SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S), SPINEL_PROP_NET_IF_UP, true)
		)
	));
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskSendCommand(
			mNCPInstance,
			boost::bind(cb,_1),
			SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_BOOL_S), SPINEL_PROP_NET_STACK_UP, true)
		)
	));
}

void
SpinelNCPControlInterface::reset(CallbackWithStatus cb)
{
	if (mNCPInstance->get_ncp_state() == FAULT) {
		mNCPInstance->change_ncp_state(UNINITIALIZED);
	}
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskSendCommand(
			mNCPInstance,
			boost::bind(cb,kWPANTUNDStatus_Ok),
			SpinelPackData(SPINEL_FRAME_PACK_CMD_RESET)
		)
	));
}

void
SpinelNCPControlInterface::begin_net_wake(uint8_t data, uint32_t flags, CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
SpinelNCPControlInterface::host_did_wake(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
SpinelNCPControlInterface::begin_low_power(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
SpinelNCPControlInterface::refresh_state(CallbackWithStatus cb)
{
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskSendCommand(
			mNCPInstance,
			boost::bind(cb,_1),
			SpinelPackData(SPINEL_FRAME_PACK_CMD_NOOP)
		)
	));
}

void
SpinelNCPControlInterface::data_poll(CallbackWithStatus cb)
{
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskSendCommand(
			mNCPInstance,
			boost::bind(cb,_1),
			SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_GET, SPINEL_PROP_STREAM_NET)
		)
	));
}

void
SpinelNCPControlInterface::config_gateway(bool defaultRoute, const uint8_t prefix[8], uint32_t preferredLifetime, uint32_t validLifetime, CallbackWithStatus cb)
{
    const static int kPreferredFlag = 1 << 5;
    const static int kSlaacFlag = 1 << 4;
    const static int kDhcpFlag = 1 << 3; (void)kDhcpFlag;
    const static int kConfigureFlag = 1 << 2; (void)kConfigureFlag;
    const static int kDefaultRouteFlag = 1 << 1;
    const static int kOnMeshFlag = 1 << 0;

	struct in6_addr addr = {};
	uint8_t flags = 0;

	if (!prefix) {
		cb(kWPANTUNDStatus_InvalidArgument);
		return;
	}

	if (!mNCPInstance->mEnabled) {
		cb(kWPANTUNDStatus_InvalidWhenDisabled);
		return;
	}

	if (defaultRoute) {
		flags |= kDefaultRouteFlag;
	}

	flags |= kPreferredFlag | kSlaacFlag | kOnMeshFlag;

	memcpy(addr.s6_addr, prefix, 8);

	memcpy(addr.s6_addr + 8, mNCPInstance->mMACAddress, 8);
	addr.s6_addr[8] ^= 0x02; // flip the private-use bit on the hardware address.

	if (validLifetime == 0) {
		mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskChangeNetData(
				mNCPInstance,
				boost::bind(cb,_1),
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(
						SPINEL_DATATYPE_IPv6ADDR_S
						SPINEL_DATATYPE_UINT8_S
						SPINEL_DATATYPE_BOOL_S
						SPINEL_DATATYPE_UINT8_S
					),
					SPINEL_PROP_THREAD_ON_MESH_NETS,
					&addr,
					64,
					false,
					flags
				)
			)
		));
	} else {
		mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskChangeNetData(
				mNCPInstance,
				boost::bind(cb,_1),
				SpinelPackData(
					SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(
						SPINEL_DATATYPE_IPv6ADDR_S
						SPINEL_DATATYPE_UINT8_S
						SPINEL_DATATYPE_BOOL_S
						SPINEL_DATATYPE_UINT8_S
					),
					SPINEL_PROP_THREAD_ON_MESH_NETS,
					&addr,
					64,
					false,
					flags
				)
			)
		));
	}
}

void
SpinelNCPControlInterface::add_external_route(const uint8_t *route, int route_prefix_len, int domain_id,
	ExternalRoutePriority priority, CallbackWithStatus cb)
{
    const static int kPreferenceOffset = 6;
	struct in6_addr addr = {};
	uint8_t flags = 0;

	switch (priority) {
	case ROUTE_HIGH_PREFERENCE:
		flags = (1 << kPreferenceOffset);
		break;

	case ROUTE_MEDIUM_PREFERENCE:
		flags = 0;
		break;

	case ROUTE_LOW_PREFRENCE:
		flags = (3 << kPreferenceOffset);
		break;
	}

	memcpy(addr.s6_addr, route, route_prefix_len);

	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskChangeNetData(
			mNCPInstance,
			boost::bind(cb,_1),
			SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_INSERT(
					SPINEL_DATATYPE_IPv6ADDR_S
					SPINEL_DATATYPE_UINT8_S
					SPINEL_DATATYPE_BOOL_S
					SPINEL_DATATYPE_UINT8_S
				),
				SPINEL_PROP_THREAD_LOCAL_ROUTES,
				&addr,
				route_prefix_len*8, // because route_prefix_len is in bytes
				false,
				flags
			)
		)
	));
}

void
SpinelNCPControlInterface::remove_external_route(const uint8_t *route, int route_prefix_len, int domain_id, CallbackWithStatus cb)
{
	struct in6_addr addr = {};

	if (route_prefix_len > sizeof(addr)) {
		cb(kWPANTUNDStatus_InvalidArgument);
		return;
	}

	memcpy(addr.s6_addr, route, route_prefix_len);

	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskChangeNetData(
			mNCPInstance,
			boost::bind(cb,_1),
			SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_REMOVE(
					SPINEL_DATATYPE_IPv6ADDR_S
					SPINEL_DATATYPE_UINT8_S
					SPINEL_DATATYPE_BOOL_S
					SPINEL_DATATYPE_UINT8_S
				),
				SPINEL_PROP_THREAD_LOCAL_ROUTES,
				&addr,
				route_prefix_len*8, // because route_prefix_len is in bytes
				false,
				0
			)
		)
	));
}

void
SpinelNCPControlInterface::permit_join(
    int seconds,
    uint8_t traffic_type,
    in_port_t traffic_port,
    bool network_wide,
    CallbackWithStatus cb
    )
{
	int ret = kWPANTUNDStatus_Ok;

	if (!mNCPInstance->mEnabled) {
		ret = kWPANTUNDStatus_InvalidWhenDisabled;
		goto bail;
	}

	if (traffic_port == 0) {
		// If no port was explicitly set, default to the discovered
		// "Commissioner Port"  (“:MC”).
		traffic_port = htons(mNCPInstance->mCommissionerPort);
	}

	ret = mNCPInstance->set_commissioniner(seconds, traffic_type, traffic_port);

	require_noerr(ret, bail);

	if (seconds > 0) {
		mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				mNCPInstance,
				boost::bind(cb,_1),
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UINT16_S), SPINEL_PROP_THREAD_ASSISTING_PORTS, ntohs(traffic_port))
			)
		));
	} else {
		mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
			new SpinelNCPTaskSendCommand(
				mNCPInstance,
				boost::bind(cb,_1),
				SpinelPackData(SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_VOID_S), SPINEL_PROP_THREAD_ASSISTING_PORTS)
			)
		));
	}

bail:
	if (ret) {
		cb(ret);
	} else {
		syslog(LOG_NOTICE, "PermitJoin: seconds=%d type=%d port=%d", seconds, traffic_type, ntohs(traffic_port));
	}
}

void
SpinelNCPControlInterface::netscan_start(
    const ValueMap& options,
    CallbackWithStatus cb
) {
	ChannelMask channel_mask(mNCPInstance->mDefaultChannelMask);

	if (options.count(kWPANTUNDProperty_NCPChannelMask)) {
		channel_mask = any_to_int(options.at(kWPANTUNDProperty_NCPChannelMask));
	}

	if (-1 == mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskScan(
			mNCPInstance,
			boost::bind(cb,_1),
			channel_mask
		)
	))) {
		cb(kWPANTUNDStatus_InvalidForCurrentState);
	}
}

void
SpinelNCPControlInterface::netscan_stop(CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Start network scan
}

void
SpinelNCPControlInterface::energyscan_start(
    const ValueMap& options,
    CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
SpinelNCPControlInterface::energyscan_stop(CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

std::string
SpinelNCPControlInterface::get_name() {
	return mNCPInstance->get_name();
}

void
SpinelNCPControlInterface::mfg(
    const std::string& mfg_command,
    CallbackWithStatusArg1 cb
) {
	mNCPInstance->start_new_task(boost::shared_ptr<SpinelNCPTask>(
		new SpinelNCPTaskSendCommand(
			mNCPInstance,
			cb,
			SpinelPackData(
				SPINEL_FRAME_PACK_CMD_PROP_VALUE_SET(SPINEL_DATATYPE_UTF8_S),
				SPINEL_PROP_NEST_STREAM_MFG,
				mfg_command.c_str()
			),
			NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
			SPINEL_DATATYPE_UTF8_S
		)
	));
}

const WPAN::NetworkInstance&
SpinelNCPControlInterface::get_current_network_instance()const
{
	return mNCPInstance->get_current_network_instance();
}


NCPInstance&
SpinelNCPControlInterface::get_ncp_instance()
{
	return (*mNCPInstance);
}


// ----------------------------------------------------------------------------
// MARK: -

void
SpinelNCPControlInterface::get_property(
    const std::string& in_key, CallbackWithStatusArg1 cb
    )
{
	if (!mNCPInstance->is_initializing_ncp()) {
		syslog(LOG_INFO, "get_property: key: \"%s\"", in_key.c_str());
	}
	mNCPInstance->get_property(in_key, cb);
}

void
SpinelNCPControlInterface::set_property(
    const std::string&                      key,
    const boost::any&                       value,
    CallbackWithStatus      cb
    )
{
	syslog(LOG_INFO, "set_property: key: \"%s\"", key.c_str());
	mNCPInstance->set_property(key, value, cb);
}
