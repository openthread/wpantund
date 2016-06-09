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

#include "DummyNCPControlInterface.h"
#include "DummyNCPInstance.h"

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

using namespace nl;
using namespace nl::wpantund;

// ----------------------------------------------------------------------------
// MARK: -

DummyNCPControlInterface::DummyNCPControlInterface(DummyNCPInstance* instance_pointer)
	:mNCPInstance(instance_pointer)
{
}

// ----------------------------------------------------------------------------
// MARK: -

void
DummyNCPControlInterface::join(
	const ValueMap& options,
    CallbackWithStatus cb
) {
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::form(
	const ValueMap& options,
    CallbackWithStatus cb
) {

	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::leave(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::attach(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::reset(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::begin_net_wake(uint8_t data, uint32_t flags, CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::host_did_wake(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::begin_low_power(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::refresh_state(CallbackWithStatus cb)
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::data_poll(CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Send data poll command
}

void
DummyNCPControlInterface::config_gateway(bool defaultRoute, const uint8_t prefix[8], uint32_t preferredLifetime, uint32_t validLifetime, CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Send config gateway command
}

void
DummyNCPControlInterface::add_external_route(const uint8_t *route, int route_prefix_len, int domain_id,
	ExternalRoutePriority priority, CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Send add external route command
}

void
DummyNCPControlInterface::remove_external_route(const uint8_t *route, int route_prefix_len, int domain_id, CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Send remove external route command
}

void
DummyNCPControlInterface::permit_join(
    int seconds,
    uint8_t traffic_type,
    in_port_t traffic_port,
    bool network_wide,
    CallbackWithStatus cb
    )
{
	// TODO: Writeme!
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::netscan_start(
    const ValueMap& options,
    CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Start network scan
}

void
DummyNCPControlInterface::netscan_stop(CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Start network scan
}

std::string
DummyNCPControlInterface::get_name() {
	return mNCPInstance->get_name();
}

const WPAN::NetworkInstance&
DummyNCPControlInterface::get_current_network_instance()const
{
	return mNCPInstance->get_current_network_instance();
}


NCPInstance&
DummyNCPControlInterface::get_ncp_instance()
{
	return (*mNCPInstance);
}


// ----------------------------------------------------------------------------
// MARK: -

void
DummyNCPControlInterface::get_property(
    const std::string& in_key, CallbackWithStatusArg1 cb
    )
{
	syslog(LOG_INFO, "get_property: key: \"%s\"", in_key.c_str());
	mNCPInstance->get_property(in_key, cb);
}

void
DummyNCPControlInterface::set_property(
    const std::string&                      key,
    const boost::any&                       value,
    CallbackWithStatus      cb
    )
{
	syslog(LOG_INFO, "set_property: key: \"%s\"", key.c_str());
	mNCPInstance->set_property(key, value, cb);

}
