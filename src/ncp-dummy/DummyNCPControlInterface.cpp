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
DummyNCPControlInterface::add_on_mesh_prefix(
	const struct in6_addr& prefix,
	uint8_t prefix_len,
	OnMeshPrefixFlags flags,
	OnMeshPrefixPriority priority,
	bool stable,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::remove_on_mesh_prefix(
	const struct in6_addr& prefix,
	uint8_t prefix_len,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::add_external_route(
	const struct in6_addr *prefix,
	int prefix_len_in_bits,
	int domain_id,
	ExternalRoutePriority priority,
	bool stable,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::remove_external_route(
	const struct in6_addr *prefix,
	int prefix_len_in_bits,
	int domain_id,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::add_service(
	uint32_t enterprise_number,
	const Data &service_data,
	bool stable,
	const Data &server_data,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::remove_service(
	uint32_t enterprise_number,
	const Data &service_data,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::joiner_attach(
	const ValueMap &options,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::joiner_commissioning(
	bool action,
	const ValueMap &options,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::commissioner_add_joiner(
	const JoinerInfo &joiner,
	uint32_t timeout,
	const char *psk,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::commissioner_remove_joiner(
	const JoinerInfo &joiner,
	uint32_t timeout,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::commissioner_send_announce_begin(
	uint32_t channel_mask,
	uint8_t count,
	uint16_t period,         // in milliseconds
	const struct in6_addr& dest,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::commissioner_send_energy_scan_query(
	uint32_t channel_mask,
	uint8_t count,
	uint16_t period,         // in milliseconds
	uint16_t scan_duration,  // in milliseconds
	const struct in6_addr& dest,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::commissioner_send_pan_id_query(
	uint16_t pan_id,
	uint32_t channel_mask,
	const struct in6_addr& dest,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::commissioner_generate_pskc(
	const char *pass_phrase,
	const char *network_name,
	const XPANId &xpanid,
	CallbackWithStatusArg1 cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented, std::string("generating PSKc is not supported"));
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
DummyNCPControlInterface::mfg(
	const std::string& mfg_command,
	CallbackWithStatusArg1 cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented, 0); // TODO: Start mfg run
}

void
DummyNCPControlInterface::netscan_stop(CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented); // TODO: Start network scan
}

void
DummyNCPControlInterface::energyscan_start(
	const ValueMap& options,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::energyscan_stop(CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented);
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

void
DummyNCPControlInterface::pcap_to_fd(int fd, CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::pcap_terminate(CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}


// ----------------------------------------------------------------------------
// MARK: -

void
DummyNCPControlInterface::property_get_value(
	const std::string& in_key,
	CallbackWithStatusArg1 cb
) {
	if (!mNCPInstance->is_initializing_ncp()) {
		syslog(LOG_INFO, "property_get_value: key: \"%s\"", in_key.c_str());
	}
	mNCPInstance->property_get_value(in_key, cb);
}

void
DummyNCPControlInterface::property_set_value(
	const std::string& key,
	const boost::any& value,
	CallbackWithStatus cb
) {
	syslog(LOG_INFO, "property_set_value: key: \"%s\"", key.c_str());
	mNCPInstance->property_set_value(key, value, cb);
}

void
DummyNCPControlInterface::property_insert_value(
	const std::string& key,
	const boost::any& value,
	CallbackWithStatus cb
) {
	syslog(LOG_INFO, "property_insert_value: key: \"%s\"", key.c_str());
	mNCPInstance->property_insert_value(key, value, cb);
}

void
DummyNCPControlInterface::property_remove_value(
	const std::string& key,
	const boost::any& value,
	CallbackWithStatus cb
) {
	syslog(LOG_INFO, "property_remove_value: key: \"%s\"", key.c_str());
	mNCPInstance->property_remove_value(key, value, cb);
}

void
DummyNCPControlInterface::link_metrics_query(
	const struct in6_addr &address,
	uint8_t seriesId,
	const uint8_t metrics,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::link_metrics_probe(
	const struct in6_addr &address,
	uint8_t seriesId,
	uint8_t length,
	CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::link_metrics_mgmt_forward(
		const struct in6_addr &address,
		uint8_t seriesId,
		const uint8_t frame_types,
		const uint8_t metrics,
		CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::link_metrics_mgmt_enh_ack(
		const struct in6_addr &address,
		uint8_t seriesId,
		const uint8_t metrics,
		CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::mlr_request(
		const std::vector<struct in6_addr> &addresses,
		bool mlr_timeout_present,
		uint32_t mlr_timeout,
		CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::backbone_router_config(
		const uint16_t delay,
		const uint32_t timeout,
		const uint8_t seqno,
		CallbackWithStatus cb
) {
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}

void
DummyNCPControlInterface::peek(uint32_t address, uint16_t count, CallbackWithStatusArg1 cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented, std::string("No peeking!"));
}

void
DummyNCPControlInterface::poke(uint32_t address, Data bytes, CallbackWithStatus cb)
{
	cb(kWPANTUNDStatus_FeatureNotImplemented);
}
