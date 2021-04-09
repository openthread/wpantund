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

#ifndef __WPAN_DUMMY_NCP_H__
#define __WPAN_DUMMY_NCP_H__ 1

#include "NCPInstance.h"
#include "NCPControlInterface.h"
#include "nlpt.h"
#include "Callbacks.h"
#include "EventHandler.h"

#include <queue>
#include <set>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

namespace nl {
namespace wpantund {

class DummyNCPInstance;

class DummyNCPControlInterface : public NCPControlInterface {
public:
	friend class DummyNCPInstance;

	DummyNCPControlInterface(DummyNCPInstance* instance_pointer);
	virtual ~DummyNCPControlInterface() { }

	virtual const WPAN::NetworkInstance& get_current_network_instance(void)const;

	virtual void join(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void form(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void leave(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void attach(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void begin_low_power(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void netscan_start(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void netscan_stop(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void energyscan_start(
		const ValueMap& options,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void energyscan_stop(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void begin_net_wake(
		uint8_t data,
		uint32_t flags,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void reset(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void permit_join(
		int seconds = 15 * 60,
		uint8_t commissioning_traffic_type = 0xFF,
		in_port_t commissioning_traffic_port = 0,
		bool network_wide = false,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void refresh_state(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void property_get_value(
		const std::string& key,
		CallbackWithStatusArg1 cb
	);

	virtual void property_set_value(
		const std::string& key,
		const boost::any& value,
		CallbackWithStatus cb
	);

	virtual void property_insert_value(
		const std::string& key,
		const boost::any& value,
		CallbackWithStatus cb
	);

	virtual void property_remove_value(
		const std::string& key,
		const boost::any& value,
		CallbackWithStatus cb
	);

	virtual void add_on_mesh_prefix(
		const struct in6_addr& prefix,
		uint8_t prefix_len,
		OnMeshPrefixFlags flags,
		OnMeshPrefixPriority priority,
		bool stable,
		CallbackWithStatus cb
	);

	virtual void remove_on_mesh_prefix(
		const struct in6_addr& prefix,
		uint8_t prefix_len,
		CallbackWithStatus cb
	);

	virtual void add_external_route(
		const struct in6_addr *prefix,
		int prefix_len_in_bits,
		int domain_id,
		ExternalRoutePriority priority,
		bool stable,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void remove_external_route(
		const struct in6_addr *prefix,
		int prefix_len_in_bits,
		int domain_id,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void add_service(
		uint32_t enterprise_number,
		const Data &service_data,
		bool stable,
		const Data &server_data,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void remove_service(
		uint32_t enterprise_number,
		const Data &service_data,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void joiner_attach(
		const ValueMap &options,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void joiner_commissioning(
		bool action,
		const ValueMap &options,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void commissioner_add_joiner(
		const JoinerInfo &joiner,
		uint32_t timeout,
		const char *psk,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void commissioner_remove_joiner(
		const JoinerInfo &joiner,
		uint32_t timeout,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void commissioner_send_announce_begin(
		uint32_t channel_mask,
		uint8_t count,
		uint16_t period,         // in milliseconds
		const struct in6_addr& dest,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void commissioner_send_energy_scan_query(
		uint32_t channel_mask,
		uint8_t count,
		uint16_t period,         // in milliseconds
		uint16_t scan_duration,  // in milliseconds
		const struct in6_addr& dest,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void commissioner_send_pan_id_query(
		uint16_t pan_id,
		uint32_t channel_mask,
		const struct in6_addr& dest,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void commissioner_generate_pskc(
		const char *pass_phrase,
		const char *network_name,
		const XPANId &xpanid,
		CallbackWithStatusArg1 cb = NilReturn()
	);

	virtual void data_poll(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void host_did_wake(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void peek(uint32_t address, uint16_t count,	CallbackWithStatusArg1 cb = NilReturn());
	virtual void poke(uint32_t address, Data bytes,	CallbackWithStatus cb = NilReturn());

	virtual std::string get_name(void);

	virtual NCPInstance& get_ncp_instance(void);

	virtual void link_metrics_query(
		const struct in6_addr &address,
		uint8_t seriesId,
		const uint8_t metrics,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void link_metrics_probe(
		const struct in6_addr &address,
		uint8_t seriesId,
		uint8_t length,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void link_metrics_mgmt_forward(
		const struct in6_addr &address,
		uint8_t seriesId,
		const uint8_t frame_types,
		const uint8_t metrics,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void link_metrics_mgmt_enh_ack(
		const struct in6_addr &address,
		uint8_t flags,
		const uint8_t metrics,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void mlr_request(
		const std::vector<struct in6_addr> &addresses,
		bool mlr_timeout_present,
		uint32_t mlr_timeout,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void backbone_router_config(
		const uint16_t delay,
		const uint32_t timeout,
		const uint8_t seqno,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void pcap_to_fd(int fd,
		CallbackWithStatus cb = NilReturn()
	);

	virtual void pcap_terminate(
		CallbackWithStatus cb = NilReturn()
	);

	virtual void mfg(
		const std::string& mfg_command,
		CallbackWithStatusArg1 cb = NilReturn()
	);

private:

	DummyNCPInstance* mNCPInstance;

};

}; // namespace wpantund
}; // namespace nl


#endif
