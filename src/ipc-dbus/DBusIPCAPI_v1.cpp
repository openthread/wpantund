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

#include <stdio.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <algorithm>

#include <boost/bind.hpp>

#include <dbus/dbus.h>
#include <syslog.h>

#include "wpan-dbus-v1.h"
#include "DBusIPCAPI_v1.h"
#include "wpan-error.h"

#include "NCPControlInterface.h"
#include "NCPMfgInterface_v1.h"
#include "assert-macros.h"

#include "DBUSHelpers.h"
#include "any-to.h"

using namespace DBUSHelpers;
using namespace nl;
using namespace nl::wpantund;

DBusIPCAPI_v1::DBusIPCAPI_v1(DBusConnection *connection)
	:mConnection(connection)
{
	dbus_connection_ref(mConnection);
	init_callback_tables();
}

DBusIPCAPI_v1::~DBusIPCAPI_v1()
{
	dbus_connection_unref(mConnection);
}

void
DBusIPCAPI_v1::init_callback_tables()
{
#define INTERFACE_CALLBACK_CONNECT(cmd_name, member_func) \
	mInterfaceCallbackTable[(cmd_name)] = boost::bind( \
		&DBusIPCAPI_v1::member_func, this, _1, _2)

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_RESET, interface_reset_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_STATUS, interface_status_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_JOIN, interface_join_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_FORM, interface_form_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_LEAVE, interface_leave_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_ATTACH, interface_attach_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_ROUTE_ADD, interface_route_add_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_ROUTE_REMOVE, interface_route_remove_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_SERVICE_ADD, service_add_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_SERVICE_REMOVE, service_remove_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_DATA_POLL, interface_data_poll_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_CONFIG_GATEWAY, interface_config_gateway_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_BEGIN_LOW_POWER, interface_begin_low_power_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_HOST_DID_WAKE, interface_host_did_wake_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_NET_SCAN_STOP, interface_net_scan_stop_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_NET_SCAN_START, interface_net_scan_start_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_DISCOVER_SCAN_STOP, interface_discover_scan_stop_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_DISCOVER_SCAN_START, interface_discover_scan_start_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_ENERGY_SCAN_STOP, interface_energy_scan_stop_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_ENERGY_SCAN_START, interface_energy_scan_start_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_MFG, interface_mfg_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PROP_GET, interface_prop_get_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PROP_SET, interface_prop_set_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PROP_INSERT, interface_prop_insert_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PROP_REMOVE, interface_prop_remove_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PCAP_TO_FD, interface_pcap_to_fd_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PCAP_TERMINATE, interface_pcap_terminate_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_JOINER_ATTACH, interface_joiner_attach_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_JOINER_START, interface_joiner_start_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_JOINER_STOP, interface_joiner_stop_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_JOINER_COMMISSIONING, interface_joiner_commissioning_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_JOINER_ADD, interface_joiner_add_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_JOINER_REMOVE, interface_joiner_remove_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_ANNOUNCE_BEGIN, interface_announce_begin_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_ENERGY_SCAN_QUERY, interface_energy_scan_query_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PAN_ID_QUERY, interface_pan_id_query_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_GENERATE_PSKC, interface_generate_pskc);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_PEEK, interface_peek_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_POKE, interface_poke_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_LINK_METRICS_QUERY, interface_link_metrics_query_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_LINK_METRICS_PROBE, interface_link_metrics_probe_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_LINK_METRICS_MGMT_FORWARD, interface_link_metrics_mgmt_forward_handler);
	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_LINK_METRICS_MGMT_ENH_ACK, interface_link_metrics_mgmt_enh_ack_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_MLR_REQUEST, interface_mlr_request_handler);

	INTERFACE_CALLBACK_CONNECT(WPANTUND_IF_CMD_BACKBONE_ROUTER_CONFIG, interface_backbone_router_config_handler);
}

static void
ObjectPathUnregisterFunction_cb(DBusConnection *connection, void *user_data)
{
	delete (std::pair<NCPControlInterface*, DBusIPCAPI_v1*> *)user_data;
}

std::string
DBusIPCAPI_v1::path_for_iface(NCPControlInterface* interface)
{
	return std::string(WPANTUND_DBUS_PATH) + "/" + interface->get_name();
}

int
DBusIPCAPI_v1::add_interface(NCPControlInterface* interface)
{
	static const DBusObjectPathVTable ipc_interface_vtable = {
		&ObjectPathUnregisterFunction_cb,
		&DBusIPCAPI_v1::dbus_message_handler,
	};

	std::string name = interface->get_name();
	std::string path = std::string(WPANTUND_DBUS_PATH) + "/" + name;

	std::pair<NCPControlInterface*, DBusIPCAPI_v1*> *cb_data =
	    new std::pair<NCPControlInterface*, DBusIPCAPI_v1*>(interface, this);

	require(dbus_connection_register_object_path(
	            mConnection,
	            path.c_str(),
	            &ipc_interface_vtable,
	            (void*)cb_data
	            ), bail);

	interface->mOnPropertyChanged.connect(
	    boost::bind(
			&DBusIPCAPI_v1::property_changed,
			this,
			interface,
			_1,
			_2
		)
	);

	interface->mOnNetScanBeacon.connect(
	    boost::bind(
			&DBusIPCAPI_v1::received_beacon,
			this,
			interface,
			_1
		)
	);

	interface->mOnEnergyScanResult.connect(
		boost::bind(
			&DBusIPCAPI_v1::received_energy_scan_result,
			this,
			interface,
			_1
		)
	);

	interface->mOnNetworkTimeUpdate.connect(
		boost::bind(
			&DBusIPCAPI_v1::received_network_time_update,
			this,
			interface,
			_1
		)
	);

bail:
	return 0;
}

void
DBusIPCAPI_v1::CallbackWithStatus_Helper(int ret, DBusMessage *original_message)
{
	DBusMessage *reply = dbus_message_new_method_return(original_message);

	syslog(LOG_DEBUG, "Sending DBus response for \"%s\" to \"%s\"", dbus_message_get_member(original_message), dbus_message_get_sender(original_message));

	if(reply) {
		dbus_message_append_args(
			reply,
			DBUS_TYPE_INT32, &ret,
			DBUS_TYPE_INVALID
		);

		dbus_connection_send(mConnection, reply, NULL);
		dbus_message_unref(reply);
	}
	dbus_message_unref(original_message);
}

static void
ipc_append_network_properties(
    DBusMessageIter *iter, const WPAN::NetworkInstance& network
    )
{
	const char* network_name = network.name.c_str();

	if (network_name[0]) {
		append_dict_entry(
			iter,
			kWPANTUNDProperty_NetworkName,
			DBUS_TYPE_STRING,
			&network_name
		);
	}

	if (network.get_xpanid_as_uint64() != 0) {
		uint64_t xpan_id = network.get_xpanid_as_uint64();
		append_dict_entry(
			iter,
			kWPANTUNDProperty_NetworkXPANID,
			DBUS_TYPE_UINT64,
			&xpan_id
		);
	}

	{
		uint16_t pan_id = network.panid;
		append_dict_entry(
			iter,
			kWPANTUNDProperty_NetworkPANID,
			DBUS_TYPE_UINT16,
			&pan_id
		);
	}

	if (network.type != 0) {
		int32_t type = network.type;
		append_dict_entry(
			iter,
			kWPANTUNDProperty_NetworkNodeType,
			DBUS_TYPE_INT32,
			&type
		);
	}

	if (network.channel) {
		uint16_t channel = network.channel;
		append_dict_entry(
			iter,
			kWPANTUNDProperty_NCPChannel,
			DBUS_TYPE_INT16,
			&channel
		);

		if (network.rssi != -128) {
			int8_t rssi = network.rssi;
			append_dict_entry(iter, "RSSI", DBUS_TYPE_BYTE, &rssi);
		}

		dbus_bool_t allowing_join = network.joinable;
		append_dict_entry(
			iter,
			kWPANTUNDProperty_NestLabs_NetworkAllowingJoin,
			DBUS_TYPE_BOOLEAN,
			&allowing_join
		);
	}

	if (network.get_hwaddr_as_uint64() != 0) {
		append_dict_entry(
			iter,
			kWPANTUNDProperty_NCPHardwareAddress,
			nl::Data(network.hwaddr, 8)
		);
	}
}

static void
ipc_append_network_dict(
    DBusMessageIter *iter, const WPAN::NetworkInstance& network
    )
{
	DBusMessageIter dict;

	dbus_message_iter_open_container(
	    iter,
	    DBUS_TYPE_ARRAY,
	    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_VARIANT_AS_STRING
	    DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
	    &dict
	    );
	ipc_append_network_properties(&dict, network);

	dbus_message_iter_close_container(iter, &dict);
}

void
DBusIPCAPI_v1::received_beacon(NCPControlInterface* interface, const WPAN::NetworkInstance& network)
{
	DBusMessageIter iter;
	DBusMessage* signal;

	signal = dbus_message_new_signal(
		path_for_iface(interface).c_str(),
		WPANTUND_DBUS_APIv1_INTERFACE,
		WPANTUND_IF_SIGNAL_NET_SCAN_BEACON
    );

	dbus_message_iter_init_append(signal, &iter);

	ipc_append_network_dict(&iter, network);

	dbus_connection_send(mConnection, signal, NULL);

	dbus_message_unref(signal);
}

void
DBusIPCAPI_v1::received_network_time_update(
	NCPControlInterface* interface, const ValueMap &network_time_update)
{
	DBusMessageIter iter;
	DBusMessage* signal;

	signal = dbus_message_new_signal(
		path_for_iface(interface).c_str(),
		WPANTUND_DBUS_APIv1_INTERFACE,
		WPANTUND_IF_SIGNAL_NETWORK_TIME_UPDATE
	);

	dbus_message_iter_init_append(signal, &iter);

	append_any_to_dbus_iter(&iter, network_time_update);

	dbus_connection_send(mConnection, signal, NULL);

	dbus_message_unref(signal);
}

static void
ipc_append_energy_scan_result_dict(
    DBusMessageIter *iter, const EnergyScanResultEntry& energy_scan_result
    )
{
	uint16_t channel = energy_scan_result.mChannel;
	int16_t maxRssi = static_cast<int16_t>(energy_scan_result.mMaxRssi);
	DBusMessageIter dict;

	dbus_message_iter_open_container(
	    iter,
	    DBUS_TYPE_ARRAY,
	    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_VARIANT_AS_STRING
	    DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
	    &dict
	    );

	append_dict_entry(&dict, kWPANTUNDProperty_NCPChannel, DBUS_TYPE_INT16, &channel);
	append_dict_entry(&dict, "RSSI", DBUS_TYPE_BYTE, &maxRssi);

	dbus_message_iter_close_container(iter, &dict);
}

void
DBusIPCAPI_v1::received_energy_scan_result(NCPControlInterface* interface,
                                          const EnergyScanResultEntry& energy_scan_result)
{
	DBusMessageIter iter;
	DBusMessage* signal;

	signal = dbus_message_new_signal(
		path_for_iface(interface).c_str(),
		WPANTUND_DBUS_APIv1_INTERFACE,
		WPANTUND_IF_SIGNAL_ENERGY_SCAN_RESULT
    );

	dbus_message_iter_init_append(signal, &iter);

	ipc_append_energy_scan_result_dict(&iter, energy_scan_result);

	dbus_connection_send(mConnection, signal, NULL);

	dbus_message_unref(signal);
}

void
DBusIPCAPI_v1::property_changed(NCPControlInterface* interface,const std::string& key, const boost::any& value)
{
	DBusMessageIter iter;
	DBusMessage* signal;
	std::string key_as_path;
	std::string path;

	// Transform the key into a DBus-compatible path
	for (std::string::const_iterator i = key.begin();
		i != key.end();
		++i
	) {
		const char c = *i;
		if (isalnum(c) || (c == '_')) {
			key_as_path += c;
		} else if (c == ':') {
			key_as_path += '/';
		} else if (c == '.') {
			key_as_path += '_';
		}
	}

	path = path_for_iface(interface) + "/Property/" + key_as_path;

	syslog(LOG_DEBUG, "DBusAPIv1:PropChanged: %s - value: %s", path.c_str(), any_to_string(value).c_str());

	signal = dbus_message_new_signal(
		path.c_str(),
		WPANTUND_DBUS_APIv1_INTERFACE,
		WPANTUND_IF_SIGNAL_PROP_CHANGED
    );

	if (signal) {
		dbus_message_iter_init_append(signal, &iter);

		append_any_to_dbus_iter(&iter, key);
		append_any_to_dbus_iter(&iter, value);

		dbus_connection_send(mConnection, signal, NULL);
		dbus_message_unref(signal);
	}
}

void
DBusIPCAPI_v1::status_response_helper(
    int ret, NCPControlInterface* interface, DBusMessage *message
    )
{
	DBusMessage *reply = dbus_message_new_method_return(message);

	if (reply) {
		DBusMessageIter iter;
		dbus_message_iter_init_append(reply, &iter);

		DBusMessageIter dict;
		boost::any value;
		NCPState ncp_state = UNINITIALIZED;
		std::string ncp_state_string;
		const char* ncp_state_cstr = kWPANTUNDStateUninitialized;

		dbus_message_iter_open_container(
			&iter,
			DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING
			DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
			&dict
		);

		value = interface->property_get_value(kWPANTUNDProperty_NCPState);

		if (!value.empty()) {
			ncp_state_string = any_to_string(value);
			ncp_state = string_to_ncp_state(ncp_state_string);
			ncp_state_cstr = ncp_state_string.c_str();
		}

		append_dict_entry(&dict,
						  kWPANTUNDProperty_NCPState,
						  DBUS_TYPE_STRING,
						  &ncp_state_cstr);

		value = interface->property_get_value(kWPANTUNDProperty_DaemonEnabled);
		if (!value.empty()) {
			append_dict_entry(&dict, kWPANTUNDProperty_DaemonEnabled, value);
		}

		value = interface->property_get_value(kWPANTUNDProperty_NCPVersion);
		if (!value.empty()) {
			append_dict_entry(&dict, kWPANTUNDProperty_NCPVersion, value);
		}

		value = interface->property_get_value(kWPANTUNDProperty_POSIXAppRCPVersionCached);
		if (!value.empty()) {
			append_dict_entry(&dict, kWPANTUNDProperty_POSIXAppRCPVersion, value);
		}

		value = interface->property_get_value(kWPANTUNDProperty_DaemonVersion);
		if (!value.empty()) {
			append_dict_entry(&dict, kWPANTUNDProperty_DaemonVersion, value);
		}

		value = interface->property_get_value(kWPANTUNDProperty_ConfigNCPDriverName);
		if (!value.empty()) {
			append_dict_entry(&dict, kWPANTUNDProperty_ConfigNCPDriverName, value);
		}

		value = interface->property_get_value(kWPANTUNDProperty_NCPHardwareAddress);
		if (!value.empty()) {
			append_dict_entry(&dict, kWPANTUNDProperty_NCPHardwareAddress, value);
		}

		if (ncp_state_is_commissioned(ncp_state))
		{
			value = interface->property_get_value(kWPANTUNDProperty_NCPChannel);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NCPChannel, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_NetworkNodeType);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NetworkNodeType, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_NetworkName);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NetworkName, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_NetworkXPANID);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NetworkXPANID, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_NetworkPANID);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NetworkPANID, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_IPv6LinkLocalAddress);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_IPv6LinkLocalAddress, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_IPv6MeshLocalAddress);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_IPv6MeshLocalAddress, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_IPv6MeshLocalPrefix);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_IPv6MeshLocalPrefix, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_NestLabs_LegacyMeshLocalAddress);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NestLabs_LegacyMeshLocalAddress, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NestLabs_LegacyMeshLocalPrefix, value);
			}

			value = interface->property_get_value(kWPANTUNDProperty_NestLabs_NetworkAllowingJoin);
			if (!value.empty()) {
				append_dict_entry(&dict, kWPANTUNDProperty_NestLabs_NetworkAllowingJoin, value);
			}
		}

		dbus_message_iter_close_container(&iter, &dict);

		dbus_connection_send(mConnection, reply, NULL);
		dbus_message_unref(reply);
	}
	dbus_message_unref(message);
}

void
DBusIPCAPI_v1::CallbackWithStatusArg1_Helper(
    int status, const boost::any& value, DBusMessage *message
)
{
	DBusMessage *reply = dbus_message_new_method_return(message);
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);

	if (!status && value.empty()) {
		status = kWPANTUNDStatus_PropertyEmpty;
	}

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &status);

	if (value.empty()) {
		append_any_to_dbus_iter(&iter, std::string("<empty>"));
	} else {
		append_any_to_dbus_iter(&iter, value);
	}

	dbus_connection_send(mConnection, reply, NULL);
	dbus_message_unref(message);
	dbus_message_unref(reply);
}


DBusHandlerResult
DBusIPCAPI_v1::interface_reset_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->reset(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
								 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_status_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	NCPState ncp_state = UNINITIALIZED;
	boost::any value(interface->property_get_value(kWPANTUNDProperty_NCPState));

	if (!value.empty()) {
		ncp_state = string_to_ncp_state(any_to_string(value));
	}

	if (ncp_state_is_sleeping(ncp_state)
	 || ncp_state_is_detached_from_ncp(ncp_state)
	 || (ncp_state == UNINITIALIZED)
	) {
		status_response_helper(0, interface, message);
	} else {
		interface->refresh_state(boost::bind(&DBusIPCAPI_v1::
										 status_response_helper, this, _1, interface, message));
	}
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_join_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	ValueMap options;
	DBusMessageIter iter;

	dbus_message_iter_init(message, &iter);

	options = value_map_from_dbus_iter(&iter);

	dbus_message_ref(message);

	interface->join(
		options,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_form_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	ValueMap options;
	DBusMessageIter iter;

	dbus_message_iter_init(message, &iter);

	options = value_map_from_dbus_iter(&iter);

	dbus_message_ref(message);

	interface->form(
		options,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_leave_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->leave(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
								 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_attach_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->attach(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
								  this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_begin_low_power_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->begin_low_power(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
								 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_host_did_wake_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->host_did_wake(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
								 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_net_scan_stop_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->netscan_stop(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
									 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_discover_scan_stop_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->netscan_stop(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
									 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_energy_scan_stop_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->energyscan_stop(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
									 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_mfg_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	NCPMfgInterface_v1* mfg_interface(dynamic_cast<NCPMfgInterface_v1*>(interface));

	const char *mfg_command_cstr = "";
	std::string mfg_command;

	dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_STRING, &mfg_command_cstr,
		DBUS_TYPE_INVALID
	);

	mfg_command = mfg_command_cstr;

	dbus_message_ref(message);

	mfg_interface->mfg(
		mfg_command,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatusArg1_Helper,
			this,
			_1,
			_2,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_prop_get_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	const char* property_key_cstr = "";
	std::string property_key;
	dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_STRING, &property_key_cstr,
		DBUS_TYPE_INVALID
		);

	property_key = property_key_cstr;

	if (interface->translate_deprecated_property(property_key)) {
		syslog(LOG_WARNING, "PropGet: Property \"%s\" is deprecated. Please use \"%s\" instead.", property_key_cstr, property_key.c_str());
	}

	dbus_message_ref(message);

	interface->property_get_value(
		property_key,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatusArg1_Helper,
			this,
			_1,
			_2,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_prop_set_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	DBusMessageIter iter;
	const char* property_key_cstr = "";
	std::string property_key;
	boost::any property_value;

	dbus_message_iter_init(message, &iter);

	require (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING, bail);

	dbus_message_iter_get_basic(&iter, &property_key_cstr);
	dbus_message_iter_next(&iter);

	property_value = any_from_dbus_iter(&iter);
	property_key = property_key_cstr;

	if (interface->translate_deprecated_property(property_key, property_value)) {
		syslog(LOG_WARNING, "PropSet: Property \"%s\" is deprecated. Please use \"%s\" instead.", property_key_cstr, property_key.c_str());
	}

	dbus_message_ref(message);

	interface->property_set_value(
		property_key,
		property_value,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_prop_insert_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	DBusMessageIter iter;
	const char* property_key_cstr = "";
	std::string property_key;
	boost::any property_value;

	dbus_message_iter_init(message, &iter);

	require (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING, bail);

	dbus_message_iter_get_basic(&iter, &property_key_cstr);
	dbus_message_iter_next(&iter);

	property_value = any_from_dbus_iter(&iter);
	property_key = property_key_cstr;

	if (interface->translate_deprecated_property(property_key, property_value)) {
		syslog(LOG_WARNING, "PropeInsert: Property \"%s\" is deprecated. Please use \"%s\" instead.", property_key_cstr, property_key.c_str());
	}

	dbus_message_ref(message);

	interface->property_insert_value(
		property_key,
		property_value,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_prop_remove_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	DBusMessageIter iter;
	const char* property_key_cstr = "";
	std::string property_key;
	boost::any property_value;

	dbus_message_iter_init(message, &iter);

	require (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING, bail);

	dbus_message_iter_get_basic(&iter, &property_key_cstr);
	dbus_message_iter_next(&iter);

	property_value = any_from_dbus_iter(&iter);
	property_key = property_key_cstr;

	if (interface->translate_deprecated_property(property_key, property_value)) {
		syslog(LOG_WARNING, "PropRemove: Property \"%s\" is deprecated. Please use \"%s\" instead.", property_key_cstr, property_key.c_str());
	}

	dbus_message_ref(message);

	interface->property_remove_value(
		property_key,
		property_value,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_net_scan_start_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	ValueMap options;
	NCPControlInterface::ChannelMask channel_mask = 0;

	dbus_message_ref(message);

	dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &channel_mask,
		DBUS_TYPE_INVALID
	);

	if (channel_mask) {
		options[kWPANTUNDValueMapKey_Scan_ChannelMask] = channel_mask;
	}

	interface->netscan_start(
		options,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_discover_scan_start_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	ValueMap options;
	NCPControlInterface::ChannelMask channel_mask = 0;
	dbus_bool_t joiner_flag = FALSE;
	dbus_bool_t enable_filtering = FALSE;
	uint16_t pan_id_filter = 0xffff;

	dbus_message_ref(message);

	dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &channel_mask,
		DBUS_TYPE_BOOLEAN, &joiner_flag,
		DBUS_TYPE_BOOLEAN, &enable_filtering,
		DBUS_TYPE_UINT16, &pan_id_filter,
		DBUS_TYPE_INVALID
	);

	options[kWPANTUNDValueMapKey_Scan_Discover] = true;

	if (channel_mask) {
		options[kWPANTUNDValueMapKey_Scan_ChannelMask] = channel_mask;
	}

	options[kWPANTUNDValueMapKey_Scan_JoinerFalg] = joiner_flag ? true : false;
	options[kWPANTUNDValueMapKey_Scan_EnableFiltering] = enable_filtering ? true : false;
	options[kWPANTUNDValueMapKey_Scan_PANIDFilter] = pan_id_filter;

	interface->netscan_start(
		options,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_energy_scan_start_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	ValueMap options;
	NCPControlInterface::ChannelMask channel_mask = 0;

	dbus_message_ref(message);

	dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &channel_mask,
		DBUS_TYPE_INVALID
	);

	if (channel_mask) {
		options[kWPANTUNDProperty_NCPChannelMask] = channel_mask;
	}

	interface->energyscan_start(
		options,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_pcap_to_fd_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	int fd = -1;

	dbus_message_ref(message);

	dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UNIX_FD, &fd,
		DBUS_TYPE_INVALID
	);

	interface->pcap_to_fd(
		fd,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_pcap_terminate_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->pcap_terminate(
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_data_poll_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_ref(message);

	interface->data_poll(boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,
								 this, _1, message));
	ret = DBUS_HANDLER_RESULT_HANDLED;

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_config_gateway_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_bool_t default_route = FALSE;
	dbus_bool_t preferred = TRUE;
	dbus_bool_t slaac = TRUE;
	dbus_bool_t on_mesh = TRUE;
	dbus_bool_t dhcp = FALSE;
	dbus_bool_t configure = FALSE;
	dbus_bool_t stable = TRUE;
	dbus_bool_t nd_dns = FALSE;
	dbus_bool_t domain_prefix = FALSE;
	uint32_t preferred_lifetime = 0;
	uint32_t valid_lifetime = 0;
	uint8_t *prefix(NULL);
	int prefix_len_in_bytes(0);
	struct in6_addr address = {};
	bool did_succeed(false);
	int16_t priority_raw(0);
	NCPControlInterface::OnMeshPrefixPriority priority(NCPControlInterface::PREFIX_MEDIUM_PREFERENCE);
	NCPControlInterface::OnMeshPrefixFlags flags;
	uint16_t prefix_len_in_bits = 0;
	const uint16_t max_prefix_len_in_bits = 64;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_BOOLEAN, &default_route,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &prefix, &prefix_len_in_bytes,
		DBUS_TYPE_UINT32, &preferred_lifetime,
		DBUS_TYPE_UINT32, &valid_lifetime,
		DBUS_TYPE_BOOLEAN, &preferred,
		DBUS_TYPE_BOOLEAN, &slaac,
		DBUS_TYPE_BOOLEAN, &on_mesh,
		DBUS_TYPE_INT16, &priority_raw,
		DBUS_TYPE_BOOLEAN, &dhcp,
		DBUS_TYPE_BOOLEAN, &configure,
		DBUS_TYPE_BOOLEAN, &stable,
		DBUS_TYPE_UINT16, &prefix_len_in_bits,
		DBUS_TYPE_BOOLEAN, &nd_dns,
		DBUS_TYPE_BOOLEAN, &domain_prefix,
		DBUS_TYPE_INVALID
	);

	if (!did_succeed) {
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_BOOLEAN, &default_route,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &prefix, &prefix_len_in_bytes,
			DBUS_TYPE_UINT32, &preferred_lifetime,
			DBUS_TYPE_UINT32, &valid_lifetime,
			DBUS_TYPE_BOOLEAN, &preferred,
			DBUS_TYPE_BOOLEAN, &slaac,
			DBUS_TYPE_BOOLEAN, &on_mesh,
			DBUS_TYPE_INT16, &priority_raw,
			DBUS_TYPE_BOOLEAN, &dhcp,
			DBUS_TYPE_BOOLEAN, &configure,
			DBUS_TYPE_BOOLEAN, &stable,
			DBUS_TYPE_UINT16, &prefix_len_in_bits,
			DBUS_TYPE_INVALID
		);
	}

	if (!did_succeed) {
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_BOOLEAN, &default_route,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &prefix, &prefix_len_in_bytes,
			DBUS_TYPE_UINT32, &preferred_lifetime,
			DBUS_TYPE_UINT32, &valid_lifetime,
			DBUS_TYPE_BOOLEAN, &preferred,
			DBUS_TYPE_BOOLEAN, &slaac,
			DBUS_TYPE_BOOLEAN, &on_mesh,
			DBUS_TYPE_INT16, &priority_raw,
			DBUS_TYPE_INVALID
		);

		prefix_len_in_bits = static_cast<uint16_t>(IPV6_PREFIX_BYTES_TO_BITS(prefix_len_in_bytes));

		if (prefix_len_in_bits > max_prefix_len_in_bits) {
			prefix_len_in_bits = max_prefix_len_in_bits;
		}
	}

	if (!did_succeed) {
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_BOOLEAN, &default_route,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &prefix, &prefix_len_in_bytes,
			DBUS_TYPE_UINT32, &preferred_lifetime,
			DBUS_TYPE_UINT32, &valid_lifetime,
			DBUS_TYPE_INVALID
		);

		prefix_len_in_bits = static_cast<uint16_t>(IPV6_PREFIX_BYTES_TO_BITS(prefix_len_in_bytes));

		if (prefix_len_in_bits > max_prefix_len_in_bits) {
			prefix_len_in_bits = max_prefix_len_in_bits;
		}
	}

	require(did_succeed, bail);
	require(prefix_len_in_bytes <= sizeof(address), bail);
	require(prefix_len_in_bytes >= 0, bail);

	require(prefix_len_in_bits <= max_prefix_len_in_bits, bail);
	require(prefix_len_in_bits > 0, bail);
	require(prefix_len_in_bits <= IPV6_PREFIX_BYTES_TO_BITS(prefix_len_in_bytes), bail);

	memcpy(address.s6_addr, prefix, prefix_len_in_bytes);

	if (priority_raw > 0) {
		priority = NCPControlInterface::PREFIX_HIGH_PREFERENCE;
	} else if (priority_raw < 0) {
		priority = NCPControlInterface::PREFIX_LOW_PREFRENCE;
	}

	if (default_route) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_DEFAULT_ROUTE);
	}

	if (preferred) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_PREFERRED);
	}

	if (slaac) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_SLAAC);
	}

	if (on_mesh) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_ON_MESH);
	}

	if (dhcp) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_DHCP);
	}

	if (configure) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_CONFIGURE);
	}

	if (nd_dns) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_ND_DNS);
	}

	if (domain_prefix) {
		flags.insert(NCPControlInterface::PREFIX_FLAG_DOMAIN_PREFIX);
	}

	dbus_message_ref(message);

	if (valid_lifetime == 0) {
		interface->remove_on_mesh_prefix(
			address,
			static_cast<uint8_t>(prefix_len_in_bits),
			boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,this, _1, message)
		);
	} else {
		interface->add_on_mesh_prefix(
			address,
			static_cast<uint8_t>(prefix_len_in_bits),
			flags,
			priority,
			stable,
			boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper,this, _1, message)
		);
	}

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::service_add_handler(
	NCPControlInterface *interface,
	DBusMessage *message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	bool did_succeed;
	uint32_t enterprise_number;
	uint8_t *service_data;
	int service_data_len;
	dbus_bool_t stable;
	uint8_t *server_data;
	int server_data_len;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &enterprise_number,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &service_data, &service_data_len,
		DBUS_TYPE_BOOLEAN, &stable,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &server_data, &server_data_len,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);

	dbus_message_ref(message);

	interface->add_service(
		enterprise_number,
		Data(service_data, service_data_len),
		stable,
		Data(server_data, server_data_len),
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message));

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::service_remove_handler(
	NCPControlInterface *interface,
	DBusMessage *message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	bool did_succeed;
	uint32_t enterprise_number;
	uint8_t *service_data;
	int service_data_len;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &enterprise_number,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &service_data, &service_data_len,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);

	dbus_message_ref(message);

	interface->remove_service(
		enterprise_number,
		Data(service_data, service_data_len),
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message));

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_route_add_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint8_t *route_prefix(NULL);
	int prefix_len_in_bytes(0);
	uint16_t domain_id(0);
	int16_t priority_raw(0);
	NCPControlInterface::ExternalRoutePriority priority(NCPControlInterface::ROUTE_MEDIUM_PREFERENCE);
	dbus_bool_t stable(TRUE);
	uint8_t prefix_len_in_bits(0);
	struct in6_addr address = {};
	bool did_succeed(false);

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &route_prefix, &prefix_len_in_bytes,
		DBUS_TYPE_UINT16, &domain_id,
		DBUS_TYPE_INT16, &priority_raw,
		DBUS_TYPE_BYTE, &prefix_len_in_bits,
		DBUS_TYPE_BOOLEAN, &stable,
		DBUS_TYPE_INVALID
	);

	if (!did_succeed) {
		// Check the syntax without the `stable` argument
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &route_prefix, &prefix_len_in_bytes,
			DBUS_TYPE_UINT16, &domain_id,
			DBUS_TYPE_INT16, &priority_raw,
			DBUS_TYPE_BYTE, &prefix_len_in_bits,
			DBUS_TYPE_INVALID
		);
	}

	if (!did_succeed) {
		// Likely using the old syntax that doesn't include the prefix length in bits
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &route_prefix, &prefix_len_in_bytes,
			DBUS_TYPE_UINT16, &domain_id,
			DBUS_TYPE_INT16, &priority_raw,
			DBUS_TYPE_INVALID
		);
		prefix_len_in_bits = IPV6_PREFIX_BYTES_TO_BITS(prefix_len_in_bytes);
	}

	require(did_succeed, bail);
	require(prefix_len_in_bytes <= sizeof(address), bail);
	require(prefix_len_in_bytes >= 0, bail);

	memcpy(address.s6_addr, route_prefix, prefix_len_in_bytes);

	if  (priority_raw > 0) {
		priority = NCPControlInterface::ROUTE_HIGH_PREFERENCE;
	} else if (priority_raw < 0) {
		priority = NCPControlInterface::ROUTE_LOW_PREFRENCE;
	}

	dbus_message_ref(message);

	interface->add_external_route(
		&address,
		prefix_len_in_bits,
		domain_id,
		priority,
		stable,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_route_remove_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint8_t *route_prefix = NULL;
	int prefix_len_in_bytes(0);
	uint8_t prefix_len_in_bits(0);
	uint16_t domain_id = 0;
	struct in6_addr address = {};
	bool did_succeed(false);

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &route_prefix, &prefix_len_in_bytes,
		DBUS_TYPE_UINT16, &domain_id,
		DBUS_TYPE_BYTE, &prefix_len_in_bits,
		DBUS_TYPE_INVALID
	);

	if (!did_succeed) {
		// Likely using the old syntax that doesn't include the prefix length in bits
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &route_prefix, &prefix_len_in_bytes,
			DBUS_TYPE_UINT16, &domain_id,
			DBUS_TYPE_INVALID
		);
		prefix_len_in_bits = IPV6_PREFIX_BYTES_TO_BITS(prefix_len_in_bytes);
	}

	require(did_succeed, bail);
	require(prefix_len_in_bytes <= sizeof(address), bail);
	require(prefix_len_in_bytes >= 0, bail);

	memcpy(address.s6_addr, route_prefix, prefix_len_in_bytes);

	dbus_message_ref(message);

	interface->remove_external_route(
		&address,
		prefix_len_in_bits,
		domain_id,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_joiner_attach_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	ValueMap options;
	DBusMessageIter iter;

	dbus_message_iter_init(message, &iter);

	options = value_map_from_dbus_iter(&iter);

	dbus_message_ref(message);

	interface->joiner_attach(
		options,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_joiner_start_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	ValueMap options;
	DBusMessageIter iter;

	dbus_message_iter_init(message, &iter);

	options = value_map_from_dbus_iter(&iter);

	dbus_message_ref(message);

	interface->joiner_commissioning(
		true, // start
		options,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_joiner_stop_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	ValueMap options;

	dbus_message_ref(message);

	interface->joiner_commissioning(
		false, // stop
		options,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_joiner_commissioning_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	// The "JoinerCommissioning" DBus command is being deprecated.
	// Please use the "JoinerStart" and "JoinerStop" DBus commands
	// instead

	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_bool_t action = FALSE;
	const char* psk = NULL;
	const char* provisioning_url = NULL;
	int psk_len = 0;
	int provisioning_url_len = 0;
	bool did_succeed = false;
	ValueMap options;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_BOOLEAN, &action,
		DBUS_TYPE_STRING, &psk,
		DBUS_TYPE_STRING, &provisioning_url,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);

	// psk must be specified if joiner starts commissioning
	require(action == FALSE || psk != NULL, bail);

	if (psk) {
		options[kWPANTUNDValueMapKey_Joiner_PSKd] = std::string(psk);
	}

	if (provisioning_url) {
		options[kWPANTUNDValueMapKey_Joiner_ProvisioningUrl] = std::string(provisioning_url);
	}

	dbus_message_ref(message);
	interface->joiner_commissioning(
		action,
		options,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_joiner_add_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	NCPControlInterface::JoinerInfo joiner;
	const uint8_t* ext_addr = NULL;
	int ext_addr_len = 0;
	const char* psk = NULL;
	uint32_t timeout = 0;
	uint8_t discerner_len = 0;
	uint64_t discerner_value = 0;
	bool did_succeed = false;


	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_STRING, &psk,
		DBUS_TYPE_UINT32, &timeout,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ext_addr, &ext_addr_len,
		DBUS_TYPE_BYTE, &joiner.mDiscerner.mBitLength,
		DBUS_TYPE_UINT64, &joiner.mDiscerner.mValue,
		DBUS_TYPE_INVALID
	);

	joiner.mType = NCPControlInterface::JoinerInfo::kDiscerner;

	if (!did_succeed) {
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_STRING, &psk,
			DBUS_TYPE_UINT32, &timeout,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ext_addr, &ext_addr_len,
			DBUS_TYPE_INVALID
		);

		if (did_succeed) {
			joiner.mType = NCPControlInterface::JoinerInfo::kEui64;
			require(ext_addr_len == NCP_EUI64_SIZE, bail);
			memcpy(&joiner.mEui64, ext_addr, NCP_EUI64_SIZE);
		}
	}

	if (!did_succeed) {
		// No extended address specified
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_STRING, &psk,
			DBUS_TYPE_UINT32, &timeout,
			DBUS_TYPE_INVALID
		);

		joiner.mType = NCPControlInterface::JoinerInfo::kAny;
	}

	require(did_succeed, bail);
	require(psk != NULL, bail);

	dbus_message_ref(message);

	interface->commissioner_add_joiner(
		joiner,
		timeout,
		psk,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_joiner_remove_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	NCPControlInterface::JoinerInfo joiner;
	const uint8_t* ext_addr = NULL;
	int ext_addr_len = 0;
	uint32_t joiner_timeout = 0;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &joiner_timeout,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ext_addr, &ext_addr_len,
		DBUS_TYPE_BYTE, &joiner.mDiscerner.mBitLength,
		DBUS_TYPE_UINT64, &joiner.mDiscerner.mValue,
		DBUS_TYPE_INVALID
	);

	joiner.mType = NCPControlInterface::JoinerInfo::kDiscerner;

	if (!did_succeed) {
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_UINT32, &joiner_timeout,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ext_addr, &ext_addr_len,
			DBUS_TYPE_INVALID
		);

		if (did_succeed) {
			joiner.mType = NCPControlInterface::JoinerInfo::kEui64;
			require(ext_addr_len == NCP_EUI64_SIZE, bail);
			memcpy(&joiner.mEui64, ext_addr, NCP_EUI64_SIZE);
		}
	}

	if (!did_succeed) {
		// No extended address specified
		did_succeed = dbus_message_get_args(
			message, NULL,
			DBUS_TYPE_UINT32, &joiner_timeout,
			DBUS_TYPE_INVALID
		);

		joiner.mType = NCPControlInterface::JoinerInfo::kAny;
	}

	require(did_succeed, bail);

	dbus_message_ref(message);

	interface->commissioner_remove_joiner(
		joiner,
		joiner_timeout,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_announce_begin_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint32_t channel_mask;
	uint8_t count;
	uint16_t period;
	const uint8_t *dest_addr = NULL;
	int dest_addr_len;
	struct in6_addr dest;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &channel_mask,
		DBUS_TYPE_BYTE, &count,
		DBUS_TYPE_UINT16, &period,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_addr, &dest_addr_len,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(dest_addr_len == sizeof(dest), bail);

	dbus_message_ref(message);

	memcpy(dest.s6_addr, dest_addr, sizeof(dest));

	interface->commissioner_send_announce_begin(
		channel_mask,
		count,
		period,
		dest,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_energy_scan_query_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint32_t channel_mask;
	uint8_t count;
	uint16_t period;
	uint16_t scan_duration;
	const uint8_t *dest_addr = NULL;
	int dest_addr_len;
	struct in6_addr dest;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &channel_mask,
		DBUS_TYPE_BYTE, &count,
		DBUS_TYPE_UINT16, &period,
		DBUS_TYPE_UINT16, &scan_duration,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_addr, &dest_addr_len,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(dest_addr_len == sizeof(dest), bail);

	dbus_message_ref(message);

	memcpy(dest.s6_addr, dest_addr, sizeof(dest));

	interface->commissioner_send_energy_scan_query(
		channel_mask,
		count,
		period,
		scan_duration,
		dest,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_pan_id_query_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint16_t pan_id;
	uint32_t channel_mask;
	const uint8_t *dest_addr = NULL;
	int dest_addr_len;
	struct in6_addr dest;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT16, &pan_id,
		DBUS_TYPE_UINT32, &channel_mask,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_addr, &dest_addr_len,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(dest_addr_len == sizeof(dest), bail);

	dbus_message_ref(message);

	memcpy(dest.s6_addr, dest_addr, sizeof(dest));

	interface->commissioner_send_pan_id_query(
		pan_id,
		channel_mask,
		dest,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_generate_pskc(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	const char *pass_phrase = "";
	const char *network_name = "";
	const uint8_t *xpan_id_ptr = NULL;
	int xpan_id_len;
	NCPControlInterface::XPANId xpan_id;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_STRING, &pass_phrase,
		DBUS_TYPE_STRING, &network_name,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &xpan_id_ptr, &xpan_id_len,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(xpan_id_len == sizeof(xpan_id), bail);

	dbus_message_ref(message);

	memcpy(xpan_id.m8, xpan_id_ptr, sizeof(xpan_id));

	interface->commissioner_generate_pskc(
		pass_phrase,
		network_name,
		xpan_id,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatusArg1_Helper, this, _1, _2, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_peek_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint32_t address;
	uint16_t count;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &address,
		DBUS_TYPE_UINT16, &count,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);

	dbus_message_ref(message);

	interface->peek(
		address,
		count,
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatusArg1_Helper,
			this,
			_1,
			_2,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_poke_handler(
   NCPControlInterface* interface,
   DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint32_t address;
	int count = 0;
	uint8_t *bytes = NULL;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT32, &address,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &bytes, &count,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);

	dbus_message_ref(message);

	interface->poke(
		address,
		Data(bytes, count),
		boost::bind(
			&DBusIPCAPI_v1::CallbackWithStatus_Helper,
			this,
			_1,
			message
		)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_link_metrics_query_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	const uint8_t *dest_addr = NULL;
	int dest_addr_len;
	struct in6_addr dest;
	uint8_t series;
	uint8_t metrics = 0;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_addr, &dest_addr_len,
		DBUS_TYPE_BYTE, &series,
		DBUS_TYPE_BYTE, &metrics,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(dest_addr_len == sizeof(dest), bail);

	dbus_message_ref(message);

	memcpy(dest.s6_addr, dest_addr, sizeof(dest));

	interface->link_metrics_query(
		dest,
		series,
		metrics,
	 	boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_link_metrics_probe_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	const uint8_t *dest_addr = NULL;
	int dest_addr_len;
	struct in6_addr dest;
	uint8_t series;
	uint8_t length;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_addr, &dest_addr_len,
		DBUS_TYPE_BYTE, &series,
		DBUS_TYPE_BYTE, &length,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(dest_addr_len == sizeof(dest), bail);

	dbus_message_ref(message);

	memcpy(dest.s6_addr, dest_addr, sizeof(dest));

	interface->link_metrics_probe(
		dest,
		series,
		length,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_link_metrics_mgmt_forward_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	const uint8_t *dest_addr = NULL;
	int dest_addr_len;
	struct in6_addr dest;
	uint8_t series_id = 0;
	uint8_t metrics = 0;
	uint8_t frame_types = 0;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_addr, &dest_addr_len,
		DBUS_TYPE_BYTE, &series_id,
		DBUS_TYPE_BYTE, &frame_types,
		DBUS_TYPE_BYTE, &metrics,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(dest_addr_len == sizeof(dest), bail);

	dbus_message_ref(message);

	memcpy(dest.s6_addr, dest_addr, sizeof(dest));

	interface->link_metrics_mgmt_forward(
		dest,
		series_id,
		frame_types,
		metrics,
	 	boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_link_metrics_mgmt_enh_ack_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	const uint8_t *dest_addr = NULL;
	int dest_addr_len;
	struct in6_addr dest;
	uint8_t metrics = 0;
	uint8_t flags = 0;
	bool did_succeed = false;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dest_addr, &dest_addr_len,
		DBUS_TYPE_BYTE, &flags,
		DBUS_TYPE_BYTE, &metrics,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	require(dest_addr_len == sizeof(dest), bail);

	dbus_message_ref(message);

	memcpy(dest.s6_addr, dest_addr, sizeof(dest));

	interface->link_metrics_mgmt_enh_ack(
		dest,
		flags,
		metrics,
	 	boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_mlr_request_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	bool did_succeed = true;
	std::vector<struct in6_addr> addresses;
	dbus_bool_t mlr_timeout_present;
	uint32_t mlr_timeout;

	DBusMessageIter iter;
	did_succeed = dbus_message_iter_init(message, &iter);
	require(did_succeed, bail);

	did_succeed = (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY);
	require(did_succeed, bail);
	DBusMessageIter sub_iter;
	dbus_message_iter_recurse(&iter, &sub_iter);
	do {
		addresses.push_back(any_to_ipv6(any_from_dbus_iter(&sub_iter)));
	} while (dbus_message_iter_next(&sub_iter));

	dbus_message_iter_next(&iter);

	did_succeed = (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_BOOLEAN);
	require(did_succeed, bail);
	dbus_message_iter_get_basic(&iter, &mlr_timeout_present);

	dbus_message_iter_next(&iter);
	did_succeed = (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_UINT32);
	require(did_succeed, bail);
	dbus_message_iter_get_basic(&iter, &mlr_timeout);

	dbus_message_ref(message);

	interface->mlr_request(
		addresses,
		mlr_timeout_present,
		mlr_timeout,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::interface_backbone_router_config_handler(
	NCPControlInterface* interface,
	DBusMessage *        message
) {
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	bool did_succeed = true;
	uint16_t delay = 0;
	uint32_t timeout = 0;
	uint8_t seqno = 0;

	did_succeed = dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_UINT16, &delay,
		DBUS_TYPE_UINT32, &timeout,
		DBUS_TYPE_BYTE, &seqno,
		DBUS_TYPE_INVALID
	);

	require(did_succeed, bail);
	dbus_message_ref(message);

	interface->backbone_router_config(
		delay,
		timeout,
		seqno,
		boost::bind(&DBusIPCAPI_v1::CallbackWithStatus_Helper, this, _1, message)
	);

	ret = DBUS_HANDLER_RESULT_HANDLED;

bail:
	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::message_handler(
    NCPControlInterface* interface,
    DBusConnection *        connection,
    DBusMessage *           message
    )
{
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if ((dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL)
		&& (dbus_message_has_interface(message, WPANTUND_DBUS_APIv1_INTERFACE)
			|| dbus_message_has_interface(message, WPANTUND_DBUS_NLAPIv1_INTERFACE))
		&& mInterfaceCallbackTable.count(dbus_message_get_member(message))
	) {
		try {
			ret = mInterfaceCallbackTable.at(dbus_message_get_member(message))(
				interface,
				message
			);
		} catch (std::invalid_argument x) {
			DBusIPCAPI_v1::CallbackWithStatus_Helper(kWPANTUNDStatus_InvalidArgument,message);
			ret = DBUS_HANDLER_RESULT_HANDLED;
		}
	}

	return ret;
}

DBusHandlerResult
DBusIPCAPI_v1::dbus_message_handler(
    DBusConnection *connection,
    DBusMessage *   message,
    void *          user_data
) {
	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_SIGNAL) {
		syslog(LOG_INFO, "Inbound DBus message for INTERFACE \"%s\" from \"%s\"", dbus_message_get_member(message), dbus_message_get_sender(message));
	}
	std::pair<NCPControlInterface*,
	          DBusIPCAPI_v1*> *cb_data =
	    (std::pair<NCPControlInterface*, DBusIPCAPI_v1*> *)user_data;
	return cb_data->second->message_handler(cb_data->first,
	                                                  connection,
	                                                  message);
}
