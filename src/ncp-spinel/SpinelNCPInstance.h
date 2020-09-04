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

#ifndef __wpantund__SpinelNCPInstance__
#define __wpantund__SpinelNCPInstance__

#include "NCPInstanceBase.h"
#include "SpinelNCPControlInterface.h"
#include "SpinelNCPThreadDataset.h"
#include "SpinelNCPTaskSendCommand.h"
#include "nlpt.h"
#include "SocketWrapper.h"
#include "SocketAsyncOp.h"
#include "ValueMap.h"

#include <queue>
#include <set>
#include <map>
#include <errno.h>
#include "spinel.h"

#include "SpinelNCPVendorCustom.h"

WPANTUND_DECLARE_NCPINSTANCE_PLUGIN(spinel, SpinelNCPInstance);

#define EVENT_NCP_MARKER         0xAB000000
#define EVENT_NCP(x)             ((x)|EVENT_NCP_MARKER)
#define IS_EVENT_FROM_NCP(x)     (((x)&~0xFFFFFF) == EVENT_NCP_MARKER)


#define EVENT_NCP_RESET                (0xFF0000|EVENT_NCP_MARKER)
#define EVENT_NCP_PROP_VALUE_IS        (0xFF0001|EVENT_NCP_MARKER)
#define EVENT_NCP_PROP_VALUE_INSERTED  (0xFF0002|EVENT_NCP_MARKER)
#define EVENT_NCP_PROP_VALUE_REMOVED   (0xFF0003|EVENT_NCP_MARKER)

#define NCP_FRAMING_OVERHEAD 3

#define CONTROL_REQUIRE_EMPTY_OUTBOUND_BUFFER_WITHIN(seconds, error_label) do { \
		EH_WAIT_UNTIL_WITH_TIMEOUT(seconds, (GetInstance(this)->mOutboundBufferLen <= 0) && GetInstance(this)->mOutboundCallback.empty()); \
		require_string(!eh_did_timeout, error_label, "Timed out while waiting " # seconds " seconds for empty outbound buffer"); \
	} while (0)

#define CONTROL_REQUIRE_OUTBOUND_BUFFER_FLUSHED_WITHIN(seconds, error_label) do { \
		static const int ___crsw_send_finished = 0xFF000000 | __LINE__; \
		static const int ___crsw_send_failed = 0xFE000000 | __LINE__; \
		__ASSERT_MACROS_check(GetInstance(this)->mOutboundCallback.empty()); \
		require(GetInstance(this)->mOutboundBufferLen > 0, error_label); \
		GetInstance(this)->mOutboundCallback = CALLBACK_FUNC_SPLIT( \
			boost::bind(&NCPInstanceBase::process_event_helper, GetInstance(this), ___crsw_send_finished), \
			boost::bind(&NCPInstanceBase::process_event_helper, GetInstance(this), ___crsw_send_failed) \
		); \
		GetInstance(this)->mOutboundBuffer[0] = mLastHeader; \
		EH_WAIT_UNTIL_WITH_TIMEOUT(seconds, (event == ___crsw_send_finished) || (event == ___crsw_send_failed)); \
		require_string(!eh_did_timeout, error_label, "Timed out while trying to send command"); \
		require_string(event == ___crsw_send_finished, error_label, "Failure while trying to send command"); \
	} while (0)

#define CONTROL_REQUIRE_PREP_TO_SEND_COMMAND_WITHIN(timeout, error_label) do { \
		CONTROL_REQUIRE_EMPTY_OUTBOUND_BUFFER_WITHIN(timeout, error_label); \
		GetInstance(this)->mLastTID = SPINEL_GET_NEXT_TID(GetInstance(this)->mLastTID); \
		mLastHeader = (SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0 | (GetInstance(this)->mLastTID << SPINEL_HEADER_TID_SHIFT)); \
	} while (false)

#define CONTROL_REQUIRE_COMMAND_RESPONSE_WITHIN(timeout, error_label) do { \
		EH_REQUIRE_WITHIN(	\
			timeout,	\
			IS_EVENT_FROM_NCP(event) && GetInstance(this)->mInboundHeader == mLastHeader, \
			error_label	\
		);	\
	} while (false)

namespace nl {
namespace wpantund {

class SpinelNCPTask;
class SpinelNCPControlInterface;

class SpinelNCPInstance : public NCPInstanceBase {
	friend class SpinelNCPControlInterface;
	friend class SpinelNCPTask;
	friend class SpinelNCPTaskDeepSleep;
	friend class SpinelNCPTaskWake;
	friend class SpinelNCPTaskJoin;
	friend class SpinelNCPTaskForm;
	friend class SpinelNCPTaskScan;
	friend class SpinelNCPTaskLeave;
	friend class SpinelNCPTaskPeek;
	friend class SpinelNCPTaskHostDidWake;
	friend class SpinelNCPTaskSendCommand;
	friend class SpinelNCPTaskGetNetworkTopology;
	friend class SpinelNCPTaskGetMsgBufferCounters;
	friend class SpinelNCPTaskJoinerCommissioning;
	friend class SpinelNCPTaskJoinerAttach;
	friend class SpinelNCPVendorCustom;

public:

	enum DriverState {
		INITIALIZING,
		INITIALIZING_WAITING_FOR_RESET,
		NORMAL_OPERATION
	};

public:
	SpinelNCPInstance(const Settings& settings = Settings());

	virtual ~SpinelNCPInstance();

	virtual SpinelNCPControlInterface& get_control_interface();

	virtual int vprocess_event(int event, va_list args);


protected:
	virtual char ncp_to_driver_pump();
	virtual char driver_to_ncp_pump();

	void start_new_task(const boost::shared_ptr<SpinelNCPTask> &task);

	virtual bool is_busy(void);

protected:

	int vprocess_init(int event, va_list args);
	int vprocess_disabled(int event, va_list args);
	int vprocess_associated(int event, va_list args);
	int vprocess_resume(int event, va_list args);
	int vprocess_offline(int event, va_list args);

	void handle_ncp_spinel_callback(unsigned int command, const uint8_t* cmd_data_ptr, spinel_size_t cmd_data_len);
	void handle_ncp_spinel_value_is(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len);
	void handle_ncp_spinel_value_inserted(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len);
	void handle_ncp_spinel_value_removed(spinel_prop_key_t key, const uint8_t* value_data_ptr, spinel_size_t value_data_len);
	void handle_ncp_state_change(NCPState new_ncp_state, NCPState old_ncp_state);

	void handle_ncp_log_stream(const uint8_t* data_ptr, int data_len);
	void handle_ncp_spinel_value_is_ON_MESH_NETS(const uint8_t* value_data_ptr, spinel_size_t value_data_len);
	void handle_ncp_spinel_value_is_OFF_MESH_ROUTES(const uint8_t* value_data_ptr, spinel_size_t value_data_len);
	void handle_ncp_spinel_value_is_SERVICES(const uint8_t* data_ptr, spinel_size_t value_data_len);

	bool should_filter_address(const struct in6_addr &address, uint8_t prefix_len);
	void filter_addresses(void);

	virtual void add_unicast_address_on_ncp(const struct in6_addr &addr, uint8_t prefix_len,
					CallbackWithStatus cb);
	virtual void remove_unicast_address_on_ncp(const struct in6_addr& addr, uint8_t prefix_len,
					CallbackWithStatus cb);

	virtual void add_multicast_address_on_ncp(const struct in6_addr &addr, CallbackWithStatus cb);
	virtual void remove_multicast_address_on_ncp(const struct in6_addr &addr, CallbackWithStatus cb);

	virtual void add_service_on_ncp(uint32_t enterprise_number, const Data& service_data, bool stable,
					const Data& server_data, CallbackWithStatus cb);

	virtual void remove_service_on_ncp(uint32_t enterprise_number, const Data& service_data, CallbackWithStatus cb);

	virtual void add_on_mesh_prefix_on_ncp(const struct in6_addr &addr, uint8_t prefix_len, uint8_t flags, bool stable,
					CallbackWithStatus cb);
	virtual void remove_on_mesh_prefix_on_ncp(const struct in6_addr &addr, uint8_t prefix_len, uint8_t flags,
					bool stable, CallbackWithStatus cb);

	virtual void add_route_on_ncp(const struct in6_addr &route, uint8_t prefix_len, RoutePreference preference,
					bool stable, CallbackWithStatus cb);
	virtual void remove_route_on_ncp(const struct in6_addr &route, uint8_t prefix_len, RoutePreference preference,
					bool stable, CallbackWithStatus cb);

	static RoutePreference convert_flags_to_route_preference(uint8_t flags);
	static uint8_t convert_route_preference_to_flags(RoutePreference priority);

private:
	enum SpinelFrameOrigin {
		kDriverToNCP,
		kNCPToDriver,
	};

	void log_spinel_frame(SpinelFrameOrigin origin, const uint8_t *frame_ptr, spinel_size_t frame_len);

private:
	void update_node_type(NodeType node_type);
	void update_link_local_address(struct in6_addr *addr);
	void update_mesh_local_address(struct in6_addr *addr);
	void update_mesh_local_prefix(struct in6_addr *addr);

private:
	void get_dataset_command_help(std::list<std::string> &list);
	int unpack_and_set_local_dataset(const uint8_t *data_in, spinel_size_t data_len);
	void perform_dataset_command(const std::string& command, CallbackWithStatus cb);

public:
	static bool setup_property_supported_by_class(const std::string& prop_name);

	virtual std::set<std::string> get_supported_property_keys(void) const;

private:
	typedef SpinelNCPTaskSendCommand::ReplyUnpacker ReplyUnpacker;

	void get_spinel_prop(CallbackWithStatusArg1 cb, spinel_prop_key_t prop_key, const std::string &reply_format);
	void get_spinel_prop_with_unpacker(CallbackWithStatusArg1 cb, spinel_prop_key_t prop_key, ReplyUnpacker unpacker);

	void check_capability_prop_get(CallbackWithStatusArg1 cb, const std::string &prop_name, unsigned int capability,
			PropGetHandler handler);

	void register_get_handler(const char *prop_name, PropGetHandler handler);
	void register_get_handler_capability(const char *prop_name, unsigned int capability, PropGetHandler handler);

	void register_get_handler_spinel_simple(const char *prop_name, spinel_prop_key_t prop_key,
			const char *reply_format);
	void register_get_handler_spinel_unpacker(const char *prop_name, spinel_prop_key_t prop_key,
			ReplyUnpacker unpacker);
	void register_get_handler_capability_spinel_simple(const char *prop_name, unsigned int capability,
			spinel_prop_key_t prop_key, const char *reply_format);
	void register_get_handler_capability_spinel_unpacker(const char *prop_name, unsigned int capability,
			spinel_prop_key_t prop_key, ReplyUnpacker unpacker);

	void regsiter_all_get_handlers(void);

	void get_prop_ConfigNCPDriverName(CallbackWithStatusArg1 cb);
	void get_prop_NCPCapabilities(CallbackWithStatusArg1 cb);
	void get_prop_NetworkIsCommissioned(CallbackWithStatusArg1 cb);
	void get_prop_ThreadRouterID(CallbackWithStatusArg1 cb);
	void get_prop_ThreadConfigFilterRLOCAddresses(CallbackWithStatusArg1 cb);
	void get_prop_ThreadConfigFilterALOCAddresses(CallbackWithStatusArg1 cb);
	void get_prop_JoinerDiscernerBitLength(CallbackWithStatusArg1 cb);
	void get_prop_CommissionerEnergyScanResult(CallbackWithStatusArg1 cb);
	void get_prop_CommissionerPanIdConflictResult(CallbackWithStatusArg1 cb);
	void get_prop_IPv6MeshLocalPrefix(CallbackWithStatusArg1 cb);
	void get_prop_IPv6MeshLocalAddress(CallbackWithStatusArg1 cb);
	void get_prop_IPv6LinkLocalAddress(CallbackWithStatusArg1 cb);
	void get_prop_ThreadChildTable(CallbackWithStatusArg1 cb);
	void get_prop_ThreadChildTableAsValMap(CallbackWithStatusArg1 cb);
	void get_prop_ThreadChildTableAddresses(CallbackWithStatusArg1 cb);
	void get_prop_ThreadNeighborTable(CallbackWithStatusArg1 cb);
	void get_prop_ThreadNeighborTableAsValMap(CallbackWithStatusArg1 cb);
	void get_prop_ThreadNeighborTableErrorRates(CallbackWithStatusArg1 cb);
	void get_prop_ThreadNeighborTableErrorRatesAsValMap(CallbackWithStatusArg1 cb);
	void get_prop_ThreadRouterTable(CallbackWithStatusArg1 cb);
	void get_prop_ThreadRouterTableAsValMap(CallbackWithStatusArg1 cb);
	void get_prop_OpenThreadMsgBufferCounters(CallbackWithStatusArg1 cb);
	void get_prop_OpenThreadMsgBufferCountersAsString(CallbackWithStatusArg1 cb);
	void get_prop_OpenThreadSteeringDataSetWhenJoinable(CallbackWithStatusArg1 cb);
	void get_prop_OpenThreadSteeringDataAddress(CallbackWithStatusArg1 cb);
	void get_prop_DatasetActiveTimestamp(CallbackWithStatusArg1 cb);
	void get_prop_DatasetPendingTimestamp(CallbackWithStatusArg1 cb);
	void get_prop_DatasetMasterKey(CallbackWithStatusArg1 cb);
	void get_prop_DatasetNetworkName(CallbackWithStatusArg1 cb);
	void get_prop_DatasetExtendedPanId(CallbackWithStatusArg1 cb);
	void get_prop_DatasetMeshLocalPrefix(CallbackWithStatusArg1 cb);
	void get_prop_DatasetDelay(CallbackWithStatusArg1 cb);
	void get_prop_DatasetPanId(CallbackWithStatusArg1 cb);
	void get_prop_DatasetChannel(CallbackWithStatusArg1 cb);
	void get_prop_DatasetPSKc(CallbackWithStatusArg1 cb);
	void get_prop_DatasetChannelMaskPage0(CallbackWithStatusArg1 cb);
	void get_prop_DatasetSecPolicyKeyRotation(CallbackWithStatusArg1 cb);
	void get_prop_DatasetSecPolicyFlags(CallbackWithStatusArg1 cb);
	void get_prop_DatasetRawTlvs(CallbackWithStatusArg1 cb);
	void get_prop_DatasetDestIpAddress(CallbackWithStatusArg1 cb);
	void get_prop_DatasetAllFileds(CallbackWithStatusArg1 cb);
	void get_prop_DatasetAllFiledsAsValMap(CallbackWithStatusArg1 cb);
	void get_prop_DatasetCommand(CallbackWithStatusArg1 cb);
	void get_prop_DaemonTickleOnHostDidWake(CallbackWithStatusArg1 cb);
	void get_prop_POSIXAppRCPVersionCached(CallbackWithStatusArg1 cb);
	void get_prop_MACFilterFixedRssi(CallbackWithStatusArg1 cb);

private:
	typedef boost::function<int(const boost::any&, boost::any&)> ValueConverter;

	void set_spinel_prop(const boost::any &value, CallbackWithStatus cb, spinel_prop_key_t prop_key, char pack_type,
			unsigned int capability = 0, bool save_in_settings = false, const std::string &prop_name = std::string());

	static void convert_value_prop_set(const boost::any &value, CallbackWithStatus cb, const std::string &prop_name,
			ValueConverter converter, PropUpdateHandler handler);

	void register_set_handler(const char *prop_name, PropUpdateHandler handler,
			ValueConverter converter = ValueConverter());
	void register_set_handler_spinel(const char *prop_name, spinel_prop_key_t prop_key, char pack_type,
			ValueConverter converter = ValueConverter());
	void register_set_handler_spinel_persist(const char *prop_name, spinel_prop_key_t prop_key, char pack_type,
			ValueConverter converter = ValueConverter());
	void register_set_handler_capability_spinel(const char *prop_name, unsigned int capability,
			spinel_prop_key_t prop_key, char pack_type, ValueConverter converter = ValueConverter());
	void register_set_handler_capability_spinel_persist(const char *prop_name, unsigned int capability,
			spinel_prop_key_t prop_key, char pack_type, ValueConverter converter = ValueConverter());

	void regsiter_all_set_handlers(void);

	static int convert_value_NCPMCUPowerState(const boost::any &value, boost::any &value_out);
	static int convert_value_channel_mask(const boost::any &value, boost::any &value_out);
	static int convert_value_counter_reset(const boost::any &value, boost::any &value_out);
	static int convert_value_CommissionerState(const boost::any &value, boost::any &value_out);

	void set_prop_NetworkKey(const boost::any &value, CallbackWithStatus cb);
	void set_prop_InterfaceUp(const boost::any &value, CallbackWithStatus cb);
	void set_prop_NetworkXPANID(const boost::any &value, CallbackWithStatus cb);
	void set_prop_IPv6MeshLocalPrefix(const boost::any &value, CallbackWithStatus cb);
	void set_prop_ThreadConfigFilterRLOCAddresses(const boost::any &value, CallbackWithStatus cb);
	void set_prop_ThreadConfigFilterALOCAddresses(const boost::any &value, CallbackWithStatus cb);
	void set_prop_OpenThreadSteeringDataSetWhenJoinable(const boost::any &value, CallbackWithStatus cb);
	void set_prop_OpenThreadSteeringDataAddress(const boost::any &value, CallbackWithStatus cb);
	void set_prop_TmfProxyStream(const boost::any &value, CallbackWithStatus cb);
	void set_prop_UdpForwardStream(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetActiveTimestamp(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetPendingTimestamp(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetMasterKey(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetNetworkName(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetExtendedPanId(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetMeshLocalPrefix(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetDelay(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetPanId(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetChannel(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetPSKc(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetChannelMaskPage0(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetSecPolicyKeyRotation(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetSecPolicyFlags(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetRawTlvs(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetDestIpAddress(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DatasetCommand(const boost::any &value, CallbackWithStatus cb);
	void set_prop_DaemonTickleOnHostDidWake(const boost::any &value, CallbackWithStatus cb);
	void set_prop_MACFilterFixedRssi(const boost::any &value, CallbackWithStatus cb);
	void set_prop_JoinerDiscernerBitLength(const boost::any &value, CallbackWithStatus cb);
	void set_prop_JoinerDiscernerValue(const boost::any &value, CallbackWithStatus cb);

private:
	void check_capability_prop_update(const boost::any &value, CallbackWithStatus cb, const std::string &prop_name,
			unsigned int capability, PropUpdateHandler handler);

	void register_insert_handler(const char *prop_name, PropUpdateHandler handler);
	void register_insert_handler_capability(const char *prop_name, unsigned int capability, PropUpdateHandler handler);

	void regsiter_all_insert_handlers(void);

	void insert_prop_MACAllowlistEntries(const boost::any &value, CallbackWithStatus cb);
	void insert_prop_MACDenylistEntries(const boost::any &value, CallbackWithStatus cb);
	void insert_prop_MACFilterEntries(const boost::any &value, CallbackWithStatus cb);

private:
	void register_remove_handler(const char *prop_name, PropUpdateHandler handler);
	void register_remove_handler_capability(const char *prop_name, unsigned int capability, PropUpdateHandler handler);

	void regsiter_all_remove_handlers(void);

	void remove_prop_MACAllowlistEntries(const boost::any &value, CallbackWithStatus cb);
	void remove_prop_MACDenylistEntries(const boost::any &value, CallbackWithStatus cb);
	void remove_prop_MACFilterEntries(const boost::any &value, CallbackWithStatus cb);

public:

	virtual void property_get_value(const std::string& key, CallbackWithStatusArg1 cb);

	virtual void property_set_value(const std::string& key, const boost::any& value, CallbackWithStatus cb);

	virtual void property_insert_value(const std::string& key, const boost::any& value, CallbackWithStatus cb);

	virtual void property_remove_value(const std::string& key, const boost::any& value, CallbackWithStatus cb);


public:
	virtual cms_t get_ms_to_next_event(void);

	virtual void reset_tasks(wpantund_status_t status = kWPANTUNDStatus_Canceled);

	static void handle_ncp_debug_stream(const uint8_t* data_ptr, int data_len);

	static std::string thread_mode_to_string(uint8_t mode);

	uint8_t get_thread_mode(void);

	virtual void process(void);

private:
	struct SettingsEntry
	{
	public:
		SettingsEntry(const Data &command = Data(), unsigned int capability = 0) :
			mSpinelCommand(command),
			mCapability(capability)
		{
		}

		Data mSpinelCommand;
		unsigned int mCapability;
	};

	/* Map from property key to setting entry
	 *
	 * The map contains all parameters/properties that are retained and
	 * restored when NCP gets initialized.
	 *
	 * `Setting entry` contains an optional capability value and an associated
	 * spinel command.
	 *
	 * If the `capability` is present in the list of NCP capabilities , then
	 * the associated spinel command is sent to NCP after initialization.
	 */
	typedef std::map<std::string, SettingsEntry> SettingsMap;

private:
	enum {
		kMaxCommissionerEnergyScanResultEntries = 64,
		kMaxCommissionerPanIdConflictResultEntries = 64,
	};

	SpinelNCPControlInterface mControlInterface;

	uint8_t mLastTID;

	uint8_t mLastHeader;

	uint8_t mInboundFrame[SPINEL_FRAME_BUFFER_SIZE];
	uint8_t mInboundHeader;
	spinel_size_t mInboundFrameSize;
	uint8_t mInboundFrameDataType;
	const uint8_t* mInboundFrameDataPtr;
	spinel_size_t mInboundFrameDataLen;
	uint16_t mInboundFrameHDLCCRC;

	uint8_t mOutboundBufferHeader[3];
	uint8_t mOutboundBuffer[SPINEL_FRAME_BUFFER_SIZE];
	uint8_t mOutboundBufferType;
	spinel_ssize_t mOutboundBufferLen;
	spinel_ssize_t mOutboundBufferSent;
	uint8_t mOutboundBufferEscaped[SPINEL_FRAME_BUFFER_SIZE*2];
	spinel_ssize_t mOutboundBufferEscapedLen;
	boost::function<void(int)> mOutboundCallback;

	int mTXPower;
	uint8_t mThreadMode;
	bool mIsCommissioned;
	bool mFilterRLOCAddresses;
	bool mFilterALOCAddresses;
	bool mTickleOnHostDidWake;
	std::string mRcpVersion;

	std::set<unsigned int> mCapabilities;

	bool mSetSteeringDataWhenJoinable;
	uint8_t mSteeringDataAddress[8];

	ThreadDataset mLocalDataset;

	SettingsMap mSettings;
	SettingsMap::iterator mSettingsIter;

	DriverState mDriverState;

	// Protothreads and related state
	PT mSleepPT;
	PT mSubPT;

	int mSubPTIndex;

	Data mNetworkPSKc;
	Data mNetworkKey;
	uint32_t mNetworkKeyIndex;
	uint32_t mSupportedChannelMask;
	uint32_t mPreferredChannelMask;
	bool mXPANIDWasExplicitlySet;
	uint8_t mChannelManagerNewChannel;
	int8_t mMacFilterFixedRssi;

	uint8_t mJoinerDiscernerBitLength;
	std::list<ValueMap> mCommissionerEnergyScanResult;
	std::list<ValueMap> mCommissionerPanIdConflictResult;

	bool mResetIsExpected;

	bool mIsPcapInProgress;

	// Task management
	std::list<boost::shared_ptr<SpinelNCPTask> > mTaskQueue;

	// The vendor custom class needs to
	// remain as the last thing in this class.
	SpinelNCPVendorCustom mVendorCustom;
}; // class SpinelNCPInstance

extern class SpinelNCPInstance* gNCPInstance;

template<class C>
inline SpinelNCPInstance* GetInstance(C *x)
{
	return x->mInstance;
}

template<>
inline SpinelNCPInstance* GetInstance<SpinelNCPInstance>(SpinelNCPInstance *x)
{
	return x;
}

template<class C>
inline nl::wpantund::SpinelNCPControlInterface* GetInterface(C *x)
{
	return x->mInterface;
}

template<>
inline nl::wpantund::SpinelNCPControlInterface* GetInterface<nl::wpantund::SpinelNCPControlInterface>(nl::wpantund::SpinelNCPControlInterface *x)
{
	return x;
}

bool ncp_event_matches_header_from_args(int event, va_list args, uint8_t last_header);

int peek_ncp_callback_status(int event, va_list args);

int spinel_status_to_wpantund_status(int spinel_status);

}; // namespace wpantund
}; // namespace nl

#endif /* defined(__wpantund__SpinelNCPInstance__) */
