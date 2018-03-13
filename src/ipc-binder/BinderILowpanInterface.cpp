/*
 *
 * Copyright (C) 2017 Nest Labs, Inc.
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
 *    Description:
 *      Thread-safe IBinder class wrapper for NCPControlInterface.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include "assert-macros.h"
#include <stdio.h>
#include "NCPControlInterface.h"
#include "BinderILowpanInterface.h"
#include "BinderIPCServer.h"
#include <boost/bind.hpp>
#include <errno.h>
#include <algorithm>
#include "any-to.h"
#include "wpan-error.h"
#include "BinderTypeGlue.h"

using namespace nl;
using namespace nl::wpantund;
using namespace android;
using namespace android::binder;
using namespace android::net::lowpan;
using ::android::net::lowpan::ILowpanInterface;
using ::android::net::lowpan::LowpanIdentity;
using ::android::net::lowpan::LowpanProvision;
using ::android::net::lowpan::LowpanBeaconInfo;
using ::android::net::lowpan::LowpanCredential;
using ::android::net::lowpan::LowpanChannelInfo;
using ::android::binder::Status;
using ::android::binder::Value;
using ::android::binder::Map;
using ::android::String16;
using ::boost::any;
using ::android::binder::Map;

// Poison the use of boost::any_cast in this file.
// It is too tempting and it will silently not work.
// Put your boost::any_cast stuff in BinderTypeGlue.cpp.
#define any_cast   $$__DO_NOT_USE_BOOST_ANY_CAST_IN_THIS_FILE__$$

BinderILowpanInterface::BinderILowpanInterface(BinderIPCServer &ipcServer, NCPControlInterface *interface):
	mIpcServer(ipcServer),
	mInterface(*interface)
{
	mOnPropertyChangedConnection = interface->mOnPropertyChanged.connect(
		boost::bind(
			&BinderILowpanInterface::onPropertyChanged,
			this,
			_1,
			_2
		)
	);

	mOnNetScanBeaconConnection = interface->mOnNetScanBeacon.connect(
		boost::bind(
			&BinderILowpanInterface::onNetScanBeacon,
			this,
			_1
		)
	);

	mOnEnergyScanResultConnection = interface->mOnEnergyScanResult.connect(
		boost::bind(
			&BinderILowpanInterface::onEnergyScanResult,
			this,
			_1
		)
	);
}

BinderILowpanInterface::~BinderILowpanInterface()
{
	mOnPropertyChangedConnection.disconnect();
	mOnNetScanBeaconConnection.disconnect();
	mOnEnergyScanResultConnection.disconnect();
}

void
BinderILowpanInterface::binderDied(const wp<IBinder>& who)
{
	removeListener(interface_cast<ILowpanInterfaceListener>(who.promote()));
}

::android::binder::Status
BinderILowpanInterface::getName(::std::string* _aidl_return)
{
	// This method doesn't require us to lock the main thread.
	*_aidl_return = mInterface.get_name();
	return Status::ok();
}

Status
BinderILowpanInterface::join(const LowpanProvision& provision)
{
	Status ret;
	CallbackArguments args;
	ValueMap value_map;

	// Convert the provision to a value map that we can
	// then pass into join().
	ret = add_to_value_map(value_map, provision);

	require(ret.isOk(), bail);

	// Make sure we don't automatically enter the comissioning
	// state upon joining error.
	value_map[kWPANTUNDUseModernBehavior] = true;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.join(value_map, CallbackCompletion(args));
	}

	args.wait();

	ret = args.get_android_status();

bail:
	return ret;
}

::android::binder::Status
BinderILowpanInterface::form(const LowpanProvision& provision)
{
	Status ret;
	CallbackArguments args;
	ValueMap value_map;

	// Convert the provision to a value map that we can
	// then pass into form().
	ret = add_to_value_map(value_map, provision);

	require(ret.isOk(), bail);

	// Always use modern behavior
	value_map[kWPANTUNDUseModernBehavior] = true;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.form(value_map, CallbackCompletion(args));
	}

	args.wait();

	ret = args.get_android_status();

bail:
	return ret;
}

::android::binder::Status
BinderILowpanInterface::attach(const LowpanProvision& provision)
{
	Status ret;
	ValueMap value_map;
	ValueMap::const_iterator iter;

	// Convert the provision to property values that we can
	// then set on the interface.
	ret = add_to_value_map(value_map, provision);

	require(ret.isOk(), bail);

	// Always use modern behavior
	value_map[kWPANTUNDUseModernBehavior] = true;

	for (iter = value_map.begin(); iter != value_map.end(); ++iter) {
		ret = setProperty(iter->first, iter->second);
		require (ret.isOk(), bail);
	}

	ret = setProperty(kWPANTUNDProperty_InterfaceUp, cast_to_any(true));

bail:
	return ret;
}

::android::binder::Status
BinderILowpanInterface::leave()
{
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.leave(CallbackCompletion(ret));
	}

	ret.wait();

	return ret.get_android_status();
}

::android::binder::Status
BinderILowpanInterface::reset()
{
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.reset(CallbackCompletion(ret));
	}

	ret.wait();

	return ret.get_android_status();
}

::android::binder::Status
BinderILowpanInterface::beginLowPower()
{
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.begin_low_power(CallbackCompletion(ret));
	}

	ret.wait();

	return ret.get_android_status();
}

::android::binder::Status
BinderILowpanInterface::onHostWake()
{
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.host_did_wake(CallbackCompletion(ret));
	}

	ret.wait();

	return ret.get_android_status();
}

::android::binder::Status
BinderILowpanInterface::pollForData()
{
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.data_poll(CallbackCompletion(ret));
	}

	ret.wait();

	return ret.get_android_status();
}

Status BinderILowpanInterface::fetchProperty(const std::string& key, boost::any& out) {
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.property_get_value(key, CallbackCompletion(ret));
	}

	ret.wait();

	out = ret.mValue;

	return ret.get_android_status();
}

Status BinderILowpanInterface::fetchPropertyToBinderValue(const std::string& key, Value& value) {
	boost::any x;
	Status ret = fetchProperty(key, x);

	require(ret.isOk(), bail);

	try {
		value = cast_to_binder_value(x);

	} catch (boost::bad_any_cast x) {
		ret = Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	} catch (std::invalid_argument x) {
		ret = Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	}

bail:
	return ret;
}

Status BinderILowpanInterface::setProperty(const std::string& key, const boost::any& value) {
	CallbackArguments args;
	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.property_set_value(key, value, CallbackCompletion(args));
	}
	args.wait();
	return args.get_android_status();
}

Status BinderILowpanInterface::getSupportedChannels(::std::vector<::android::net::lowpan::LowpanChannelInfo>* _aidl_return) {
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

Status BinderILowpanInterface::getSupportedNetworkTypes(::std::vector<::std::string>* _aidl_return) {
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

Status BinderILowpanInterface::setEnabled(bool enabled) {
	return setProperty(kWPANTUNDProperty_DaemonEnabled, cast_to_any(enabled));
}


#define FETCH_AND_RETURN_PROPERTY_WITH_ACTION(key, getter, action) \
	Value value; \
	Status ret; \
	ret = fetchPropertyToBinderValue(key, value); \
	require(ret.isOk(), bail); \
	require_action(value.getter(_aidl_return), bail, ret = wpantund_status_to_binder_status(kWPANTUNDStatus_Failure)); \
bail: \
	if (!ret.isOk()) { \
		action ; \
	} \
	return ret

#define FETCH_AND_RETURN_PROPERTY(key, getter) \
	FETCH_AND_RETURN_PROPERTY_WITH_ACTION(key, getter, \
		ret.setServiceSpecificError(ret.serviceSpecificErrorCode(), ret.exceptionMessage() + " (" + key + ")") \
	)

Status BinderILowpanInterface::getNcpVersion(::std::string* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY(kWPANTUNDProperty_NCPVersion, getString);
}

Status BinderILowpanInterface::getDriverVersion(::std::string* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY(kWPANTUNDProperty_DaemonVersion, getString);
}

Status BinderILowpanInterface::getMacAddress(::std::vector<uint8_t>* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY(kWPANTUNDProperty_NCPHardwareAddress, getByteVector);
}

Status BinderILowpanInterface::isEnabled(bool* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY(kWPANTUNDProperty_DaemonEnabled, getBoolean);
}

Status BinderILowpanInterface::isUp(bool* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY(kWPANTUNDProperty_InterfaceUp, getBoolean);
}

Status BinderILowpanInterface::isCommissioned(bool* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY_WITH_ACTION(kWPANTUNDProperty_NetworkIsCommissioned, getBoolean, { ret = Status::ok(); *_aidl_return = false; });
}

Status BinderILowpanInterface::isConnected(bool* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY_WITH_ACTION(kWPANTUNDProperty_NetworkIsConnected, getBoolean, { ret = Status::ok(); *_aidl_return = false; });
}

Status BinderILowpanInterface::getRole(::std::string* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY(kWPANTUNDProperty_NCPRole, getString);
}

Status BinderILowpanInterface::getExtendedAddress(::std::vector<uint8_t>* _aidl_return) {
	FETCH_AND_RETURN_PROPERTY(kWPANTUNDProperty_NCPExtendedAddress, getByteVector);
}

Status BinderILowpanInterface::getPartitionId(::std::string* _aidl_return) {
	// This is a stub.
	// TODO: Plumb this into wpantund.
	*_aidl_return = "";
	return Status::ok();
}

Status BinderILowpanInterface::getState(::std::string* _aidl_return) {
	// We can't use the FETCH_AND_RETURN_PROPERTY macros here because
	// we have to convert the wpantund-style status to a lowpan status.
	boost::any x;
	Status ret = fetchProperty(kWPANTUNDProperty_NCPState, x);

	require(ret.isOk(), bail);

	try {
		*_aidl_return = ncp_state_to_lowpan_state(any_to_string(x));
	} catch (boost::bad_any_cast x) {
		ret = Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	} catch (std::invalid_argument x) {
		ret = Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	}

bail:
	return ret;
}

Status BinderILowpanInterface::getLowpanIdentity(::android::net::lowpan::LowpanIdentity* _aidl_return) {
	LowpanIdentity::Builder builder;
	Status ret;
	Value value;
	std::string tmpString;
	std::vector<uint8_t> tmpByteVector;
	int32_t tmpInt32;

	ret = fetchPropertyToBinderValue(kWPANTUNDProperty_NetworkName, value);
	if (ret.isOk() && value.getString(&tmpString)) {
		builder.setName(tmpString);
	}

	ret = fetchPropertyToBinderValue(kWPANTUNDProperty_NetworkType, value);
	if (ret.isOk() && value.getString(&tmpString)) {
		builder.setType(tmpString);
	}

	ret = fetchPropertyToBinderValue(kWPANTUNDProperty_NetworkXPANID, value);
	if (ret.isOk() && value.getByteVector(&tmpByteVector)) {
		builder.setXpanid(tmpByteVector);
	}

	ret = fetchPropertyToBinderValue(kWPANTUNDProperty_NetworkPANID, value);
	if (ret.isOk() && value.getInt(&tmpInt32)) {
		builder.setPanid(tmpInt32);
	}

	ret = fetchPropertyToBinderValue(kWPANTUNDProperty_NCPChannel, value);
	if (ret.isOk() && value.getInt(&tmpInt32)) {
		builder.setChannel(tmpInt32);
	}

	*_aidl_return = builder.build();

	return Status::ok();
}

Status BinderILowpanInterface::getLowpanCredential(::android::net::lowpan::LowpanCredential* _aidl_return) {
	Status ret;
	Value value;
	std::vector<uint8_t> masterKey;
	int32_t masterKeyIndex = 0;

	ret = fetchPropertyToBinderValue(kWPANTUNDProperty_NetworkKey, value);
	if (ret.isOk()) {
		value.getByteVector(&masterKey);
	}

	ret = fetchPropertyToBinderValue(kWPANTUNDProperty_NetworkKeyIndex, value);
	if (ret.isOk()) {
		value.getInt(&masterKeyIndex);
	}

	return Status::fromStatusT(LowpanCredential::initMasterKey(*_aidl_return, masterKey, masterKeyIndex));
}

::android::binder::Status
BinderILowpanInterface::addListener(const ::android::sp<::android::net::lowpan::ILowpanInterfaceListener>& listener)
{
	{
		std::lock_guard<std::mutex> guard(mMutex);
		mListeners.insert(listener);
	}
	ILowpanInterface::asBinder(listener)->linkToDeath(this);
	return Status::ok();
}

::android::binder::Status
BinderILowpanInterface::removeListener(const ::android::sp<::android::net::lowpan::ILowpanInterfaceListener>& listener)
{
	ILowpanInterface::asBinder(listener)->unlinkToDeath(this);
	{
		std::lock_guard<std::mutex> guard(mMutex);
		mListeners.erase(listener);
	}
	return Status::ok();
}

::android::binder::Status
BinderILowpanInterface::getLinkAddresses(::std::vector<std::string>* _aidl_return)
{
	std::string key = kWPANTUNDProperty_InternalAddressTable;
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.property_get_value(key, CallbackCompletion(ret));
	}

	ret.wait();

	if (ret.mStatus == kWPANTUNDStatus_Ok) {
		try {
			convert_any_to_link_addresses(_aidl_return, ret.mValue);
		} catch (boost::bad_any_cast x) {
			syslog(LOG_ERR, "BinderILowpanInterface::getLinkAddresses: Caught bad_any_cast exception, \"%s\"", x.what());
			return Status::fromServiceSpecificError(
				ILowpanInterface::ERROR_UNSPECIFIED,
				x.what()
			);
		}
	} else {
		syslog(LOG_ERR, "BinderILowpanInterface::getLinkAddresses: Unable to fetch key \"%s\", error %d (%08X)", key.c_str(), ret.mStatus, ret.mStatus);
	}

	return ret.get_android_status();
}

::android::binder::Status
BinderILowpanInterface::getLinkNetworks(::std::vector<::android::net::IpPrefix>* _aidl_return)
{
	std::string key = kWPANTUNDProperty_InternalRouteTable;
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.property_get_value(key, CallbackCompletion(ret));
	}

	ret.wait();

	if (ret.mStatus == kWPANTUNDStatus_Ok) {
		try {
			convert_any_to_link_networks(_aidl_return, ret.mValue);
		} catch (boost::bad_any_cast x) {
			syslog(LOG_ERR, "BinderILowpanInterface::getLinkNetworks: Caught bad_any_cast exception, \"%s\"", x.what());
			return Status::fromServiceSpecificError(
				ILowpanInterface::ERROR_UNSPECIFIED,
				x.what()
			);
		}
	} else {
		syslog(LOG_ERR, "BinderILowpanInterface::getLinkNetworks: Unable to fetch key \"%s\", error %d (%08X)", key.c_str(), ret.mStatus, ret.mStatus);
	}

	return ret.get_android_status();
}

::android::binder::Status
BinderILowpanInterface::addOnMeshPrefix(const ::android::net::IpPrefix& prefix, int32_t flags)
{
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

::android::binder::Status
BinderILowpanInterface::removeOnMeshPrefix(const ::android::net::IpPrefix& prefix)
{
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

::android::binder::Status
BinderILowpanInterface::addExternalRoute(const ::android::net::IpPrefix& prefix, int32_t flags)
{
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

::android::binder::Status
BinderILowpanInterface::removeExternalRoute(const ::android::net::IpPrefix& prefix)
{
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

void
BinderILowpanInterface::onNetScanFinished(int status)
{
	mNetScanStatus = status;
	if (mNetScanListener != NULL) {
		mNetScanListener->onNetScanFinished();
		mNetScanListener.clear();
	}
}

::android::binder::Status
BinderILowpanInterface::startNetScan(const ::android::binder::Map& properties, const ::android::sp<::android::net::lowpan::ILowpanNetScanCallback>& listener)
{
	Status ret = Status::ok();
	ValueMap value_map;

	try {
		value_map = cast_to_value_map(properties);
	} catch (boost::bad_any_cast x) {
		return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	} catch (std::invalid_argument x) {
		return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	}

	{
		BinderIPCServerLock lock(mIpcServer);

		/* Here we wait for any previous scan to complete. To do that
		 * we poll mNetScanListener for when it becomes NULL.
		 * This normally isn't a good synchronization strategy,
		 * but we are using it here because of the complex relationship
		 * between the main thread (which owns mNetScanListener)
		 * and binder threads (of which this function is running on).
		 * A simple polling loop with a 1-second sleep gets the job done
		 * in a fairly robust fashion without adding unnecessary
		 * additional complexity. This comes at the expense of latency
		 * and proper FIFO queueing, neither of which are terribly
		 * important for the initiation of a network scan. In any case,
		 * the contention case should happen extremely rarely.
		 *
		 * We allow 10 seconds to elapse before we give up on the
		 * previous scan and force the previous scan to abort.
		 */
		for (int i = 10; i != 0 && mNetScanListener != NULL; i--) {
			// Unlock the main thread so that it can
			// finish the previous scan.
			mIpcServer.unlockMainThread();

			// Let the main thread run for a second.
			sleep(1);

			// Re-lock the main thread so that we
			// can check mNetScanListener.
			mIpcServer.lockMainThread();
		}

		if (mNetScanListener != NULL) {
			// The previous scan in progress is still in progress.
			// We will fail, but first let's go ahead and try to stop
			// the previous scan in case we are somehow wedged.

			mNetScanListener->onNetScanFinished();
			mNetScanListener.clear();
			mInterface.netscan_stop();

			return Status::fromServiceSpecificError(
				ILowpanInterface::ERROR_UNSPECIFIED,
				"Net scan was already in progress"
			);
		}

		mNetScanListener = listener;
		mNetScanStatus = -1;

		mInterface.netscan_start(value_map,
			boost::bind(
				&BinderILowpanInterface::onNetScanFinished,
				this,
				_1
			)
		);

		if (mNetScanStatus != -1) {
			ret = wpantund_status_to_binder_status(mNetScanStatus);
		} else {
			mNetScanListener = listener;
		}
	}

	return ret;
}

::android::binder::Status
BinderILowpanInterface::stopNetScan()
{
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.netscan_stop(CallbackCompletion(ret));
	}

	ret.wait();

	return ret.get_android_status();
}

void
BinderILowpanInterface::onEnergyScanFinished(int status)
{
	mEnergyScanStatus = status;
	if (mEnergyScanListener != NULL) {
		mEnergyScanListener->onEnergyScanFinished();
		mEnergyScanListener.clear();
	}
}

::android::binder::Status
BinderILowpanInterface::startEnergyScan(const ::android::binder::Map& properties, const ::android::sp<::android::net::lowpan::ILowpanEnergyScanCallback>& listener)
{
	Status ret = Status::ok();
	ValueMap value_map;

	try {
		value_map = cast_to_value_map(properties);
	} catch (boost::bad_any_cast x) {
		return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	} catch (std::invalid_argument x) {
		return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, String8(x.what()));
	}

	{
		BinderIPCServerLock lock(mIpcServer);

		/* Here we wait for any previous scan to complete. To do that
		 * we poll mEnergyScanListener for when it becomes NULL.
		 * This normally isn't a good synchronization strategy,
		 * but we are using it here because of the complex relationship
		 * between the main thread (which owns mEnergyScanListener)
		 * and binder threads (of which this function is running on).
		 * A simple polling loop with a 1-second sleep gets the job done
		 * in a fairly robust fashion without adding unnecessary
		 * additional complexity. This comes at the expense of latency
		 * and proper FIFO queueing, neither of which are terribly
		 * important for the initiation of an energy scan. In any case,
		 * the contention case should happen extremely rarely.
		 *
		 * We allow 10 seconds to elapse before we give up on the
		 * previous scan and force the previous scan to abort.
		 */
		for (int i = 10; i != 0 && mEnergyScanListener != NULL; i--) {
			// Unlock the main thread so that it can
			// finish the previous scan.
			mIpcServer.unlockMainThread();

			// Let the main thread run for a second.
			sleep(1);

			// Re-lock the main thread so that we
			// can check mEnergyScanListener.
			mIpcServer.lockMainThread();
		}

		if (mEnergyScanListener != NULL) {
			// The previous scan in progress is still in progress.
			// We will fail, but first let's go ahead and try to stop
			// the previous scan in case we are somehow wedged.

			mEnergyScanListener->onEnergyScanFinished();
			mEnergyScanListener.clear();
			mInterface.energyscan_stop();

			return Status::fromServiceSpecificError(
				ILowpanInterface::ERROR_UNSPECIFIED,
				"Energy scan was already in progress"
			);
		}

		mEnergyScanListener = listener;
		mEnergyScanStatus = -1;

		mInterface.energyscan_start(value_map,
			boost::bind(
				&BinderILowpanInterface::onEnergyScanFinished,
				this,
				_1
			)
		);

		if (mEnergyScanStatus != -1) {
			ret = wpantund_status_to_binder_status(mEnergyScanStatus);
		} else {
			mEnergyScanListener = listener;
		}
	}

	return ret;
}

::android::binder::Status
BinderILowpanInterface::stopEnergyScan()
{
	CallbackArguments ret;

	{
		BinderIPCServerLock lock(mIpcServer);
		mInterface.energyscan_stop(CallbackCompletion(ret));
	}

	ret.wait();

	return ret.get_android_status();
}

Status BinderILowpanInterface::startCommissioningSession(const ::android::net::lowpan::LowpanBeaconInfo& beaconInfo) {
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

Status BinderILowpanInterface::closeCommissioningSession() {
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

Status BinderILowpanInterface::sendToCommissioner(const ::std::vector<uint8_t>& packet) {
	// TODO: Plumb this into wpantund.
	return wpantund_status_to_binder_status(kWPANTUNDStatus_FeatureNotImplemented);
}

void
BinderILowpanInterface::onPropertyChanged(const std::string& key, const boost::any& value)
{
	std::set<::android::sp<::android::net::lowpan::ILowpanInterfaceListener>>::const_iterator iter;

	// DO NOT LOCK THE MAIN THEAD HERE. THIS IS A CALL FROM THE
	// MAIN THREAD INTO BINDER. LOCKING THE MAIN THREAD WILL CAUSE
	// A DEADLOCK.
	try {
		if (key == kWPANTUNDProperty_DaemonReadyForHostSleep) {
			// TODO: Have this effect the Android sleep system in some way.
			return;
		} else if (key == kWPANTUNDProperty_DaemonEnabled) {
			bool x = any_to_bool(value);
			for (iter = mListeners.begin(); iter != mListeners.end(); ++iter) {
				(*iter)->onEnabledChanged(x);
			}
		} else if (key == kWPANTUNDProperty_InterfaceUp) {
			bool x = any_to_bool(value);
			for (iter = mListeners.begin(); iter != mListeners.end(); ++iter) {
				(*iter)->onUpChanged(x);
			}
		} else if (key == kWPANTUNDProperty_NetworkIsConnected) {
			bool x = any_to_bool(value);
			for (iter = mListeners.begin(); iter != mListeners.end(); ++iter) {
				(*iter)->onConnectedChanged(x);
			}
		} else if (key == kWPANTUNDProperty_NCPState) {
			std::string x = ncp_state_to_lowpan_state(any_to_string(value));
			for (iter = mListeners.begin(); iter != mListeners.end(); ++iter) {
				(*iter)->onStateChanged(x);
			}
		} else if (key == kWPANTUNDProperty_NCPRole) {
			std::string x = any_to_string(value);
			for (iter = mListeners.begin(); iter != mListeners.end(); ++iter) {
				(*iter)->onRoleChanged(x);
			}
		} else if (key == kWPANTUNDProperty_InternalNetworkId) {
			LowpanIdentity x = any_to_lowpan_identity(value);
			for (iter = mListeners.begin(); iter != mListeners.end(); ++iter) {
				(*iter)->onLowpanIdentityChanged(x);
			}
		}
	} catch (boost::bad_any_cast x) {
		syslog(LOG_ERR, "BinderILowpanInterface::onPropertyChanged: Caught bad_any_cast exception for key \"%s\": \"%s\"", key.c_str(), x.what());
	} catch (std::invalid_argument x) {
		syslog(LOG_ERR, "BinderILowpanInterface::onPropertyChanged: Caught invalid_argument exception for key \"%s\": \"%s\"", key.c_str(), x.what());
	}

}

void
BinderILowpanInterface::onNetScanBeacon(const WPAN::NetworkInstance& network)
{
	// DO NOT LOCK THE MAIN THEAD HERE. THIS IS A CALL FROM THE
	// MAIN THREAD INTO BINDER. LOCKING THE MAIN THREAD WILL CAUSE
	// A DEADLOCK.

	if (mNetScanListener != NULL) {
		LowpanBeaconInfo::Builder builder;

		if (!network.name.empty()) {
			builder.setName(network.name);
		}

		if (network.get_xpanid_as_uint64() != 0) {
			builder.setXpanid(network.xpanid, sizeof(network.xpanid));
		}

		builder.setPanid(network.panid);

		if (network.type == 3) {
			builder.setType(ILowpanInterface::NETWORK_TYPE_THREAD_V1());
		} else if (network.type != 0) {
			builder.setType(ILowpanInterface::NETWORK_TYPE_UNKNOWN());
		}

		if (network.channel) {
			builder.setChannel(network.channel);
			builder.setRssi(network.rssi);
			builder.setLqi(network.lqi);
		}

		if (network.joinable) {
			builder.setFlag(LowpanBeaconInfo::FLAG_CAN_ASSIST);
		}

		if (network.get_hwaddr_as_uint64() != 0) {
			builder.setBeaconAddress(network.hwaddr, sizeof(network.hwaddr));
		}

		mNetScanListener->onNetScanBeacon(builder.build());
	}
}

void
BinderILowpanInterface::onEnergyScanResult(const EnergyScanResultEntry& entry)
{
	// DO NOT LOCK THE MAIN THEAD HERE. THIS IS A CALL FROM THE
	// MAIN THREAD INTO BINDER. LOCKING THE MAIN THREAD WILL CAUSE
	// A DEADLOCK.

	if (mEnergyScanListener != NULL) {
		mEnergyScanListener->onEnergyScanResult(
			(int32_t)entry.mChannel,
			(int32_t)entry.mMaxRssi
		);
	}
}
