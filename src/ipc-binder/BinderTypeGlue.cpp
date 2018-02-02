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
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * This file contains all of the type conversion glue necessary
 * for ipc-binder to work smoothly.
 *
 * This file is necessary because wpantund requires RTTI, but
 * libandroid_net_lowpan requires RTTI to be turned off. This file
 * is how we get around this: All conversions which need RTTI are in
 * this file, whereas the rest of the ipc-binder plug-in has RTTI
 * turned off. This is the only place in ipc-binder that you can
 * safely do a boost::cast_any for example.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include "assert-macros.h"
#include "BinderTypeGlue.h"

#include <syslog.h>
#include <utils/String8.h>
#include "NilReturn.h"
#include "NCPTypes.h"
#include "NetworkInstance.h"
#include "ValueMap.h"
#include "any-to.h"
#include "wpan-error.h"
#include "wpan-properties.h"
#include "IPv6Helpers.h"
#include <android/net/lowpan/ILowpanInterface.h>
#include <binder/IpPrefix.h>

using namespace android;
using namespace android::binder;
using namespace nl;
using namespace nl::wpantund;

using ::android::binder::Map;
using ::android::binder::Status;
using ::android::binder::Value;
using ::android::net::IpPrefix;
using ::android::net::lowpan::ILowpanInterface;
using ::android::net::lowpan::LowpanBeaconInfo;
using ::android::net::lowpan::LowpanChannelInfo;
using ::android::net::lowpan::LowpanCredential;
using ::android::net::lowpan::LowpanIdentity;
using ::android::net::lowpan::LowpanProvision;
using ::android::String16;
using ::android::String8;
using ::boost::any;
using ::std::map;
using ::std::string;
using ::std::vector;

CallbackArguments::CallbackArguments():
	mStatus(kWPANTUNDStatus_Ok), mDidFinish(false)
{
	pthread_cond_init(&mCond, NULL);
	pthread_mutex_init(&mMutex, NULL);
}

CallbackArguments::~CallbackArguments() {
	pthread_cond_destroy(&mCond);
	pthread_mutex_destroy(&mMutex);
}

::android::binder::Status
CallbackArguments::get_android_status()
{
	return wpantund_status_to_binder_status(mStatus);
}

void
CallbackArguments::wait()
{
	pthread_mutex_lock(&mMutex);

	while (!mDidFinish) {
		pthread_cond_wait(&mCond, &mMutex);
	}

	pthread_mutex_unlock(&mMutex);
}

void
CallbackArguments::finish()
{
	pthread_mutex_lock(&mMutex);
	mDidFinish = true;
	pthread_cond_signal(&mCond);
	pthread_mutex_unlock(&mMutex);
}

CallbackCompletion::CallbackCompletion(CallbackArguments &args): mArguments(args)
{
}

void
CallbackCompletion::operator()(void)
{
	mArguments.mStatus = 0;
	mArguments.finish();
}

void
CallbackCompletion::operator()(int status)
{
	mArguments.mStatus = status;
	mArguments.finish();
}

::android::net::lowpan::LowpanIdentity
nl::wpantund::any_to_lowpan_identity(const ::boost::any& value) {
	::android::net::lowpan::LowpanIdentity::Builder builder;
	::nl::wpantund::WPAN::NetworkId networkId = boost::any_cast<::nl::wpantund::WPAN::NetworkId>(value);

	builder.setName(networkId.name);
	builder.setXpanid(networkId.xpanid, sizeof(networkId.xpanid));

	return builder.build();
}

void
CallbackCompletion::operator()(int status, const boost::any& value)
{
	mArguments.mStatus = status;
	mArguments.mValue = value;
	mArguments.finish();
}

any
nl::wpantund::cast_to_any(const ::android::binder::Value& value)
{
	any ret;

	if (value.isBoolean()) {
		bool x;
		require(value.getBoolean(&x), bail);
		ret = x;

	} else if (value.isInt()) {
		int32_t x;
		require(value.getInt(&x), bail);
		ret = x;

	} else if (value.isByte()) {
		int8_t x;
		require(value.getByte(&x), bail);
		ret = x;

	} else if (value.isLong()) {
		int64_t x;
		require(value.getLong(&x), bail);
		ret = x;

	} else if (value.isDouble()) {
		double x;
		require(value.getDouble(&x), bail);
		ret = x;

	} else if (value.isString()) {
		String16 x;
		require(value.getString(&x), bail);
		ret = std::string(String8(x).string());

	} else if (value.isBooleanVector()) {
		std::vector<bool> x;
		require(value.getBooleanVector(&x), bail);
		ret = x;

	} else if (value.isByteVector()) {
		nl::Data x;
		require(value.getByteVector(&x), bail);
		ret = x;

	} else if (value.isIntVector()) {
		std::vector<int32_t> x;
		require(value.getIntVector(&x), bail);
		ret = x;

	} else if (value.isLongVector()) {
		std::vector<int64_t> x;
		require(value.getLongVector(&x), bail);
		ret = x;

	} else if (value.isDoubleVector()) {
		std::vector<double> x;
		require(value.getDoubleVector(&x), bail);
		ret = x;

	} else if (value.isStringVector()) {
		std::vector<String16> x;
		std::vector<std::string> y;
		std::vector<String16>::const_iterator iter;

		require(value.getStringVector(&x), bail);

		// Convert the std::vector<String16>
		// to a std::vector<std::string>
		for (iter = x.begin(); iter != x.end(); ++iter) {
			y.push_back(String8(*iter).string());
		}

		ret = y;

	} else if (value.empty()) {
		// This is the "NULL" case, which we treat
		// as an empty any. We could leave this line
		// out, but we are keeping it in to remain
		// explicit about what is happening.
		ret = any();

	} else {
		syslog(LOG_ERR, "cast_to_any: Unsupported parcelType %d!", value.parcelType());

		throw std::invalid_argument("Unsupported type");
	}

bail:
	return ret;
}

void
nl::wpantund::convert_any_to_link_addresses(std::vector<std::string>* link_addresses, const any& value)
{
	std::map<struct in6_addr, GlobalAddressEntry> address_table = boost::any_cast<std::map<struct in6_addr, GlobalAddressEntry>>(value);
	std::map<struct in6_addr, GlobalAddressEntry>::const_iterator iter, end = address_table.end();

	for (iter = address_table.begin(); iter != end; ++iter) {
		link_addresses->push_back(in6_addr_to_string(iter->first) + "/64");
	}
}

void
nl::wpantund::convert_any_to_link_networks(std::vector<IpPrefix>* link_addresses, const any& value)
{
	std::list<LinkRoute> route_table = boost::any_cast<std::list<LinkRoute>>(value);
	std::list<LinkRoute>::const_iterator iter, end = route_table.end();

	for (iter = route_table.begin(); iter != end; ++iter) {
		link_addresses->push_back(IpPrefix(iter->mPrefix, iter->mPrefixLen));
	}
}

std::string
nl::wpantund::ncp_state_to_lowpan_state(const ::std::string& ncp_state)
{
	std::string ret;

	if (ncp_state == kWPANTUNDStateCredentialsNeeded) {
		ret = String8(ILowpanInterface::STATE_COMMISSIONING()).string();
	} else if (ncp_state == kWPANTUNDStateFault) {
		ret = String8(ILowpanInterface::STATE_FAULT()).string();
	} else if (ncp_state.compare(0, sizeof(kWPANTUNDStateUninitialized) - 1, kWPANTUNDStateUninitialized) == 0) {
		ret = String8(ILowpanInterface::STATE_OFFLINE()).string();
	} else if (ncp_state.compare(0, sizeof(kWPANTUNDStateOffline) - 1, kWPANTUNDStateOffline) == 0) {
		ret = String8(ILowpanInterface::STATE_OFFLINE()).string();
	} else if (ncp_state.compare(0, sizeof(kWPANTUNDStateAssociating) - 1, kWPANTUNDStateAssociating) == 0) {
		ret = String8(ILowpanInterface::STATE_ATTACHING()).string();
	} else if (ncp_state.compare(0, sizeof(kWPANTUNDStateAssociated) - 1, kWPANTUNDStateAssociated) == 0) {
		ret = String8(ILowpanInterface::STATE_ATTACHED()).string();
	} else {
		syslog(LOG_ERR, "ncp_state_to_lowpan_state: Unknown NCP state \"%s\", using FAULT", ncp_state.c_str());
		ret = String8(ILowpanInterface::STATE_FAULT()).string();
	}

	return ret;
}

Value
nl::wpantund::cast_to_binder_value(const any& value)
{
	Value ret;

	if (value.type() == typeid(std::string)) {
		std::string v = boost::any_cast<std::string>(value);
		const char* cstr = v.c_str();
		ret = String16(cstr);

	} else if (value.type() == typeid(char*)) {
		const char* cstr = boost::any_cast<char*>(value);
		ret = String16(cstr);

	} else if (value.type() == typeid(bool)) {
		ret = boost::any_cast<bool>(value);

	} else if (value.type() == typeid(uint8_t)) {
		ret = (int32_t)boost::any_cast<uint8_t>(value);

	} else if (value.type() == typeid(int8_t)) {
		ret = (int32_t)boost::any_cast<int8_t>(value);

	} else if (value.type() == typeid(uint16_t)) {
		ret = (int32_t)boost::any_cast<uint16_t>(value);

	} else if (value.type() == typeid(int16_t)) {
		ret = (int32_t)boost::any_cast<int16_t>(value);

	} else if (value.type() == typeid(uint32_t)) {
		// Not an ideal cast, but without unsigned
		// types in Value, not much else we can do.
		ret = (int64_t)boost::any_cast<uint32_t>(value);

	} else if (value.type() == typeid(int32_t)) {
		ret = boost::any_cast<int32_t>(value);

	} else if (value.type() == typeid(uint64_t)) {

		// Not an ideal cast, but without unsigned
		// types in Value, not much else we can do.
		ret = (int64_t)boost::any_cast<uint64_t>(value);

	} else if (value.type() == typeid(int64_t)) {
		ret = boost::any_cast<int64_t>(value);

	} else if (value.type() == typeid(double)) {
		ret = boost::any_cast<double>(value);

	} else if (value.type() == typeid(float)) {
		ret = (float)boost::any_cast<double>(value);

	} else if (value.type() == typeid(std::list<std::string>)) {
		const std::list<std::string>& list_of_strings =
			boost::any_cast< std::list<std::string> >(value);
		std::list<std::string>::const_iterator list_iter;
		std::vector<String16> x;

		for (list_iter = list_of_strings.begin();
			 list_iter != list_of_strings.end();
			 list_iter++) {
			const char* cstr = list_iter->c_str();
			x.push_back(String16(cstr));
		}

		ret = x;

	} else if (value.type() == typeid(std::set<std::string>)) {
		const std::set<std::string>& set_of_strings =
			boost::any_cast< std::set<std::string> >(value);
		std::set<std::string>::const_iterator set_iter;
		std::vector<String16> x;

		for (set_iter = set_of_strings.begin();
			 set_iter != set_of_strings.end();
			 set_iter++) {
			const char* cstr = set_iter->c_str();
			x.push_back(String16(cstr));
		}

		ret = x;

	} else if (value.type() == typeid(nl::Data)) {
		ret = static_cast<std::vector<uint8_t> >(boost::any_cast<nl::Data>(value));

	} else if (value.type() == typeid(std::vector<uint8_t>)) {
		ret = boost::any_cast<std::vector<uint8_t> >(value);

	} else if (value.type() == typeid(std::set<int>)) {
		const std::set<int>& container =
			boost::any_cast< std::set<int> >(value);
		std::set<int>::const_iterator container_iter;
		std::vector<int32_t> x;

		for (container_iter = container.begin();
			 container_iter != container.end();
			 container_iter++) {
			x.push_back(*container_iter);
		}

		ret = x;

	} else if (value.empty()) {
		// This is the "NULL" case, which we treat
		// as an empty Value. We could leave this line
		// out, but we are keeping it in to remain
		// explicit about what is happening.
		ret = Value();

	} else {
		syslog(LOG_ERR, "cast_to_binder_value: Unsupported type \"%s\"!", value.type().name());
		throw std::invalid_argument("Unsupported type");
	}

	return ret;
}

static const char kWpantundPropertyPrefix[] = "org.wpantund.";

int32_t
nl::wpantund::wpantund_status_to_service_code(int status)
{
	static std::map<int, int32_t> *map = NULL;
	std::map<int, int32_t>::const_iterator iter;

	if (map == NULL) {
		static std::map<int, int32_t> *newMap = new std::map<int, int32_t>();

		(*newMap)[kWPANTUNDStatus_Failure] = ILowpanInterface::ERROR_UNSPECIFIED;
		(*newMap)[kWPANTUNDStatus_InvalidArgument] = ILowpanInterface::ERROR_INVALID_ARGUMENT;
		(*newMap)[kWPANTUNDStatus_InvalidWhenDisabled] = ILowpanInterface::ERROR_DISABLED;
		(*newMap)[kWPANTUNDStatus_InvalidForCurrentState] = ILowpanInterface::ERROR_WRONG_STATE;
		(*newMap)[kWPANTUNDStatus_InvalidType] = ILowpanInterface::ERROR_INVALID_ARGUMENT;
		(*newMap)[kWPANTUNDStatus_InvalidRange] = ILowpanInterface::ERROR_INVALID_ARGUMENT;
		(*newMap)[kWPANTUNDStatus_Timeout] = ILowpanInterface::ERROR_TIMEOUT;
		(*newMap)[kWPANTUNDStatus_SocketReset] = ILowpanInterface::ERROR_IO_FAILURE;
		(*newMap)[kWPANTUNDStatus_Busy] = ILowpanInterface::ERROR_BUSY;
		(*newMap)[kWPANTUNDStatus_Already] = ILowpanInterface::ERROR_ALREADY;
		(*newMap)[kWPANTUNDStatus_Canceled] = ILowpanInterface::ERROR_CANCELED;
		(*newMap)[kWPANTUNDStatus_FeatureNotSupported] = ILowpanInterface::ERROR_FEATURE_NOT_SUPPORTED;
		(*newMap)[kWPANTUNDStatus_FeatureNotImplemented] = ILowpanInterface::ERROR_FEATURE_NOT_SUPPORTED;
		(*newMap)[kWPANTUNDStatus_PropertyNotFound] = ILowpanInterface::ERROR_FEATURE_NOT_SUPPORTED;
		(*newMap)[kWPANTUNDStatus_JoinFailedUnknown] = ILowpanInterface::ERROR_JOIN_FAILED_UNKNOWN;
		(*newMap)[kWPANTUNDStatus_JoinFailedAtScan] = ILowpanInterface::ERROR_JOIN_FAILED_AT_SCAN;
		(*newMap)[kWPANTUNDStatus_JoinFailedAtAuthenticate] = ILowpanInterface::ERROR_JOIN_FAILED_AT_AUTH;
		(*newMap)[kWPANTUNDStatus_FormFailedAtScan] = ILowpanInterface::ERROR_FORM_FAILED_AT_SCAN;
		(*newMap)[kWPANTUNDStatus_NCP_Crashed] = ILowpanInterface::ERROR_NCP_PROBLEM;
		(*newMap)[kWPANTUNDStatus_NCP_Fatal] = ILowpanInterface::ERROR_NCP_PROBLEM;
		(*newMap)[kWPANTUNDStatus_NCP_InvalidArgument] = ILowpanInterface::ERROR_NCP_PROBLEM;
		(*newMap)[kWPANTUNDStatus_NCP_InvalidRange] = ILowpanInterface::ERROR_NCP_PROBLEM;
		(*newMap)[kWPANTUNDStatus_NCP_Reset] = ILowpanInterface::ERROR_NCP_PROBLEM;

		map = newMap;
	}

	iter = map->find(status);
	if (iter != map->end()) {
		return iter->second;
	}

	if (WPANTUND_STATUS_IS_NCPERROR(status)) {
		return ILowpanInterface::ERROR_NCP_PROBLEM;
	}

	return ILowpanInterface::ERROR_UNSPECIFIED;
}

Status
nl::wpantund::wpantund_status_to_binder_status(int status)
{
	if (status == kWPANTUNDStatus_Ok) {
		return Status::ok();
	}

	return Status::fromServiceSpecificError(
		wpantund_status_to_service_code(status),
		wpantund_status_to_cstr(status)
	);
}

static std::string
lowpan_property_to_wpantund_property(const std::string& lowpanProperty)
{
	static std::map<std::string, std::string> *map = NULL;
	std::map<std::string, std::string>::const_iterator iter;

	if (map == NULL) {
		static std::map<std::string, std::string> *newMap
				= new std::map<std::string, std::string>();

#define MAP_KEY(w,l) (*newMap)[String8(ILowpanInterface::l()).string()] = w
		MAP_KEY(kWPANTUNDProperty_NCPChannelMask, KEY_CHANNEL_MASK);
		MAP_KEY(kWPANTUNDProperty_NCPTXPower, KEY_MAX_TX_POWER);
#undef MAP_KEY

		map = newMap;
	}

	iter = map->find(lowpanProperty);
	if (iter != map->end()) {
		return iter->second;
	}

	if (0 == lowpanProperty.compare(0, sizeof(kWpantundPropertyPrefix)-1, kWpantundPropertyPrefix)) {
		return lowpanProperty.substr(sizeof(kWpantundPropertyPrefix)-1);
	}

	syslog(LOG_INFO, "lowpan_property_to_wpantund_property: Can't convert \"%s\" to a wpantund equivalent", lowpanProperty.c_str());

	return lowpanProperty;
}

ValueMap
nl::wpantund::cast_to_value_map(const Map& params)
{
	ValueMap ret;
	Map::const_iterator iter;

	for (iter = params.begin(); iter != params.end(); ++iter) {
		std::string key = lowpan_property_to_wpantund_property(iter->first);
		boost::any value = cast_to_any(iter->second);

		ret[key] = value;
	}

	return ret;
}

Status
nl::wpantund::add_to_value_map(ValueMap& valueMap, const ::android::net::lowpan::LowpanIdentity& identity)
{
	std::string tmpString;
	nl::Data tmpByteVector;
	int32_t tmpInt32;;

	if (identity.getName(&tmpString)) {
		valueMap[kWPANTUNDProperty_NetworkName] = tmpString;
	}

	if (identity.getType(&tmpString) && !tmpString.empty()) {
		valueMap[kWPANTUNDProperty_NetworkType] = tmpString;
	}

	if (identity.getXpanid(&tmpByteVector) && !tmpByteVector.empty()) {
		valueMap[kWPANTUNDProperty_NetworkXPANID] = tmpByteVector;
	};

	tmpInt32 = identity.getPanid();
	if (tmpInt32 != LowpanIdentity::UNSPECIFIED_PANID) {
		valueMap[kWPANTUNDProperty_NetworkPANID] = tmpInt32;
	};

	tmpInt32 = identity.getChannel();
	if (tmpInt32 != LowpanIdentity::UNSPECIFIED_CHANNEL) {
		valueMap[kWPANTUNDProperty_NCPChannel] = tmpInt32;
	};

	return Status::ok();
}

Status
nl::wpantund::add_to_value_map(ValueMap& valueMap, const ::android::net::lowpan::LowpanCredential& credential)
{
	nl::Data masterKey;
	int32_t masterKeyIndex;

	if (credential.getMasterKey(&masterKey)) {
		valueMap[kWPANTUNDProperty_NetworkKey] = masterKey;

		masterKeyIndex = credential.getMasterKeyIndex();
		if (masterKeyIndex != LowpanCredential::UNSPECIFIED_MASTER_KEY_INDEX) {
			valueMap[kWPANTUNDProperty_NetworkKeyIndex] = masterKeyIndex;
		}
	} else {
		return Status::fromStatusT(::android::BAD_VALUE);
	}
	return Status::ok();
}

Status
nl::wpantund::add_to_value_map(ValueMap& valueMap, const ::android::net::lowpan::LowpanProvision& provision)
{
	Status ret = Status::fromStatusT(::android::BAD_VALUE);
	const LowpanIdentity* identity = provision.getLowpanIdentity();
	const LowpanCredential* credential = provision.getLowpanCredential();

	require(identity != NULL, bail);

	ret = add_to_value_map(valueMap, *identity);

	if (ret.isOk() && credential != NULL) {
		ret = add_to_value_map(valueMap, *credential);
	}

bail:
	return ret;
}
