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
 */

#ifndef BINDER_TYPE_GLUE_HEADER_INCLUDED
#define BINDER_TYPE_GLUE_HEADER_INCLUDED

#include "Callbacks.h"
#include "ValueMap.h"
#include "IPv6Helpers.h"
#include <binder/Value.h>
#include <utils/String16.h>
#include <map>
#include <boost/any.hpp>
#include <binder/Status.h>
#include <binder/Map.h>
#include <boost/bind.hpp>
#include <binder/IpPrefix.h>
#include <pthread.h>
#include <android/net/lowpan/LowpanIdentity.h>
#include <android/net/lowpan/LowpanProvision.h>
#include <android/net/lowpan/LowpanBeaconInfo.h>
#include <android/net/lowpan/LowpanChannelInfo.h>
#include <android/net/lowpan/LowpanCredential.h>

namespace nl {
namespace wpantund {

struct CallbackArguments {
public:
	CallbackArguments();
	~CallbackArguments();
	::android::binder::Status get_android_status();
	void wait();
	void finish();

public:
	volatile int mStatus;
	volatile bool mDidFinish;
	::boost::any mValue;

private:
	pthread_cond_t mCond;
	pthread_mutex_t mMutex;
};

class CallbackCompletion {
public:
	CallbackCompletion(CallbackArguments &args);

	void operator()(void);
	void operator()(int status);
	void operator()(int status, const boost::any& value);

private:
	CallbackArguments &mArguments;
};

/** Converts a binder value object into a boost any object. */
::boost::any cast_to_any(const ::android::binder::Value& value);

/** Converts a boost any object into a binder object. */
::android::binder::Value cast_to_binder_value(const ::boost::any& value);

ValueMap cast_to_value_map(const ::android::binder::Map& parameters);

::android::net::lowpan::LowpanIdentity any_to_lowpan_identity(const ::boost::any& value);

std::string ncp_state_to_lowpan_state(const ::std::string& ncpState);

::android::binder::Status add_to_value_map(ValueMap& valueMap, const ::android::net::lowpan::LowpanIdentity& identity);
::android::binder::Status add_to_value_map(ValueMap& valueMap, const ::android::net::lowpan::LowpanCredential& credential);
::android::binder::Status add_to_value_map(ValueMap& valueMap, const ::android::net::lowpan::LowpanProvision& provision);

int32_t wpantund_status_to_service_code(int status);
::android::binder::Status wpantund_status_to_binder_status(int status);

void convert_any_to_link_addresses(std::vector<std::string>* link_addresses, const ::boost::any& value);
void convert_any_to_link_networks(std::vector<::android::net::IpPrefix>* link_addresses, const ::boost::any& value);

}; // namespace wpantund
}; // namespace nl

#endif // ifndef BINDER_TYPE_GLUE_HEADER_INCLUDED
