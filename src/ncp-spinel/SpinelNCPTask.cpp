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
#include <syslog.h>
#include <errno.h>
#include "SpinelNCPTask.h"
#include "SpinelNCPInstance.h"
#include "any-to.h"

using namespace nl;
using namespace nl::wpantund;

SpinelNCPTask::SpinelNCPTask(SpinelNCPInstance* _instance, CallbackWithStatusArg1 cb):
	mInstance(_instance), mCB(cb), mNextCommandTimeout(NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT)
{
}

SpinelNCPTask::~SpinelNCPTask()
{
	finish(kWPANTUNDStatus_Canceled);
}

void
SpinelNCPTask::finish(int status, const boost::any& value)
{
	if (!mCB.empty()) {
		mCB(status, value);
		mCB = CallbackWithStatusArg1();
	}
}

static bool
spinel_callback_is_reset(int event, va_list args)
{
	int status = peek_ncp_callback_status(event, args);
	return (status >= SPINEL_STATUS_RESET__BEGIN)
	    && (status < SPINEL_STATUS_RESET__END);
}

int
SpinelNCPTask::vprocess_send_command(int event, va_list args)
{
	EH_BEGIN_SUB(&mSubPT);

	require(mNextCommand.size() < sizeof(GetInstance(this)->mOutboundBuffer), on_error);

	CONTROL_REQUIRE_PREP_TO_SEND_COMMAND_WITHIN(NCP_DEFAULT_COMMAND_SEND_TIMEOUT, on_error);
	memcpy(GetInstance(this)->mOutboundBuffer, mNextCommand.data(), mNextCommand.size());
	GetInstance(this)->mOutboundBufferLen = static_cast<spinel_ssize_t>(mNextCommand.size());
	CONTROL_REQUIRE_OUTBOUND_BUFFER_FLUSHED_WITHIN(NCP_DEFAULT_COMMAND_SEND_TIMEOUT, on_error);

	if (mNextCommand[1] == SPINEL_CMD_RESET) {
		mInstance->mResetIsExpected = true;
		EH_REQUIRE_WITHIN(
			mNextCommandTimeout,
			IS_EVENT_FROM_NCP(event)
			  && ( (GetInstance(this)->mInboundHeader == mLastHeader)
			    || spinel_callback_is_reset(event, args)
			  ),
			on_error
		);
		mNextCommandRet = kWPANTUNDStatus_Ok;

	} else {
		CONTROL_REQUIRE_COMMAND_RESPONSE_WITHIN(mNextCommandTimeout, on_error);
		mNextCommandRet = peek_ncp_callback_status(event, args);
	}

	if (mNextCommandRet) {
		mNextCommandRet = spinel_status_to_wpantund_status(mNextCommandRet);
	}

	EH_EXIT();

on_error:
	mNextCommandRet = kWPANTUNDStatus_Timeout;

	EH_END();
}

nl::Data
nl::wpantund::SpinelPackData(const char* pack_format, ...)
{
	Data ret(64);

	va_list args;
	va_start(args, pack_format);

	do {
		spinel_ssize_t packed_size = spinel_datatype_vpack(ret.data(), (spinel_size_t)ret.size(), pack_format, args);

		if (packed_size < 0) {
			ret.clear();
		} else if (packed_size > ret.size()) {
			ret.resize(packed_size);
			continue;
		} else {
			ret.resize(packed_size);
		}
		break;
	} while(true);

	va_end(args);
	return ret;
}

int
nl::wpantund::SpinelAppendAny(nl::Data &frame, const boost::any &value, char pack_type)
{
	int ret = kWPANTUNDStatus_Ok;
	const char pack_format[2] = { pack_type, 0 };

	switch (pack_type) {
	case SPINEL_DATATYPE_BOOL_C:
		frame.append(SpinelPackData(pack_format, any_to_bool(value)));
		break;

	case SPINEL_DATATYPE_UINT8_C:
	case SPINEL_DATATYPE_INT8_C:
	case SPINEL_DATATYPE_UINT16_C:
	case SPINEL_DATATYPE_INT16_C:
	case SPINEL_DATATYPE_UINT32_C:
	case SPINEL_DATATYPE_INT32_C:
	case SPINEL_DATATYPE_UINT_PACKED_C:
		frame.append(SpinelPackData(pack_format, any_to_int(value)));
		break;

	case SPINEL_DATATYPE_INT64_C:
	case SPINEL_DATATYPE_UINT64_C:
		frame.append(SpinelPackData(pack_format, any_to_uint64(value)));
		break;

	case SPINEL_DATATYPE_IPv6ADDR_C:
	{
		struct in6_addr addr = any_to_ipv6(value);
		frame.append(SpinelPackData(pack_format, &addr));
		break;
	}

	case SPINEL_DATATYPE_EUI64_C:
	{
		Data eui64 = any_to_data(value);
		if (eui64.size() == sizeof(spinel_eui64_t)) {
			frame.append(SpinelPackData(pack_format, eui64.data()));
		} else {
			ret = kWPANTUNDStatus_InvalidArgument;
		}
		break;
	}

	case SPINEL_DATATYPE_EUI48_C:
	{
		Data eui48 = any_to_data(value);
		if (eui48.size() == sizeof(spinel_eui48_t)) {
			frame.append(SpinelPackData(pack_format, eui48.data()));
		} else {
			ret = kWPANTUNDStatus_InvalidArgument;
		}
		break;
	}

	case SPINEL_DATATYPE_DATA_WLEN_C:
	case SPINEL_DATATYPE_DATA_C:
	{
		Data data = any_to_data(value);
		frame.append(SpinelPackData(pack_format, data.data(), data.size()));
		break;
	}

	case SPINEL_DATATYPE_UTF8_C:
		frame.append(SpinelPackData(pack_format, any_to_string(value).c_str()));
		break;

	case SPINEL_DATATYPE_STRUCT_C:
	case SPINEL_DATATYPE_ARRAY_C:
	default:
		ret = kWPANTUNDStatus_FeatureNotSupported;
		break;
	}

	return ret;
}
