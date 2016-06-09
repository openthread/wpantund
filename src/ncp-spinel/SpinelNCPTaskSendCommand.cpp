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
#include "SpinelNCPTaskSendCommand.h"
#include "SpinelNCPInstance.h"
#include "spinel-extra.h"

using namespace nl;
using namespace nl::wpantund;


nl::wpantund::SpinelNCPTaskSendCommand::SpinelNCPTaskSendCommand(
	SpinelNCPInstance* instance,
	CallbackWithStatusArg1 cb,
	const Data& send_command,
	int timeout,
	const std::string& packed_format
):	SpinelNCPTask(instance, cb), mPackedFormat(packed_format)
{
	mNextCommandTimeout = timeout;
	mNextCommand = send_command;
}

static boost::any
spinel_iter_to_any(spinel_datatype_iter_t *iter)
{
	boost::any ret;
	spinel_status_t status;

	switch(iter->pack_format[0]) {
	case SPINEL_DATATYPE_BOOL_C:
		{
			bool val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = val;
		}
		break;

	case SPINEL_DATATYPE_UINT8_C:
		{
			uint8_t val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = val;
		}
		break;

	case SPINEL_DATATYPE_INT8_C:
		{
			int8_t val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = (int)val;
		}
		break;

	case SPINEL_DATATYPE_UINT16_C:
		{
			uint16_t val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = val;
		}
		break;

	case SPINEL_DATATYPE_INT16_C:
		{
			int16_t val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = val;
		}
		break;

	case SPINEL_DATATYPE_UINT32_C:
		{
			uint32_t val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = val;
		}
		break;

	case SPINEL_DATATYPE_INT32_C:
		{
			int32_t val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = val;
		}
		break;

	case SPINEL_DATATYPE_UINT_PACKED_C:
		{
			unsigned int val(0);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = val;
		}
		break;

	case SPINEL_DATATYPE_IPv6ADDR_C:
		{
			const spinel_ipv6addr_t *val(NULL);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = in6_addr_to_string(*val);
		}
		break;

	case SPINEL_DATATYPE_EUI64_C:
		{
			const spinel_eui64_t *val(NULL);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = Data(val->bytes, sizeof(val->bytes));
		}
		break;

	case SPINEL_DATATYPE_EUI48_C:
		{
			const spinel_eui48_t *val(NULL);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = Data(val->bytes, sizeof(val->bytes));
		}
		break;

	case SPINEL_DATATYPE_DATA_C:
		{
			const uint8_t *val_ptr(NULL);
			spinel_size_t val_len;
			status = spinel_datatype_iter_unpack(iter, &val_ptr, &val_len);
			require_noerr(status, bail);
			ret = Data(val_ptr, val_len);
		}
		break;

	case SPINEL_DATATYPE_UTF8_C:
		{
			const char *val(NULL);
			status = spinel_datatype_iter_unpack(iter, &val);
			require_noerr(status, bail);
			ret = std::string(val);
		}
		break;

	case SPINEL_DATATYPE_STRUCT_C:
		goto bail;

	case SPINEL_DATATYPE_ARRAY_C:
		// TODO: Recursively parse this
		goto bail;

	default:
		goto bail;

	}

bail:
	return ret;
}

static boost::any
spinel_packed_to_any(const uint8_t* data_in, spinel_size_t data_len, const char* pack_format)
{
	spinel_datatype_iter_t spinel_iter = {};
	spinel_datatype_iter_start(&spinel_iter, data_in, data_len, pack_format);

	return spinel_iter_to_any(&spinel_iter);
}


int
nl::wpantund::SpinelNCPTaskSendCommand::vprocess_event(int event, va_list args)
{
	int ret = kWPANTUNDStatus_Failure;

	EH_BEGIN();

	// The first event to a task is EVENT_STARTING_TASK. The following
	// line makes sure that we don't start processing this task
	// until it is properly scheduled. All tasks immediately receive
	// the initial `EVENT_STARTING_TASK` event, but further events
	// will only be received by that task once it is that task's turn
	// to execute.
	EH_WAIT_UNTIL(EVENT_STARTING_TASK != event);

	require(mNextCommand.size() < sizeof(GetInstance(this)->mOutboundBuffer), on_error);

	EH_SPAWN(&mSubPT, vprocess_send_command(event, args));
	ret = mNextCommandRet;

	if (mPackedFormat.size()) {
		require_noerr(ret, on_error);

		require(EVENT_NCP_PROP_VALUE_IS == event, on_error);

		unsigned int key = va_arg(args, unsigned int);
		const uint8_t* data_in = va_arg(args, const uint8_t*);
		spinel_size_t data_len = va_arg_small(args, spinel_size_t);

		(void) key;

		ret = kWPANTUNDStatus_Ok;

		finish(ret, spinel_packed_to_any(data_in, data_len, mPackedFormat.c_str()));

		EH_EXIT();
	}

	finish(ret);

	EH_EXIT();

on_error:

	if (ret == kWPANTUNDStatus_Ok) {
		ret = kWPANTUNDStatus_Failure;
	}

	syslog(LOG_ERR, "SendCommand failed: %d", ret);

	finish(ret);

	EH_END();
}
