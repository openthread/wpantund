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

#ifndef __wpantund__SpinelNCPTaskSendCommand__
#define __wpantund__SpinelNCPTaskSendCommand__

#include "SpinelNCPTask.h"

using namespace nl;
using namespace nl::wpantund;

namespace nl {
namespace wpantund {

class SpinelNCPInstance;

class SpinelNCPTaskSendCommand : public SpinelNCPTask
{
public:
	typedef boost::function<int (const uint8_t*, spinel_size_t, boost::any&)> ReplyUnpacker;
	typedef boost::function<bool ()> CheckHandler;

	class Factory {
	public:

		friend class SpinelNCPTaskSendCommand;

		Factory(SpinelNCPInstance* instance);

		Factory& set_callback(const CallbackWithStatusArg1 &cb);
		Factory& set_callback(const CallbackWithStatus &cb);
		Factory& add_command(const Data& command);
		Factory& set_timeout(int timeout);

		/* For simple (single type) reply formats, we can use the
		 * `set_reply_format()` and specify the spinel packing format.
		 * For more complicated reply format (e.g., multiple types, structs)
		 * a `ReplyUnpakcer` function pointer can be specified using
		 * `set_reply_unpacker()` which is then used to decode/unpack
		 * the reply spinel message into a `boost::any` output result.
		 */
		Factory& set_reply_format(const std::string& packed_format);
		Factory& set_reply_unpacker(const ReplyUnpacker &reply_unpacker);

		Factory& set_lock_property(int lock_property);

		/* The caller can optionally set a final check handler.
		 * If provided, the task will wait for the given amount
		 * of timeout for the check handler call returning `true`.
		 *
		 */
		Factory& set_final_check(const CheckHandler &handler, int timeout = NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT);

		boost::shared_ptr<SpinelNCPTask> finish(void);

	private:
		SpinelNCPInstance* mInstance;
		CallbackWithStatusArg1 mCb;
		std::list<Data> mCommandList;
		int mTimeout;
		ReplyUnpacker mReplyUnpacker;
		int mLockProperty;
		CheckHandler mCheckHandler;
		int mCheckTimeout;
	};

	SpinelNCPTaskSendCommand(const Factory& factory);

	virtual int vprocess_event(int event, va_list args);

private:

	std::list<Data> mCommandList;
	std::list<Data>::const_iterator mCommandIter;
	int mLockProperty;
	ReplyUnpacker mReplyUnpacker;
	CheckHandler mCheckHandler;
	int mCheckTimeout;
	int mRetVal;
	boost::any mReturnValue;
};

}; // namespace wpantund
}; // namespace nl


#endif /* defined(__wpantund__SpinelNCPTaskSendCommand__) */
