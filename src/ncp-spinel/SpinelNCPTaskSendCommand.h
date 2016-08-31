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
#include "SpinelNCPInstance.h"

using namespace nl;
using namespace nl::wpantund;

namespace nl {
namespace wpantund {

class SpinelNCPTaskSendCommand : public SpinelNCPTask
{
public:
	SpinelNCPTaskSendCommand(SpinelNCPInstance* instance,
		CallbackWithStatusArg1 cb,
		const Data& send_command,
		int timeout = NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT,
		const std::string& packed_format = SPINEL_DATATYPE_NULL_S
	);

	virtual int vprocess_event(int event, va_list args);

private:
	std::string mPackedFormat;
};

}; // namespace wpantund
}; // namespace nl


#endif /* defined(__wpantund__SpinelNCPTaskSendCommand__) */
