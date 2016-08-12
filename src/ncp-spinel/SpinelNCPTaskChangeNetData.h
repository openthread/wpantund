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

#ifndef __wpantund__SpinelNCPTaskChangeNetData__
#define __wpantund__SpinelNCPTaskChangeNetData__

#include <list>
#include "SpinelNCPTask.h"
#include "SpinelNCPInstance.h"
#include "ValueMap.h"

using namespace nl;
using namespace nl::wpantund;

namespace nl {
namespace wpantund {

class SpinelNCPTaskChangeNetData : public SpinelNCPTask
{
public:
	SpinelNCPTaskChangeNetData(
		SpinelNCPInstance* instance,
		CallbackWithStatusArg1 cb,
		const Data& change_net_data_command,
		int timeout = NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT
	);

	SpinelNCPTaskChangeNetData(
		SpinelNCPInstance* instance,
		CallbackWithStatusArg1 cb,
		const std::list<Data>& change_net_data_commands,
		int timeout = NCP_DEFAULT_COMMAND_RESPONSE_TIMEOUT
	);

	virtual int vprocess_event(int event, va_list args);

private:
	std::list<Data> mChangeNetDataCommands;
	std::list<Data>::const_iterator mCommandIter;
	int mRetVal;
};

}; // namespace wpantund
}; // namespace nl


#endif /* defined(__wpantund__SpinelNCPTaskChangeNetData__) */
