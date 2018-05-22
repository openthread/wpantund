/*
 *
 * Copyright (c) 2018 Nest Labs, Inc.
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

#ifndef __wpantund__SpinelNCPVendorCustom__
#define __wpantund__SpinelNCPVendorCustom__

#include "NCPInstanceBase.h"
#include "SpinelNCPThreadDataset.h"
#include "nlpt.h"
#include "SocketWrapper.h"
#include "SocketAsyncOp.h"
#include "ValueMap.h"

#include <queue>
#include <set>
#include <map>
#include <errno.h>
#include "spinel.h"

namespace nl {
namespace wpantund {

class SpinelNCPInstance;

class SpinelNCPVendorCustom {
	friend class SpinelNCPInstance;
	friend class SpinelNCPTask;
	friend class SpinelNCPTaskSendCommand;

public:
	SpinelNCPVendorCustom(SpinelNCPInstance* instance);

	virtual ~SpinelNCPVendorCustom();

	static bool setup_property_supported_by_class(const std::string& prop_name);

	const std::set<std::string>& get_supported_property_keys()const;
	bool is_property_key_supported(const std::string& key)const;

	void property_get_value(const std::string& key, CallbackWithStatusArg1 cb);
	void property_set_value(const std::string& key, const boost::any& value, CallbackWithStatus cb);
	void property_insert_value(const std::string& key, const boost::any& value, CallbackWithStatus cb);
	void property_remove_value(const std::string& key, const boost::any& value, CallbackWithStatus cb);

	cms_t get_ms_to_next_event(void);

	void process(void);

private:
	SpinelNCPInstance *mInstance;
	std::set<std::string> mSupportedProperties;
}; // class SpinelNCPVendorCustom


}; // namespace wpantund
}; // namespace nl

#endif /* defined(__wpantund__SpinelNCPVendorCustom__) */
