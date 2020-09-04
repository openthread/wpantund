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

#include "time-utils.h"

#if USE_BOOST_CHRONO_MONOTONIC_TIME
#include <boost/chrono.hpp>

extern "C" uint64_t time_get_monotonic_us() {
	return boost::chrono::duration_cast<boost::chrono::microseconds>(
		boost::chrono::steady_clock::now().time_since_epoch())
			.count();
}
#endif // USE_BOOST_CHRONO_MONOTONIC_TIME
