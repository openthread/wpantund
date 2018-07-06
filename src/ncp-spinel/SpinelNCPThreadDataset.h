/*
 *
 * Copyright (c) 2017 Nest Labs, Inc.
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

#ifndef __wpantund__SpinelNCPThreadDataset__
#define __wpantund__SpinelNCPThreadDataset__

#include "spinel.h"
#include "ValueMap.h"

using namespace nl;
using namespace nl::wpantund;

namespace nl {
namespace wpantund {

class ThreadDataset
{
public:
	template <typename Type>
	struct Optional
	{
	public:
		Optional(void): mValue(), mHasValue(false) { }

		void clear(void) { mHasValue = false; }
		bool has_value(void) const { return mHasValue; }
		const Type &get(void) const { return mValue; }
		void set(const Type &value) { mValue = value; mHasValue = true; }
		void operator=(const Type &value) { set(value); }

	private:
		Type mValue;
		bool mHasValue;
	};

	struct SecurityPolicy {
		uint16_t mKeyRotationTime;
		uint8_t  mFlags;
	};

	ThreadDataset(void) { clear(); }

	void clear(void);

	void convert_to_valuemap(ValueMap &map);
	void convert_to_string_list(std::list<std::string> &list);

	int  set_from_spinel_frame(const uint8_t *data_in, spinel_size_t data_len);
	void convert_to_spinel_frame(Data &frame, bool include_value = true);

	Optional<uint64_t>         mActiveTimestamp;
	Optional<uint64_t>         mPendingTimestamp;
	Optional<Data>             mMasterKey;
	Optional<std::string>      mNetworkName;
	Optional<Data>             mExtendedPanId;
	Optional<struct in6_addr>  mMeshLocalPrefix;
	Optional<uint32_t>         mDelay;
	Optional<uint16_t>         mPanId;
	Optional<uint8_t>          mChannel;
	Optional<Data>             mPSKc;
	Optional<uint32_t>         mChannelMaskPage0;
	Optional<SecurityPolicy>   mSecurityPolicy;
	Optional<Data>             mRawTlvs;
	Optional<struct in6_addr>  mDestIpAddress;

private:
	enum
	{
		kMeshLocalPrefixLen = 64,
	};

	int parse_dataset_entry(const uint8_t *data_in, spinel_size_t data_len);
};

}; // namespace wpantund
}; // namespace nl


#endif /* defined(__wpantund__SpinelNCPThreadDataset__) */
