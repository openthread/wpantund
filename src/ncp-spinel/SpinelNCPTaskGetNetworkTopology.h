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

#ifndef __wpantund__SpinelNCPTaskGetNetworkTopology__
#define __wpantund__SpinelNCPTaskGetNetworkTopology__

#include <list>
#include <string>
#include "ValueMap.h"
#include "IPv6Helpers.h"
#include "SpinelNCPTask.h"
#include "SpinelNCPInstance.h"

using namespace nl;
using namespace nl::wpantund;

namespace nl {
namespace wpantund {

class SpinelNCPTaskGetNetworkTopology : public SpinelNCPTask
{
public:

	enum Type
	{
		kChildTable,                   // Get the child table
		kChildTableAddresses,          // Get the child table addresses (including registered IPv6 addresses)
		kNeighborTable,                // Get the neighbor table
		kRouterTable,                  // Get the router table
		kNeighborTableErrorRates,      // Get the neighbor's (frame/message) error rates
	};

	enum ResultFormat
	{
		kResultFormat_StringArray,     // Returns the child/neighbor table as an array of std::string(s) (one per child).
		kResultFormat_ValueMapArray,   // Returns the child/neighbor table as an array of ValueMap dictionary.
	};

	enum
	{
		kThreadMode_RxOnWhenIdle        = (1 << 3),
		kThreadMode_SecureDataRequest   = (1 << 2),
		kThreadMode_FullFunctionDevice  = (1 << 1),
		kThreadMode_FullNetworkData     = (1 << 0),
	};

	// This struct defines a common table entry to store a child info (or child addresses info), a neighbor info, or a
	// router info.
	struct TableEntry
	{
		Type      mType;

		// Common fields for all types
		uint8_t   mExtAddress[8];
		uint16_t  mRloc16;

		// Common fields for child info, neighbor info, and router info
		uint32_t  mAge;
		uint8_t   mLinkQualityIn;

		// Common fields for both child info and neighbor info
		int8_t    mAverageRssi;
		int8_t    mLastRssi;
		bool      mRxOnWhenIdle : 1;
		bool      mSecureDataRequest : 1;
		bool      mFullFunction : 1;
		bool      mFullNetworkData : 1;

		// Child info only
		uint32_t  mTimeout;
		uint8_t   mNetworkDataVersion;

		// Neighbor info only
		uint32_t  mLinkFrameCounter;
		uint32_t  mMleFrameCounter;
		bool      mIsChild : 1;

		// Router info only
		uint8_t   mRouterId;
		uint8_t   mNextHop;
		uint8_t   mPathCost;
		uint8_t   mLinkQualityOut;
		bool      mLinkEstablished : 1;

		// Child info addresses only
		std::list<struct in6_addr> mIPv6Addresses;

		// Neighbor info error rate only
		uint16_t mFrameErrorRate;
		uint16_t mMessageErrorRate;

	public:
		TableEntry(void);

		void clear(void);
		std::string get_as_string(void);
		ValueMap get_as_valuemap(void) const;
	};

	typedef std::list<TableEntry> Table;

public:
	SpinelNCPTaskGetNetworkTopology(
		SpinelNCPInstance *instance,
		CallbackWithStatusArg1 cb,
		Type table_type = kChildTable,
		ResultFormat result_format = kResultFormat_StringArray
	);
	virtual int vprocess_event(int event, va_list args);

	// Parse a single child/neighbor/router entry and update the passed-in `TableEntry`
	static int parse_child_entry(const uint8_t *data_in, spinel_size_t data_len, TableEntry& child_info);
	static int parse_child_addresses_entry(const uint8_t *data_in, spinel_size_t data_len, TableEntry& child_addr_info);
	static int parse_neighbor_entry(const uint8_t *data_in, spinel_size_t data_len, TableEntry& neighbor_info);
	static int parse_neighbor_error_rates_entry(const uint8_t *data_in, spinel_size_t data_len, TableEntry& neighbor_err_rates_info);
	static int parse_router_entry(const uint8_t *data_in, spinel_size_t data_len, TableEntry& router_info);

	// Parse the spinel child/neighbor/router table property and updates the passed-in `Table`

	static int parse_child_table(const uint8_t *data_in, spinel_size_t data_len, Table& child_table);
	static int parse_child_addresses_table(const uint8_t *data_in, spinel_size_t data_len, Table& child_addr_table);
	static int parse_neighbor_table(const uint8_t *data_in, spinel_size_t data_len, Table& neighbor_table);
	static int prase_neighbor_error_rates_table(const uint8_t *data_in, spinel_size_t data_len, Table& neighbor_err_rate_table);
	static int parse_router_table(const uint8_t *data_in, spinel_size_t data_len, Table& router_table);

private:
	static int parse_table(Type type, const uint8_t *data_in, spinel_size_t data_len, Table& table);
	static unsigned int property_key_for_type(Type type);

	Type mType;
	Table mTable;
	ResultFormat mResultFormat;
};


}; // namespace wpantund
}; // namespace nl


#endif /* defined(__wpantund__SpinelNCPTaskGetNetworkTopology__) */
