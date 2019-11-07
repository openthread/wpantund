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
 *    Description:
 *      This file contains the implementation of `Data` class
 *
 */

#include "Data.h"
#include "string-utils.h"

namespace nl {

std::string
Data::to_string(void) const
{
	size_t max_size = size() * 2 + 2;   // Every byte is encoded as two hex chars adding 1 for null.
	std::vector<char> str_buffer(max_size);
	char *str_buf_ptr = &*str_buffer.begin();

	encode_data_into_string(data(), size(), str_buf_ptr, str_buffer.size(), 0);

	return std::string(str_buf_ptr);
}

};