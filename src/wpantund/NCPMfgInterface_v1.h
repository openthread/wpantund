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

#ifndef wpantund_NCPMfgInterface_v1_h
#define wpantund_NCPMfgInterface_v1_h

#include "NCPControlInterface.h"

namespace nl {
namespace wpantund {

class NCPMfgInterface_v1 {
public:
	virtual void mfg(const std::string& mfg_command, CallbackWithStatusArg1 cb = NilReturn()) = 0;
	virtual ~NCPMfgInterface_v1() {}

};

}; // namespace wpantund
}; // namespace nl

#endif
