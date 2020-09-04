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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "tool-cmd-setprop.h"
#include "tool-updateprop.h"
#include "wpan-dbus-v1.h"

int tool_cmd_setprop(int argc, char* argv[])
{
	return tool_updateprop(WPANTUND_IF_CMD_PROP_SET, argc, argv);
}
