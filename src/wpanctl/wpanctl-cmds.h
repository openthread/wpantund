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

#ifndef wpantund_wpanctl_cmds_h
#define wpantund_wpanctl_cmds_h

#include "tool-cmd-scan.h"
#include "tool-cmd-join.h"
#include "tool-cmd-form.h"
#include "tool-cmd-leave.h"
#include "tool-cmd-permit-join.h"
#include "tool-cmd-linkmetrics.h"
#include "tool-cmd-list.h"
#include "tool-cmd-status.h"
#include "tool-cmd-mfg.h"
#include "tool-cmd-resume.h"
#include "tool-cmd-reset.h"
#include "tool-cmd-begin-low-power.h"
#include "tool-cmd-begin-net-wake.h"
#include "tool-cmd-host-did-wake.h"
#include "tool-cmd-getprop.h"
#include "tool-cmd-setprop.h"
#include "tool-cmd-insertprop.h"
#include "tool-cmd-removeprop.h"
#include "tool-cmd-cd.h"
#include "tool-cmd-poll.h"
#include "tool-cmd-config-gateway.h"
#include "tool-cmd-add-prefix.h"
#include "tool-cmd-remove-prefix.h"
#include "tool-cmd-add-route.h"
#include "tool-cmd-remove-route.h"
#include "tool-cmd-peek.h"
#include "tool-cmd-poke.h"
#include "tool-cmd-pcap.h"
#include "tool-cmd-commr.h"
#include "tool-cmd-commissioner.h"
#include "tool-cmd-joiner.h"
#include "tool-cmd-dataset.h"
#include "tool-cmd-add-service.h"
#include "tool-cmd-remove-service.h"
#include "tool-cmd-mlr.h"
#include "tool-cmd-bbr.h"

#include "wpanctl-utils.h"

#define WPANCTL_CLI_COMMANDS \
	{ \
		"join", \
		"Join a WPAN.", \
		&tool_cmd_join \
	}, \
	{ "connect", "", &tool_cmd_join, 1 }, \
	{ \
		"form", \
		"Form a new WPAN.", \
		&tool_cmd_form \
	}, \
	{ \
		"attach", \
		"Attach/resume a previously commissioned network", \
		&tool_cmd_resume \
	}, \
	{ "resume", "", &tool_cmd_resume, 1 }, \
	{ \
		"reset", \
		"Reset the NCP", \
		&tool_cmd_reset \
	}, \
	{ \
		"begin-low-power", \
		"Enter low-power mode", \
		&tool_cmd_begin_low_power \
	}, \
	{ "lurk", "", &tool_cmd_begin_low_power, 1 }, \
	{ "wake", "", &tool_cmd_status, 1 }, \
	{ \
		"leave", \
		"Abandon the currently connected WPAN.", \
		&tool_cmd_leave \
	}, \
	{ "disconnect", "", &tool_cmd_leave, 1 }, \
	{ \
		"poll", \
		"Poll the parent immediately to see if there is IP traffic", \
		&tool_cmd_poll \
	}, \
	{ \
		"config-gateway", \
		"Configure gateway (deprecated, use `add-prefix` and `remove-prefix`)", \
		&tool_cmd_config_gateway \
	}, \
	{ \
		"add-prefix", \
		"Add prefix", \
		&tool_cmd_add_prefix \
	}, \
	{ \
		"remove-prefix", \
		"Remove prefix", \
		&tool_cmd_remove_prefix \
	}, \
	{ \
		"add-route", \
		"Add external route prefix", \
		&tool_cmd_add_route \
	}, \
	{ \
		"remove-route", \
		"Remove external route prefix", \
		&tool_cmd_remove_route \
	}, \
	{ \
		"add-service", \
		"Add service", \
		&tool_cmd_add_service \
	}, \
	{ \
		"remove-service", \
		"Remove service", \
		&tool_cmd_remove_service \
	}, \
	{ \
		"joiner", \
		"Joiner commands", \
		&tool_cmd_joiner \
	}, \
	{ \
		"commissioner", \
		"Commissioner commands", \
		&tool_cmd_commr \
	}, \
	{ "commr", "", &tool_cmd_commr , 1 }, \
	{ "o-commissioner", "", &tool_cmd_commissioner , 1 }, /* old commissioner command */ \
	{ "o-commr", "", &tool_cmd_commissioner , 1 }, \
	{ \
		"linkmetrics", \
		"Link metrics commands", \
		&tool_cmd_linkmetrics \
	}, \
	{ \
		"mlr-reg", \
		"Multicast Listener Registration commands", \
		&tool_cmd_mlr_reg \
	}, \
	{ \
		"bbr", \
		"Backbone router commands", \
		&tool_cmd_bbr \
	}, \
	{ \
		"list", \
		"List available interfaces.", \
		&tool_cmd_list \
	}, \
	{ "ls", "", &tool_cmd_list, 1 }, \
	{ \
		"status", \
		"Retrieve the status of the interface.", \
		&tool_cmd_status \
	}, \
	{ \
		"permit-join", \
		"Permit other devices to join the current network.", \
		&tool_cmd_permit_join \
	}, \
	{ "pj", "", &tool_cmd_permit_join, 1 }, \
	{ "permit", "", &tool_cmd_permit_join, 1 }, \
	{ \
		"scan", \
		"Scan for nearby networks.", \
		&tool_cmd_scan \
	}, \
	{ \
		"mfg", \
		"Execute manufacturing command.", \
		&tool_cmd_mfg \
	}, \
	{ \
		"getprop", \
		"Get a property (alias: `get`).", \
		&tool_cmd_getprop \
	}, \
	{ "get", "", &tool_cmd_getprop, 1 }, \
	{ \
		"setprop", \
		"Set a property (alias: `set`).", \
		&tool_cmd_setprop \
	}, \
	{ "set", "", &tool_cmd_setprop, 1 }, \
	{ \
		"insertprop", \
		"Insert value in a list-oriented property (alias: `insert`, `add`).", \
		&tool_cmd_insertprop \
	}, \
	{ "insert", "", &tool_cmd_insertprop, 1 }, \
	{ "add", "", &tool_cmd_insertprop, 1 }, \
	{ \
		"removeprop", \
		"Remove value from a list-oriented property (alias: `remove`).", \
		&tool_cmd_removeprop \
	}, \
	{ "remove", "", &tool_cmd_removeprop, 1 }, \
	{ \
		"begin-net-wake", \
		"Initiate a network wakeup", \
		&tool_cmd_begin_net_wake \
	}, \
	{ \
		"host-did-wake", \
		"Perform any host-wakeup related tasks", \
		&tool_cmd_host_did_wake \
	}, \
	{ \
		"pcap", \
		"Start a packet capture", \
		&tool_cmd_pcap \
	}, \
	{ \
		"peek", \
		"Peek into NCP memory", \
		&tool_cmd_peek \
	}, \
	{ \
		"poke", \
		"Poke NCP memory (change content at a NCP memory address)", \
		&tool_cmd_poke \
	}, \
	{ \
		"dataset", \
		"Issue commands related to the local dataset", \
		&tool_cmd_dataset \
	}, \
	{ "cd",   "Change current interface (command mode)", \
	  &tool_cmd_cd                                            }

#endif
