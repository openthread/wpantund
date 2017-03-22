/*
 *
 * Copyright (C) 2017 Nest Labs, Inc.
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

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include "assert-macros.h"
#include <stdio.h>
#include <arpa/inet.h>
#include "NCPControlInterface.h"
#include <memory>

#include "BinderIPCServer.h"
#include "BinderILowpanInterface.h"

#include <android-base/unique_fd.h>
#include <binder/IInterface.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/Status.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/Looper.h>
#include <utils/StrongPointer.h>

#include "wpan-error.h"
#include <poll.h>
#include <unistd.h>
#include <sched.h>

using namespace nl;
using namespace nl::wpantund;
using namespace android;
using namespace android::binder;
using namespace android::net::lowpan;

BinderIPCServer::BinderIPCServer()
{
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, mMainThreadTickleFd) < 0) {
		throw std::runtime_error(strerror(errno));
	}

	pthread_mutex_init(&mMutex, NULL);

	// The default state for this mutex is *locked*.
	pthread_mutex_lock(&mMutex);

	// Get an interface to the Lowpan Service
	if (getService(ILowpanManager::LOWPAN_SERVICE_NAME(), &mManagerService) != 0) {
		// No pre-existing LoWPAN Manager Service. This is fatal.
		syslog(LOG_ERR, "Couldn't find \"%s\"", (const char*)String8(ILowpanManager::LOWPAN_SERVICE_NAME()));

		throw std::runtime_error("Unable to find LoWPAN Service");
	}

	ProcessState::self()->startThreadPool();
}

BinderIPCServer::~BinderIPCServer()
{
	IPCThreadState::shutdown();
	close(mMainThreadTickleFd[0]);
	close(mMainThreadTickleFd[1]);
	pthread_mutex_unlock(&mMutex);
	pthread_mutex_destroy(&mMutex);
}

int
BinderIPCServer::add_interface(NCPControlInterface* instance)
{
	std::string name = instance->get_name();

	mManagerService->addInterface(::android::sp<ILowpanInterface>(new BinderILowpanInterface(*this, instance)));

	mControlInterfaceMap[name] = instance;

	return kWPANTUNDStatus_Ok;
}

void
BinderIPCServer::lockMainThread()
{
	// This is called by the methods of the exported interface classes.

	// This line wakes up the main thread.
	int ret = write(mMainThreadTickleFd[0], "X", 1);

	pthread_mutex_lock(&mMutex);

	assert(ret == 1);
}

void
BinderIPCServer::unlockMainThread()
{
	// This is called by the methods of the exported interface classes.
	char x(0);
	int ret = read(mMainThreadTickleFd[1], &x, 1);

	pthread_mutex_unlock(&mMutex);

	assert(ret == 1);
}

bool
BinderIPCServer::hasPendingCommands()
{
	bool ret = false;
	const int flags = POLLRDNORM|POLLERR|POLLNVAL|POLLHUP;
	struct pollfd pollfd = { mMainThreadTickleFd[1], flags, 0 };
	int count = poll(&pollfd, 1, 0);
	ret = (count>0) && ((pollfd.revents & flags) != 0);
	return ret;
}

void
BinderIPCServer::process(void)
{
	if (hasPendingCommands()) {
		pthread_mutex_unlock(&mMutex);

		do {
			sched_yield();
		} while (hasPendingCommands());

		pthread_mutex_lock(&mMutex);
	}
}

cms_t BinderIPCServer::get_ms_to_next_event(void)
{
	return CMS_DISTANT_FUTURE;
}

int BinderIPCServer::update_fd_set(fd_set *read_fd_set, fd_set *write_fd_set,
		fd_set *error_fd_set, int *max_fd, cms_t *timeout)
{
	int ret = -1;

	if (read_fd_set != NULL) {
		FD_SET(mMainThreadTickleFd[1], read_fd_set);
	}

	if ((max_fd != NULL)) {
		*max_fd = std::max(*max_fd, mMainThreadTickleFd[1]);
	}

	if (timeout != NULL) {
		*timeout = std::min(*timeout, get_ms_to_next_event());
	}

	ret = 0;
bail:
	return ret;
}
