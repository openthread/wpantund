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
 *    Description:
 *      Declaration of the IBinder IPC Server subclass.
 *
 */

#ifndef wpantund_BinderIPCServer_h
#define wpantund_BinderIPCServer_h

#include <map>
#include <vector>
#include <pthread.h>

#include <android/net/lowpan/ILowpanManager.h>
#include <android/net/lowpan/BnLowpanManager.h>

#include "IPCServer.h"

namespace nl {
namespace wpantund {

class BinderILowpanInterface;

class BinderIPCServer : public IPCServer {
public:

	BinderIPCServer();
	virtual ~BinderIPCServer();

	virtual int add_interface(NCPControlInterface* instance);
	virtual cms_t get_ms_to_next_event(void );
	virtual void process(void);
	virtual int update_fd_set(fd_set *read_fd_set, fd_set *write_fd_set, fd_set *error_fd_set, int *max_fd, cms_t *timeout);

	void lockMainThread();
	void unlockMainThread();

private:
	bool hasPendingCommands();

	std::map<std::string, NCPControlInterface*> mControlInterfaceMap;

	::android::sp<::android::net::lowpan::ILowpanManager> mManagerService;

	pthread_mutex_t mMutex;

	// This is used to trigger the main thread to
	// wake up and handle an API request.
	int mMainThreadTickleFd[2];
}; // class BinderIPCServer

class BinderIPCServerLock {
	BinderIPCServer& mServer;
public:
	BinderIPCServerLock(BinderIPCServer& server): mServer(server)
	{
		mServer.lockMainThread();
	}

	~BinderIPCServerLock()
	{
		mServer.unlockMainThread();
	}
}; // class BinderIPCServerLock

} // namespace wpantund
} // namespace nl

#endif
