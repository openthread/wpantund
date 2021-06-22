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
 *      This file defindes the SuperSocket class, which provides an
 *      easy way to create various types of sockets using a convenient
 *      path syntax.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"

#include "SuperSocket.h"
#include "socket-utils.h"
#include "time-utils.h"
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/file.h>
#include "../wpantund/NCPConstants.h"

#if HAVE_LIBUDEV
#include <libudev.h>
#endif

using namespace nl;

SuperSocket::SuperSocket(const std::string& path)
	:UnixSocket(open_super_socket(path.c_str()), false /*should_close*/), mPath(path)
{
	// Note that the "should_close" flag above is set to false.
	// This is because a super-socket file descriptor must be closed
	// with "close_super_socket()". As such, we handle closing the
	// socket ourselves in our destructor.

	if (0 > mFDRead) {
		syslog(LOG_ERR, "Unable to open socket with path <%s>, errno=%d (%s)", path.c_str(), errno, strerror(errno));
		throw SocketError("Unable to open socket");
	}

	// Lock the file descriptor if it is to a device. It does not make sense
	// to allow someone else to use this file descriptor at the same time,
	// or to use the device while someone else is using it.
	if ( (SUPER_SOCKET_TYPE_DEVICE == get_super_socket_type_from_path(path.c_str()))
	  && (flock(mFDRead, LOCK_EX|LOCK_NB) < 0)
	) {
		// The only error we care about is EWOULDBLOCK. EINVAL is fine,
		// it just means this file descriptor doesn't support locking.
		if (EWOULDBLOCK == errno) {
			syslog(LOG_ERR, "Socket \"%s\" is locked by another process", path.c_str());

			// Failure to close this super socket here was
			// the initiating cause of oss-fuzz-3565
			close_super_socket(mFDRead);

			throw SocketError("Socket is locked by another process");
		}
	}
}

SuperSocket::~SuperSocket()
{
	SuperSocket::hibernate();
}

boost::shared_ptr<SocketWrapper>
SuperSocket::create(const std::string& path)
{
	return boost::shared_ptr<SocketWrapper>(new SuperSocket(path));
}

int
SuperSocket::hibernate(void)
{
	if (mFDRead >= 0) {
		// Unlock the FD.
		IGNORE_RETURN_VALUE(flock(mFDRead, LOCK_UN));

		// Close the existing FD.
		IGNORE_RETURN_VALUE(close_super_socket(mFDRead));
	}

	mFDRead = -1;
	mFDWrite = -1;

	return 0;
}

void SuperSocket::waitForDevice()
{
#if HAVE_LIBUDEV
	int fd;
	cms_t end;
	cms_t now;
	struct udev_monitor *mon;

	struct udev *udev = udev_new();
	if (!udev) {
		syslog(LOG_ERR, "Can't create udev");
		return;
	}

	mon = udev_monitor_new_from_netlink(udev, "udev");
	udev_monitor_filter_add_match_subsystem_devtype(mon, "tty", NULL);
	udev_monitor_enable_receiving(mon);
	fd = udev_monitor_get_fd(mon);

	end = time_ms() + (cms_t)(NCP_RESET_TIMEOUT * MSEC_PER_SEC);

	do {
		int ret;
		fd_set fds;
		struct timeval tv;

		tv.tv_sec = 0;
		tv.tv_usec = 100 * USEC_PER_MSEC;

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		ret = select(fd + 1, &fds, NULL, NULL, &tv);
		if (ret > 0 && FD_ISSET(fd, &fds)) {
			struct udev_device *dev = udev_monitor_receive_device(mon);
			if (dev) {
				struct udev_list_entry *entry;
				const char *action = udev_device_get_action(dev);

				if (strncmp(action, "add", strlen("add")) == 0) {
					udev_list_entry_foreach(
						entry, udev_device_get_devlinks_list_entry(dev))
					{
						const char *name = udev_list_entry_get_name(entry);
						if (strncmp(name, mPath.c_str(), mPath.length()) ==
						    0) {
							udev_device_unref(dev);
							goto exit;
						}
					}
				}
				udev_device_unref(dev);
			}
		}
		now = time_ms();
	} while (end > now);

	syslog(LOG_WARNING, "The USB CDC ACM device has not been added in desired time");

exit:
	udev_unref(udev);
#endif
}

void
SuperSocket::reset()
{
	syslog(LOG_DEBUG, "SuperSocket::reset()");

#if !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	SuperSocket::waitForDevice();
	SuperSocket::hibernate();

	// Sleep for 200ms to wait for things to settle down.
	usleep(MSEC_PER_SEC * 200);

	mFDRead = mFDWrite = open_super_socket(mPath.c_str());

	if (mFDRead < 0) {
		// Unable to reopen socket...!
		syslog(LOG_ERR, "SuperSocket::Reset: Unable to reopen socket <%s>, errno=%d (%s)", mPath.c_str(), errno, strerror(errno));
		throw SocketError("Unable to reopen socket");
	}

	// Lock the file descriptor. It does not make sense to allow someone else
	// to use this file descriptor at the same time, or to use the device
	// while someone else is using it.
	if ( (SUPER_SOCKET_TYPE_DEVICE == get_super_socket_type_from_path(mPath.c_str()))
	  && (flock(mFDRead, LOCK_EX|LOCK_NB) < 0)
	) {
		// The only error we care about is EWOULDBLOCK. EINVAL is fine,
		// it just means this file descriptor doesn't support locking.
		if (EWOULDBLOCK == errno) {
			syslog(LOG_ERR, "Socket is locked by another process");
			throw SocketError("Socket is locked by another process");
		}
	}
#endif // if !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
}
