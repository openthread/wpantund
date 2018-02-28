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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "time-utils.h"
#include <sys/time.h>
#include <stdio.h>

#if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static uint64_t sFuzzCms = 0;

void
fuzz_set_cms(cms_t value) {
#if DEBUG
	fprintf(stderr, "fuzz_set_cms: %dms\n", (int)value);
#endif
	sFuzzCms = value;
}

void
fuzz_ff_cms(cms_t increment) {
#if DEBUG
	fprintf(stderr, "fuzz_ff_cms: fast forward %dms\n", (int)increment);
#endif
	if (increment <= CMS_DISTANT_FUTURE) {
		sFuzzCms += increment;
	}
}

cms_t
time_ms(void)
{
	return (cms_t)sFuzzCms;
}

time_t
time_get_monotonic(void)
{
	return (time_t)(sFuzzCms/MSEC_PER_SEC);
}

#else // if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

cms_t
time_ms(void)
{
#if HAVE_CLOCK_GETTIME
	struct timespec tv = { 0 };
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &tv);

	return (cms_t)(tv.tv_sec * MSEC_PER_SEC) + (cms_t)(tv.tv_nsec / NSEC_PER_MSEC);
#else
	struct timeval tv = { 0 };
	gettimeofday(&tv, NULL);
	return (cms_t)(tv.tv_sec * MSEC_PER_SEC) + (cms_t)(tv.tv_usec / USEC_PER_MSEC);
#endif
}

time_t
time_get_monotonic(void)
{
#if HAVE_CLOCK_GETTIME
	struct timespec ts;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &ts);

	return ret == 0 ? ts.tv_sec : 0;
#else
	return time(NULL);
#endif // !__linux__
}
#endif // else FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

cms_t
cms_until_time(time_t time)
{
	time -= time_get_monotonic();

	if (time > (TIME_DISTANT_FUTURE / MSEC_PER_SEC)) {
		// Overflow.
		return CMS_DISTANT_FUTURE;
	}

	return (cms_t)(time * MSEC_PER_SEC);
}
