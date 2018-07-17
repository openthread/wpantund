/*
 *
 * Copyright (c) 2018 OpenThread Authors, Inc.
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

#include "wpanctl-utils.h"
#include "assert-macros.h"
#include "string-utils.h"
#include "commissioner-utils.h"

int
check_psk_format(const char *psk)
{
	int ret = ERRORCODE_BADARG;
	size_t len = strnlen(psk, COMMR_PSK_MAX_LENGTH + 1);

	if (len < COMMR_PSK_MIN_LENGTH) {
		fprintf(stderr, "PSKd \"%s\" is too short, must be minimum %d characters\n", psk, COMMR_PSK_MIN_LENGTH);
		goto bail;
	}

	if (len > COMMR_PSK_MAX_LENGTH) {
		fprintf(stderr, "PSKd \"%s\" is too long, must be maximum %d characters\n", psk, COMMR_PSK_MAX_LENGTH);
		goto bail;
	}

	if (!is_uppercase_or_digit(psk, len)) {
		fprintf(stderr, "PSKd \"%s\" must only contain uppercase alphanumeric characters\n", psk);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	if (strpbrk(psk, COMMR_INVALID_PSK_CHARACTERS) != NULL) {
		fprintf(stderr, "PSKd \"%s\" must not contain I, O, Q, or Z characters\n", psk);
		goto bail;
	}

	ret = ERRORCODE_OK;

bail:
	return ret;
}
