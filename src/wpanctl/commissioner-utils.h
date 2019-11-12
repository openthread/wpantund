/*
 *
 * Copyright (c) 2017 OpenThread Authors, Inc.
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

#ifndef COMMISSIONER_UTILS_H
#define COMMISSIONER_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define COMMR_EUI64_SIZE                    8
#define COMMR_IPv6_ADDRESS_SIZE             16
#define COMMR_XPANID_SIZE                   8
#define COMMR_TLVS_MAX_LEN                  255
#define COMMR_PSK_MIN_LENGTH                6
#define COMMR_PSK_MAX_LENGTH                32
#define COMMR_PROVIISIONING_URL_MAX_LENGTH  64
#define COMMR_INVALID_PSK_CHARACTERS        "IOQZ"

extern int check_psk_format(const char *psk);

#endif
