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
 *    Description:
 *		This file implements the main program entry point for the
 *		WPAN control utility, `wpanctl`.
 *
 */


#ifndef BORDER_AGENT_PROXY_H_
#define BORDER_AGENT_PROXY_H_

#include <stdint.h>
#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function pointer is called when a CoAP message ready for border agent.
 */
typedef void(*PacketHandler)(const uint8_t* aBuffer, uint16_t aLength, uint16_t aLocator, uint16_t aPort, void* aContext);

/**
 * This function pointer is called when PSKc is changed.
 */
typedef void(*PSKcHandler)(const uint8_t* aPSKc, void* aContext);

/**
 */
int otBorderAgentProxyInit(const char* aInterfaceName);

/**
 * send a border agent packet.
 */
int otBorderAgentProxySend(const uint8_t* aBuffer, uint16_t aLength, uint16_t aLocator, uint16_t aPort);

/**
 * start border agent proxy service.
 *
 * @param[in]   aPacketHandler  A pointer to the function to be called to handle the CoAP message.
 * @param[in]   aPSKcHandler    A pointer to the function to be called when PSKc is changed.
 *
 * @returns Error code.
 * @retval  0   Successfully started the border agent proxy.
 * @retval  -1  Failed to start the border agent proxy.
 */
int otBorderAgentProxyStart(PacketHandler aPacketHandler, PSKcHandler aPSKcHandler, void* aContext);

/**
 * stop border agent proxy service.
 */
int otBorderAgentProxyStop();

/**
 * get an file descriptor for poll border agent data.
 */
void otBorderAgentProxyUpdateFdSet(fd_set *aReadFdSet, fd_set *aWriteFdSet, fd_set *aErrorFdSet, int *aMaxFd);

/**
 * called when the unix fd is available for read or write.
 */
void otBorderAgentProxyProcess(fd_set *aReadFdSet, fd_set *aWriteFdSet, fd_set *aErrorFdSet);

/**
 * get pskc
 */
const uint8_t *otBorderAgentProxyGetPSKc(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // BORDER_AGENT_PROXY_H_
