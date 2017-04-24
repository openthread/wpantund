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


#include <arpa/inet.h>
#include <dbus/dbus.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/select.h>
#include <sys/time.h>
#include <map>

extern "C" {
#include "wpanctl-utils.h"
#include "bap-utils.h"
#include "wpan-dbus-v1.h"
#include "assert-macros.h"
}

#include "spinel.h"
#include "util/Data.h"
#include "bap.h"

static char sInterfaceName[IFNAMSIZ];
static char sInterfaceDBusName[DBUS_MAXIMUM_NAME_LENGTH + 1];
static char sInterfaceDBusPath[DBUS_MAXIMUM_NAME_LENGTH + 1];
static uint8_t sPSKc[sizeof(spinel_net_pskc_t)];

static DBusConnection* sConn = NULL;
static PacketHandler sPacketHandler = NULL;

typedef std::map<DBusWatch*, bool> WatchMap;
static WatchMap sWatches;

DBusHandlerResult dbus_message_handler(
        DBusConnection *connection,
        DBusMessage *message,
        void *user_data)
{
    (void)connection;
    DBusMessageIter iter;
    dbus_message_iter_init(message, &iter);

    const uint8_t* buf = NULL;
    uint16_t locator = 0;
    uint16_t port = 0;
    uint16_t len = 0;
    {
        DBusMessageIter sub_iter;
        dbus_message_iter_recurse(&iter, &sub_iter);

        int nelements = 0;
        dbus_message_iter_get_fixed_array(&sub_iter, &buf, &nelements);
        len = (uint16_t)nelements;
    }

    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &locator);
    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &port);

    sPacketHandler(buf, len, locator, port, user_data);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static dbus_bool_t bap_add_dbus_watch(struct DBusWatch *watch, void *data)
{
    sWatches[watch] = true;
    return TRUE;
}

static void bap_remove_dbus_watch(struct DBusWatch *watch, void *data)
{
    sWatches.erase(watch);
}

static void bap_toggle_dbus_watch(struct DBusWatch *watch, void *data)
{
    sWatches[watch] = (dbus_watch_get_enabled(watch) ? true : false);
}

static int bap_enable_border_agent_proxy(dbus_bool_t enable)
{
    int ret = 0;
    DBusMessage *message = NULL;
    const char *property_name = kWPANTUNDProperty_BorderAgentProxyEnable;

    message = dbus_message_new_method_call(
            sInterfaceDBusName,
            sInterfaceDBusPath,
            WPANTUND_DBUS_APIv1_INTERFACE,
            WPANTUND_IF_CMD_PROP_SET);

    require_action(message != NULL, bail, ret = -1);

    require_action(dbus_message_append_args(
            message,
            DBUS_TYPE_STRING, &property_name,
            DBUS_TYPE_BOOLEAN, &enable,
            DBUS_TYPE_INVALID), bail, ret = -1);

    require_action(dbus_connection_send(sConn, message, NULL), bail, ret = -1);

bail:
    if (message != NULL)
    {
        dbus_message_unref(message);
    }

    return ret;
}

int otBorderAgentProxyInit(const char* aInterfaceName)
{
    int ret = 0;
    strncpy(sInterfaceName, aInterfaceName, sizeof(sInterfaceName));
    require_noerr(ret = lookup_dbus_name_from_interface(sInterfaceDBusName, sInterfaceName), bail);

    // according to source code of wpanctl, better to export a function.
    snprintf(sInterfaceDBusPath,
            sizeof(sInterfaceDBusPath),
            "%s/%s",
            WPANTUND_DBUS_PATH,
            sInterfaceName);

bail:

    if (ret)
    {
        syslog(LOG_ERR, "failed to initialize border agent proxy. error=%d", ret);
    }

    return ret;
}

int otBorderAgentProxyStart(PacketHandler aPacketHandler, void* aContext)
{
    int ret = 0;
    DBusError error;

    dbus_error_init(&error);
    sConn = dbus_bus_get(DBUS_BUS_STARTER, &error);
    if (!sConn) {
        dbus_error_free(&error);
        sConn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    }
    require_action(sConn != NULL, bail, ret = -1);

    require_action(dbus_bus_register(sConn, &error), bail, ret = -1);

    require_action(dbus_bus_request_name(sConn,
                BORDER_AGENT_DBUS_NAME,
                0,
                &error) > 0, bail, ret = -1);

    static const DBusObjectPathVTable ot_ba_coap_vtable = {
        NULL,
        dbus_message_handler,
        NULL, NULL, NULL, NULL
    };

    require_action(dbus_connection_register_object_path(
            sConn,
            BORDER_AGENT_DBUS_OBJECT,
            &ot_ba_coap_vtable,
            aContext), bail, ret = -1);

    sPacketHandler = aPacketHandler;

    require_action(dbus_connection_set_watch_functions(
            sConn,
            bap_add_dbus_watch,
            bap_remove_dbus_watch,
            bap_toggle_dbus_watch,
            NULL, NULL), bail, ret = -1);

    bap_enable_border_agent_proxy(TRUE);

bail:

    if (dbus_error_is_set (&error))
    {
        syslog(LOG_ERR, "an error occurred: %s\n", error.message);
        dbus_error_free (&error);
    }

    if (ret && sConn)
    {
        dbus_connection_unref(sConn);
    }

    return ret;
}

int otBorderAgentProxySend(const uint8_t* aBuffer, uint16_t aLength, uint16_t aLocator, uint16_t aPort)
{
    int ret = 0;
    DBusMessage *message = NULL;
    nl::Data data(aLength + sizeof(aLocator) + sizeof(aPort));
    const uint8_t* value_ptr = data.data();
    const char* property_name = kWPANTUNDProperty_BorderAgentProxyStream;

    memcpy(data.data(), aBuffer, aLength);
    data[aLength] = (aLocator >> 8);
    data[aLength + 1] = (aLocator & 0xff);
    data[aLength + 2] = (aPort >> 8);
    data[aLength + 3] = (aPort & 0xff);

    message = dbus_message_new_method_call(
            sInterfaceDBusName,
            sInterfaceDBusPath,
            WPANTUND_DBUS_APIv1_INTERFACE,
            WPANTUND_IF_CMD_PROP_SET);

    require_action(message != NULL, bail, ret = -1);

    require_action(dbus_message_append_args(
            message,
            DBUS_TYPE_STRING, &property_name,
            DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
            &value_ptr, data.size(), DBUS_TYPE_INVALID), bail, ret = -1);

    require_action(dbus_connection_send(sConn, message, NULL), bail, ret = -1);

bail:

    if (message)
    {
        dbus_message_unref(message);
    }

    return ret;
}

int otBorderAgentProxyStop()
{
    bap_enable_border_agent_proxy(FALSE);
    dbus_connection_unref(sConn);
    return 0;
}

void otBorderAgentProxyUpdateFdSet(fd_set *aReadFdSet, fd_set *aWriteFdSet, fd_set *aErrorFdSet, int *aMaxFd)
{
    for (WatchMap::iterator it = sWatches.begin(); it != sWatches.end(); ++it)
    {
        if (!it->second) continue;

        DBusWatch* watch = it->first;
        unsigned int flags = dbus_watch_get_flags(watch);
        int fd = dbus_watch_get_unix_fd(watch);

        if (fd < 0) continue;

        if ((flags & DBUS_WATCH_READABLE) && (aReadFdSet != NULL)) {
            FD_SET(fd, aReadFdSet);
        }

        if ((flags & DBUS_WATCH_WRITABLE) && (aWriteFdSet != NULL) &&
                dbus_connection_has_messages_to_send(sConn)) {
            FD_SET(fd, aWriteFdSet);
        }

        if (aErrorFdSet != NULL) {
            FD_SET(fd, aErrorFdSet);
        }

        if ((aMaxFd != NULL) && fd > *aMaxFd) {
            *aMaxFd = fd;
        }
    }
}

void otBorderAgentProxyProcess(fd_set *aReadFdSet, fd_set *aWriteFdSet, fd_set *aErrorFdSet)
{
    for (WatchMap::iterator it = sWatches.begin(); it != sWatches.end(); ++it)
    {
        if (!it->second) continue;

        DBusWatch* watch = it->first;
        unsigned int flags = dbus_watch_get_flags(watch);
        int fd = dbus_watch_get_unix_fd(watch);

        if (fd < 0) continue;

        if ((flags & DBUS_WATCH_READABLE) && !FD_ISSET(fd, aReadFdSet)) {
            flags &= ~DBUS_WATCH_READABLE;
        }

        if ((flags & DBUS_WATCH_WRITABLE) && !FD_ISSET(fd, aWriteFdSet)) {
            flags &= ~DBUS_WATCH_WRITABLE;
        }

        if (FD_ISSET(fd, aErrorFdSet)) {
            flags |= DBUS_WATCH_ERROR;
        }

        dbus_watch_handle(watch, flags);
    }

    while (DBUS_DISPATCH_DATA_REMAINS == dbus_connection_get_dispatch_status(sConn) &&
            dbus_connection_read_write_dispatch(sConn, 0));
}

const uint8_t *otBorderAgentProxyGetPSKc(void)
{
    const uint8_t *pskc = NULL;
    int ret = 0;
    DBusMessageIter iter;
    DBusMessageIter subIter;
    DBusMessage *message = NULL;
    DBusMessage *reply = NULL;
    DBusError error;
    int timeout = DEFAULT_TIMEOUT_IN_SECONDS * 1000;
    const char *property_name = kWPANTUNDProperty_NetworkPSKc;

    dbus_error_init(&error);
    require((message = dbus_message_new_method_call(
            sInterfaceDBusName,
            sInterfaceDBusPath,
            WPANTUND_DBUS_APIv1_INTERFACE,
            WPANTUND_IF_CMD_PROP_GET
            )) != NULL, bail);

    require(dbus_message_append_args(
            message,
            DBUS_TYPE_STRING, &property_name,
            DBUS_TYPE_INVALID
            ), bail);

    require((reply = dbus_connection_send_with_reply_and_block(
            sConn,
            message,
            timeout,
            &error
            )) != NULL, bail);

    dbus_message_iter_init(reply, &iter);
    dbus_message_iter_get_basic(&iter, &ret);

    if (ret)
    {
        syslog(LOG_ERR, "Failed to get PSKc: %d", ret);
        goto bail;
    }

    // Move to the property
    dbus_message_iter_next(&iter);
    require(DBUS_TYPE_ARRAY == dbus_message_iter_get_arg_type(&iter), bail);
    dbus_message_iter_recurse(&iter, &subIter);
    require(DBUS_TYPE_BYTE == dbus_message_iter_get_arg_type(&subIter), bail);

    {
        int count = 0;
        dbus_message_iter_get_fixed_array(&subIter, &pskc, &count);
        require(count == sizeof(spinel_net_pskc_t), bail);
        memcpy(sPSKc, pskc, count);
        pskc = sPSKc;
    }

bail:
    if (reply)
    {
        dbus_message_unref(reply);
    }

    if (message)
    {
        dbus_message_unref(message);
    }

    return pskc;
}
