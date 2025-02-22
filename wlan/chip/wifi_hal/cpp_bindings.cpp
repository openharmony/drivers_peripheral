/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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
 */

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <sys/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>
#include <linux/nl80211.h>
#include <linux/pkt_sched.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/handlers.h>
#include "common.h"
#include "cpp_bindings.h"
#include "wifi_hal.h"

static pthread_mutex_t g_responseMutex;
static volatile bool g_isAvailableResponseLock;

void InitResponseLock()
{
    pthread_mutex_init(&g_responseMutex, nullptr);
    g_isAvailableResponseLock = true;
}

void DestroyResponseLock()
{
    g_isAvailableResponseLock = false;
    pthread_mutex_destroy(&g_responseMutex);
}

int WifiEvent::Parse()
{
    if (mHeader != nullptr) {
        return HAL_SUCCESS;
    }
    mHeader = reinterpret_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(mMsg)));
    int result = nla_parse(mAttributes, nL80211AttrMaxInternal, genlmsg_attrdata(mHeader, 0),
        genlmsg_attrlen(mHeader, 0), NULL);
    return result;
}

int WifiRequest::Create(int family, uint8_t cmd, int flags, int hdrlen)
{
    Destroy();

    mMsg = nlmsg_alloc();
    if (mMsg != nullptr) {
        genlmsg_put(mMsg, 0, 0, family, hdrlen, flags, cmd, 0); //pid = 0 seq = 0 version = 0
        return HAL_SUCCESS;
    } else {
        return HAL_OUT_OF_MEMORY;
    }
}

int WifiRequest::Create(uint32_t id, int subcmd)
{
        int res = Create(NL80211_CMD_VENDOR);
        if (res < 0) {
            return res;
        }

        res = PutU32(NL80211_ATTR_VENDOR_ID, id);
        if (res < 0) {
            return res;
        }

        res = PutU32(NL80211_ATTR_VENDOR_SUBCMD, subcmd);
        if (res < 0) {
            return res;
        }

        if (mIface != -1) {
            res = SetIfaceId(mIface);
        }

        return res;
}

static int NoSeqCheck(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

int WifiCommand::RequestResponse()
{
    int err = Create();                      /* create the message */
    if (err < 0) {
        return err;
    }

    return RequestResponse(mMsg);
}

int WifiCommand::RequestResponse(WifiRequest& request)
{
    if (!g_isAvailableResponseLock || !mInfo || !mInfo->cmdSock) {
        return 0;
    }
    pthread_mutex_lock(&g_responseMutex);
    int err = 0;

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        HDF_LOGE("nl_cb_alloc fail");
        goto out;
    }

    err = nl_send_auto_complete(mInfo->cmdSock, request.GetMessage());      /* send message */
    if (err < 0) {
        HDF_LOGE("nl_send_auto_complete fail");
        goto out;
    }
    err = 1;

    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, NoSeqCheck, NULL);
    nl_cb_err(cb, NL_CB_CUSTOM, ErrorHandler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, FinishHandler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, AckHandler, &err);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, ResponseHandler, this);

    while (err > 0) {                       /* Wait for reply */
        int res = nl_recvmsgs(mInfo->cmdSock, cb);
        if (res) {
            HDF_LOGE("nl80211: %{public}s->nl_recvmsgs failed: %{public}d", __func__, res);
            if (res == -NLE_NOMEM) {
                break;
            }
        }
    }
out:
    nl_cb_put(cb);
    pthread_mutex_unlock(&g_responseMutex);
    return err;
}

int WifiCommand::RequestEvent(int cmd)
{
    HDF_LOGD("requesting event %{public}d", cmd);
    int res = WifiRegisterHandler(WifiHandle(), cmd, EventHandler, this);
    if (res < 0) {
        return res;
    }

    res = Create();                                                         /* create the message */
    if (res < 0) {
        goto out;
    }

    HDF_LOGD("waiting for response %{public}d", cmd);

    res = nl_send_auto_complete(mInfo->cmdSock, mMsg.GetMessage());         /* send message */
    if (res < 0) {
        goto out;
    }

    HDF_LOGD("waiting for event %{public}d", cmd);
    res = mCondition.Wait();
    if (res < 0) {
        goto out;
    }

out:
    WifiUnregisterHandler(WifiHandle(), cmd);
    return res;
}

int WifiCommand::RequestVendorEvent(uint32_t id, int subcmd)
{
    int res = WifiRegisterVendorHandler(WifiHandle(), id, subcmd, EventHandler, this);
    if (res < 0) {
        return res;
    }

    res = Create();                                                    /* create the message */
    if (res < 0) {
        goto out;
    }

    res = nl_send_auto_complete(mInfo->cmdSock, mMsg.GetMessage());         /* send message */
    if (res < 0) {
        goto  out;
    }

    res = mCondition.Wait();
    if (res < 0) {
        goto out;
    }

out:
    WifiUnregisterVendorHandler(WifiHandle(), id, subcmd);
    return res;
}

/* Event handlers */
int WifiCommand::ResponseHandler(struct nl_msg *msg, void *arg)
{
    WifiCommand *cmd = (WifiCommand *)arg;
    WifiEvent reply(msg);
    int res = reply.Parse();
    if (res < 0) {
        HDF_LOGE("Failed to Parse reply message = %{public}d", res);
        return NL_SKIP;
    } else {
        return cmd->HandleResponse(reply);
    }
}

int WifiCommand::EventHandler(struct nl_msg *msg, void *arg)
{
    WifiCommand *cmd = reinterpret_cast<WifiCommand *>(arg);
    WifiEvent event(msg);
    int res = event.Parse();
    if (res < 0) {
        HDF_LOGE("Failed to Parse event = %{public}d", res);
        res = NL_SKIP;
    } else {
        res = cmd->HandleEvent(event);
    }

    cmd->mCondition.Signal();
    return res;
}

int WifiCommand::ValidHandler(struct nl_msg *msg, void *arg)
{
    int *err = (int *)arg;
    *err = 0;
    return NL_SKIP;
}

/* Other event handlers */
int WifiCommand::AckHandler(struct nl_msg *msg, void *arg)
{
    int *err = (int *)arg;
    *err = 0;
    return NL_STOP;
}

int WifiCommand::FinishHandler(struct nl_msg *msg, void *arg)
{
    int *ret = (int *)arg;
    *ret = 0;
    return NL_SKIP;
}

int WifiCommand::ErrorHandler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    int *ret = (int *)arg;
    *ret = err->error;
    return NL_SKIP;
}