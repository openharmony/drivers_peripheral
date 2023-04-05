/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <securec.h>
#include <hdf_base.h>
#include <hdf_dlist.h>
#include <hdf_log.h>
#include <hdf_sbuf.h>
#include <osal_mem.h>
#include <servmgr_hdi.h>
#include "inotification_callback.h"

#define HDF_LOG_TAG notification_callback_proxy

struct NotificationCallbackProxy {
    struct INotificationCallback impl;
    struct HdfRemoteService *remote;
};

static int32_t NotificationCallbackProxyCall(
    struct INotificationCallback *self, int32_t id, struct HdfSBuf *data, struct HdfSBuf *reply, bool isOneWay)
{
    struct HdfRemoteService *remote = self->asObject(self);
    if (remote == NULL || remote->dispatcher == NULL || remote->dispatcher->Dispatch == NULL ||
        remote->dispatcher->DispatchAsync == NULL) {
        HDF_LOGE("%{public}s: Invalid HdfRemoteService obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (isOneWay) {
        return remote->dispatcher->DispatchAsync(remote, id, data, reply);
    } else {
        return remote->dispatcher->Dispatch(remote, id, data, reply);
    }
}

static int32_t NotificationCallbackProxyOnNotificationCallback(
    struct INotificationCallback *self, enum NotificationType type, uint64_t devHandle)
{
    int32_t notificationCallbackRet = HDF_FAILURE;

    struct HdfSBuf *notificationCallbackData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *notificationCallbackReply = HdfSbufTypedObtain(SBUF_IPC);

    if (notificationCallbackData == NULL || notificationCallbackReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        notificationCallbackRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), notificationCallbackData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(notificationCallbackData, (uint64_t)type)) {
        HDF_LOGE("%{public}s: write type failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(notificationCallbackData, devHandle)) {
        HDF_LOGE("%{public}s: write devHandle failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    notificationCallbackRet = NotificationCallbackProxyCall(self, CMD_NOTIFICATION_CALLBACK_ON_NOTIFICATION_CALLBACK,
        notificationCallbackData, notificationCallbackReply, false);
    if (notificationCallbackRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, notificationCallbackRet);
        goto FINISHED;
    }

FINISHED:
    if (notificationCallbackData != NULL) {
        HdfSbufRecycle(notificationCallbackData);
    }
    if (notificationCallbackReply != NULL) {
        HdfSbufRecycle(notificationCallbackReply);
    }
    return notificationCallbackRet;
}

static int32_t NotificationCallbackProxyGetVersion(
    struct INotificationCallback *self, uint32_t *majorVer, uint32_t *minorVer)
{
    int32_t notificationCallbackRet = HDF_FAILURE;

    struct HdfSBuf *notificationCallbackData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *notificationCallbackReply = HdfSbufTypedObtain(SBUF_IPC);

    if (notificationCallbackData == NULL || notificationCallbackReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        notificationCallbackRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), notificationCallbackData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    notificationCallbackRet = NotificationCallbackProxyCall(
        self, CMD_NOTIFICATION_CALLBACK_GET_VERSION, notificationCallbackData, notificationCallbackReply, false);
    if (notificationCallbackRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, notificationCallbackRet);
        goto FINISHED;
    }

    if (!HdfSbufReadUint32(notificationCallbackReply, majorVer)) {
        HDF_LOGE("%{public}s: read majorVer failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufReadUint32(notificationCallbackReply, minorVer)) {
        HDF_LOGE("%{public}s: read minorVer failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (notificationCallbackData != NULL) {
        HdfSbufRecycle(notificationCallbackData);
    }
    if (notificationCallbackReply != NULL) {
        HdfSbufRecycle(notificationCallbackReply);
    }
    return notificationCallbackRet;
}

static struct HdfRemoteService *NotificationCallbackProxyAsObject(struct INotificationCallback *self)
{
    if (self == NULL) {
        return NULL;
    }
    struct NotificationCallbackProxy *proxy = CONTAINER_OF(self, struct NotificationCallbackProxy, impl);
    return proxy->remote;
}

static void NotificationCallbackProxyConstruct(struct INotificationCallback *impl)
{
    impl->OnNotificationCallback = NotificationCallbackProxyOnNotificationCallback;
    impl->getVersion = NotificationCallbackProxyGetVersion;
    impl->asObject = NotificationCallbackProxyAsObject;
}

struct INotificationCallback *INotificationCallbackGet(struct HdfRemoteService *remote)
{
    if (remote == NULL) {
        HDF_LOGE("%{public}s: remote is null", __func__);
        return NULL;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(remote, INOTIFICATIONCALLBACK_INTERFACE_DESC)) {
        HDF_LOGE("%{public}s: set interface token failed!", __func__);
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }

    struct NotificationCallbackProxy *proxy =
        (struct NotificationCallbackProxy *)OsalMemCalloc(sizeof(struct NotificationCallbackProxy));
    if (proxy == NULL) {
        HDF_LOGE("%{public}s: malloc INotificationCallback proxy failed!", __func__);
        return NULL;
    }

    proxy->remote = remote;
    NotificationCallbackProxyConstruct(&proxy->impl);
    struct INotificationCallback *client = &proxy->impl;

    uint32_t serMajorVer = 0;
    uint32_t serMinorVer = 0;
    int32_t notificationCallbackRet = client->getVersion(client, &serMajorVer, &serMinorVer);
    if (notificationCallbackRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get version failed!", __func__);
        INotificationCallbackRelease(client);
        return NULL;
    }

    if (serMajorVer != INOTIFICATION_CALLBACK_MAJOR_VERSION) {
        HDF_LOGE("%{public}s:check version failed! version of service:%u.%u, version of client:%u.%u", __func__,
            serMajorVer, serMinorVer, INOTIFICATION_CALLBACK_MAJOR_VERSION, INOTIFICATION_CALLBACK_MINOR_VERSION);
        INotificationCallbackRelease(client);
        return NULL;
    }

    return client;
}

void INotificationCallbackRelease(struct INotificationCallback *instance)
{
    if (instance == NULL) {
        return;
    }

    struct NotificationCallbackProxy *proxy = CONTAINER_OF(instance, struct NotificationCallbackProxy, impl);
    HdfRemoteServiceRecycle(proxy->remote);
    OsalMemFree(proxy);
}
