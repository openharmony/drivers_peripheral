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

#include "notification_callback_stub.h"
#include <hdf_base.h>
#include <hdf_dlist.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>
#include <stub_collector.h>

#define HDF_LOG_TAG notification_callback_stub

static int32_t SerStubOnNotificationCallback(struct INotificationCallback *serviceImpl,
    struct HdfSBuf *notificationCallbackData, struct HdfSBuf *notificationCallbackReply)
{
    int32_t notificationCallbackRet = HDF_FAILURE;
    enum NotificationType type;
    uint64_t devHandle = 0;

    {
        uint64_t enumTmp = 0;
        if (!HdfSbufReadUint64(notificationCallbackData, &enumTmp)) {
            HDF_LOGE("%{public}s: read type failed!", __func__);
            notificationCallbackRet = HDF_ERR_INVALID_PARAM;
            goto FINISHED;
        }
        type = (enum NotificationType)enumTmp;
    }

    if (!HdfSbufReadUint64(notificationCallbackData, &devHandle)) {
        HDF_LOGE("%{public}s: read &devHandle failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->OnNotificationCallback == NULL) {
        HDF_LOGE("%{public}s: invalid interface function OnNotificationCallback ", __func__);
        notificationCallbackRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    notificationCallbackRet = serviceImpl->OnNotificationCallback(serviceImpl, type, devHandle);
    if (notificationCallbackRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call OnNotificationCallback function failed!", __func__);
        goto FINISHED;
    }

FINISHED:
    return notificationCallbackRet;
}

static int32_t SerStubGetVersion(struct INotificationCallback *serviceImpl, struct HdfSBuf *notificationCallbackData,
    struct HdfSBuf *notificationCallbackReply)
{
    int32_t notificationCallbackRet = HDF_SUCCESS;
    if (!HdfSbufWriteUint32(notificationCallbackReply, INOTIFICATION_CALLBACK_MAJOR_VERSION)) {
        HDF_LOGE("%{public}s: write INOTIFICATION_CALLBACK_MAJOR_VERSION failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint32(notificationCallbackReply, INOTIFICATION_CALLBACK_MINOR_VERSION)) {
        HDF_LOGE("%{public}s: write INOTIFICATION_CALLBACK_MINOR_VERSION failed!", __func__);
        notificationCallbackRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    return notificationCallbackRet;
}

static struct HdfRemoteService *NotificationCallbackStubAsObject(struct INotificationCallback *self)
{
    if (self == NULL) {
        return NULL;
    }
    struct NotificationCallbackStub *stub = CONTAINER_OF(self, struct NotificationCallbackStub, interface);
    return stub->remote;
}

static int32_t NotificationCallbackOnRemoteRequest(
    struct HdfRemoteService *remote, int code, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct NotificationCallbackStub *stub = (struct NotificationCallbackStub *)remote;
    if (stub == NULL || stub->remote == NULL || stub->interface == NULL) {
        HDF_LOGE("%{public}s: invalid stub object", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (!HdfRemoteServiceCheckInterfaceToken(stub->remote, data)) {
        HDF_LOGE("%{public}s: interface token check failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    switch (code) {
        case CMD_NOTIFICATION_CALLBACK_ON_NOTIFICATION_CALLBACK:
            return SerStubOnNotificationCallback(stub->interface, data, reply);
        case CMD_NOTIFICATION_CALLBACK_GET_VERSION:
            return SerStubGetVersion(stub->interface, data, reply);
        default: {
            HDF_LOGE("%{public}s: not support cmd %{public}d", __func__, code);
            return HDF_ERR_INVALID_PARAM;
        }
    }
}

static struct HdfRemoteService **NotificationCallbackStubNewInstance(void *impl)
{
    if (impl == NULL) {
        HDF_LOGE("%{public}s: impl is null", __func__);
        return NULL;
    }

    struct INotificationCallback *serviceImpl = (struct INotificationCallback *)impl;
    struct NotificationCallbackStub *stub = OsalMemCalloc(sizeof(struct NotificationCallbackStub));
    if (stub == NULL) {
        HDF_LOGE("%{public}s: failed to malloc stub object", __func__);
        return NULL;
    }
    stub->remote = HdfRemoteServiceObtain((struct HdfObject *)stub, &stub->dispatcher);
    if (stub->remote == NULL) {
        OsalMemFree(stub);
        return NULL;
    }
    (void)HdfRemoteServiceSetInterfaceDesc(stub->remote, INOTIFICATIONCALLBACK_INTERFACE_DESC);
    stub->dispatcher.Dispatch = NotificationCallbackOnRemoteRequest;
    stub->interface = serviceImpl;
    stub->interface->asObject = NotificationCallbackStubAsObject;
    return &stub->remote;
}

static void NotificationCallbackStubRelease(struct HdfRemoteService **remote)
{
    if (remote == NULL) {
        return;
    }
    struct NotificationCallbackStub *stub = CONTAINER_OF(remote, struct NotificationCallbackStub, remote);
    HdfRemoteServiceRecycle(stub->remote);
    OsalMemFree(stub);
}

__attribute__((unused)) static struct StubConstructor g_notificationcallbackConstructor = {
    .constructor = NotificationCallbackStubNewInstance,
    .destructor = NotificationCallbackStubRelease,
};

__attribute__((constructor)) static void NotificationCallbackStubRegister(void)
{
    HDF_LOGI("%{public}s: register stub constructor of '%{public}s'", __func__, INOTIFICATIONCALLBACK_INTERFACE_DESC);
    StubConstructorRegister(INOTIFICATIONCALLBACK_INTERFACE_DESC, &g_notificationcallbackConstructor);
}
