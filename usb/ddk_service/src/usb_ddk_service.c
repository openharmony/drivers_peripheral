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

#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>

#include "hdf_remote_service.h"
#include "usb_ddk_impl.h"
#include "usb_ddk_interface.h"
#include "usb_raw_api.h"
#include "usb_ddk_hash.h"

#define HDF_LOG_TAG usb_ddk_service

struct UsbDdkService {
    struct IUsbDdk interface;
};

struct UsbDdkListener {
    struct HdfDevEventlistener hdfListener;
    struct DListHead node;
};

struct UsbDdkListenerList {
    struct DListHead head;
    struct OsalMutex lock;
};

struct UsbDdkListenerList g_listenerList;

static int32_t UsbDdkInit(struct IUsbDdk *self)
{
    (void)self;
    HDF_LOGI("usb ddk init");
    return UsbInitHostSdk(NULL);
}

static int32_t UsbDdkRelease(struct IUsbDdk *self)
{
    (void)self;
    HDF_LOGI("usb ddk exit");
    return UsbExitHostSdk(NULL);
}

static int32_t UsbDdkRegisterNotification(struct IUsbDdk *self, struct INotificationCallback *cb)
{
    (void)self;
    if (cb == NULL) {
        HDF_LOGE("%{public}s, invalid param cb:%{public}d", __func__, cb == NULL);
        return HDF_ERR_INVALID_PARAM;
    }

    struct ListenerPrivInfo *privInfo = (struct ListenerPrivInfo *)OsalMemCalloc(sizeof(struct ListenerPrivInfo));
    if (privInfo == NULL) {
        HDF_LOGE("%{public}s alloc privInfo failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    privInfo->cb = cb;

    int32_t ret = HDF_SUCCESS;
    struct UsbDdkListener *listener = (struct UsbDdkListener *)OsalMemCalloc(sizeof(struct UsbDdkListener));
    if (listener == NULL) {
        HDF_LOGE("%{public}s alloc listener failed", __func__);
        ret = HDF_DEV_ERR_NO_MEMORY;
        goto FINISHED;
    }
    listener->hdfListener.callBack = OnUsbDdkEventReceived;
    listener->hdfListener.priv = privInfo;

    ret = DdkListenerMgrAdd(&listener->hdfListener);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s add listener failed", __func__);
        ret = HDF_DEV_ERR_NO_MEMORY;
        goto FINISHED;
    }

    OsalMutexLock(&g_listenerList.lock);
    DListInsertTail(&listener->node, &g_listenerList.head);
    OsalMutexUnlock(&g_listenerList.lock);
    return HDF_SUCCESS;

FINISHED:
    OsalMemFree(privInfo);
    OsalMemFree(listener);
    return ret;
}

static int32_t UsbDdkUnRegisterNotification(struct IUsbDdk *self, struct INotificationCallback *cb)
{
    (void)self;
    if (cb == NULL) {
        HDF_LOGE("%{public}s, invalid param cb:%{public}d", __func__, cb == NULL);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbDdkListener *listener = NULL;
    struct ListenerPrivInfo *priv = NULL;
    OsalMutexLock(&g_listenerList.lock);
    // find listener
    DLIST_FOR_EACH_ENTRY(listener, &g_listenerList.head, struct UsbDdkListener, node) {
        priv = (struct ListenerPrivInfo *)listener->hdfListener.priv;
        struct HdfRemoteService *remoteObj = priv->cb->asObject(priv->cb);
        if (remoteObj->index == cb->asObject(cb)->index) {
            break;
        }
    }

    if (listener == NULL) {
        HDF_LOGE("%{public}s listener not found", __func__);
        return HDF_ERR_OUT_OF_RANGE;
    }

    int32_t ret = DdkListenerMgrRemove(&listener->hdfListener);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s remove listener failed", __func__);
        return HDF_FAILURE;
    }

    DListRemove(&listener->node);
    OsalMutexUnlock(&g_listenerList.lock);

    OsalMemFree(listener->hdfListener.priv);
    OsalMemFree((void *)listener);
    return HDF_SUCCESS;
}

static int32_t UsbDdkGetDeviceDescriptor(struct IUsbDdk *self, uint64_t devHandle, struct UsbDeviceDescriptor *desc)
{
    (void)self;
    if (desc == NULL) {
        HDF_LOGE("%{public}s param invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    UsbRawHandle *rawHandle = UsbRawOpenDevice(NULL, GET_BUS_NUM(devHandle), GET_DEV_NUM(devHandle));
    if (rawHandle == NULL) {
        HDF_LOGE("%{public}s open device failed", __func__);
        return HDF_FAILURE;
    }

    UsbRawDevice *rawDevice = UsbRawGetDevice(rawHandle);
    if (rawDevice == NULL) {
        HDF_LOGE("%{public}s get device failed", __func__);
        (void)UsbRawCloseDevice(rawHandle);
        return HDF_FAILURE;
    }

    int32_t ret = UsbRawGetDeviceDescriptor(rawDevice, desc);
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s get desc failed %{public}d", __func__, ret);
    }
    (void)UsbRawCloseDevice(rawHandle);
    return ret;
}

static int32_t UsbDdkGetConfigDescriptor(
    struct IUsbDdk *self, uint64_t devHandle, uint8_t configIndex, uint8_t *configDesc, uint32_t *configDescLen)
{
    (void)self;
    if (configDesc == NULL || configDescLen == NULL) {
        HDF_LOGE("%{public}s param invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    UsbRawHandle *rawHandle = UsbRawOpenDevice(NULL, GET_BUS_NUM(devHandle), GET_DEV_NUM(devHandle));
    if (rawHandle == NULL) {
        HDF_LOGE("%{public}s open device failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = GetRawConfigDescriptor(rawHandle, configIndex, configDesc, configDescLen);
    if (ret <= 0) {
        HDF_LOGW("%{public}s get config desc failed %{public}d", __func__, ret);
    } else {
        *configDescLen = ret;
        ret = HDF_SUCCESS;
    }

    (void)UsbRawCloseDevice(rawHandle);
    return ret;
}

static int32_t UsbDdkClaimInterface(struct IUsbDdk *self, uint64_t devHandle, uint8_t interfaceIndex,
    enum UsbClaimMode claimMode, uint64_t *interfaceHandle)
{
    (void)self;
    if (interfaceHandle == NULL) {
        HDF_LOGE("%{public}s param invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbInterface *interface;
    if (claimMode == USB_CLAIM_FORCE) {
        interface = UsbClaimInterface(NULL, GET_BUS_NUM(devHandle), GET_DEV_NUM(devHandle), interfaceIndex);
    } else {
        interface = UsbClaimInterfaceUnforce(NULL, GET_BUS_NUM(devHandle), GET_DEV_NUM(devHandle), interfaceIndex);
    }

    if (interface == NULL) {
        HDF_LOGE("%{public}s claim failed %{public}d", __func__, claimMode);
        return HDF_FAILURE;
    }

    UsbInterfaceHandle *handle = UsbOpenInterface(interface);
    if (handle == NULL) {
        HDF_LOGE("%{public}s open failed %{public}d", __func__, claimMode);
        return HDF_FAILURE;
    }

    int32_t ret = UsbDdkHash((uint64_t)handle, interfaceHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s hash failed %{public}d", __func__, ret);
    }
    return ret;
}

static int32_t UsbDdkReleaseInterface(struct IUsbDdk *self, uint64_t interfaceHandle)
{
    (void)self;
    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, &handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    struct UsbInterface *interface = NULL;
    ret = GetInterfaceByHandle((const UsbInterfaceHandle *)handle, &interface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get interface failed %{public}d", __func__, ret);
        return ret;
    }

    ret = UsbCloseInterface((const UsbInterfaceHandle *)handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s close interface failed %{public}d", __func__, ret);
        return ret;
    }

    UsbDdkDelHashRecord(interfaceHandle);

    return UsbReleaseInterface(interface);
}

static int32_t UsbDdkSelectInterfaceSetting(struct IUsbDdk *self, uint64_t interfaceHandle, uint8_t settingIndex)
{
    (void)self;
    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, &handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    struct UsbInterface *interface = NULL;
    return UsbSelectInterfaceSetting((const UsbInterfaceHandle *)handle, settingIndex, &interface);
}

static int32_t UsbDdkGetCurrentInterfaceSetting(struct IUsbDdk *self, uint64_t interfaceHandle, uint8_t *settingIndex)
{
    (void)self;
    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, &handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    return UsbGetInterfaceSetting((const UsbInterfaceHandle *)handle, settingIndex);
}

static int32_t UsbDdkSendControlReadRequest(struct IUsbDdk *self, uint64_t interfaceHandle,
    const struct UsbControlRequestSetup *setup, uint8_t *data, uint32_t *dataLen)
{
    (void)self;
    if (setup == NULL || data == NULL || dataLen == NULL || *dataLen > MAX_CONTROL_BUFF_SIZE) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, &handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    struct UsbRequest *request = UsbAllocRequest((const UsbInterfaceHandle *)handle, 0, MAX_CONTROL_BUFF_SIZE);
    if (request == NULL) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.interfaceId = USB_CTRL_INTERFACE_ID;
    params.requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    params.timeout = setup->timeout;
    params.ctrlReq.target = GET_CTRL_REQ_RECIP(setup->requestType);
    params.ctrlReq.reqType = GET_CTRL_REQ_TYPE(setup->requestType);
    params.ctrlReq.directon = GET_CTRL_REQ_DIR(setup->requestType);
    params.ctrlReq.request = setup->requestCmd;
    params.ctrlReq.value = setup->value;
    params.ctrlReq.index = setup->index;
    params.ctrlReq.buffer = (void *)data;
    params.ctrlReq.length = *dataLen;

    ret = UsbFillRequest(request, (const UsbInterfaceHandle *)handle, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = memcpy_s(data, *dataLen, request->compInfo.buffer, request->compInfo.actualLength);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed %{public}d", __func__, ret);
        goto FINISHED;
    }
    *dataLen = request->compInfo.actualLength;

FINISHED:
    (void)UsbFreeRequest(request);
    return ret;
}

static int32_t UsbDdkSendControlWriteRequest(struct IUsbDdk *self, uint64_t interfaceHandle,
    const struct UsbControlRequestSetup *setup, const uint8_t *data, uint32_t dataLen)
{
    (void)self;
    bool isInvalidParam = (setup == NULL || data == NULL || dataLen > MAX_CONTROL_BUFF_SIZE);
    if (isInvalidParam) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(interfaceHandle, &handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    struct UsbRequest *request = UsbAllocRequest((const UsbInterfaceHandle *)handle, 0, MAX_CONTROL_BUFF_SIZE);
    if (request == NULL) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.interfaceId = USB_CTRL_INTERFACE_ID;
    params.pipeAddress = 0;
    params.pipeId = 0;
    params.requestType = USB_REQUEST_PARAMS_CTRL_TYPE;
    params.timeout = setup->timeout;
    params.ctrlReq.target = GET_CTRL_REQ_RECIP(setup->requestType);
    params.ctrlReq.reqType = GET_CTRL_REQ_TYPE(setup->requestType);
    params.ctrlReq.directon = GET_CTRL_REQ_DIR(setup->requestType);
    params.ctrlReq.request = setup->requestCmd;
    params.ctrlReq.value = setup->value;
    params.ctrlReq.index = setup->index;
    params.ctrlReq.buffer = (void *)data;
    params.ctrlReq.length = dataLen;

    ret = UsbFillRequest(request, (const UsbInterfaceHandle *)handle, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

FINISHED:
    (void)UsbFreeRequest(request);
    return ret;
}

static int32_t UsbDdkSendPipeReadRequest(
    struct IUsbDdk *self, const struct UsbRequestPipe *pipe, uint8_t *buffer, uint32_t *bufferLen)
{
    (void)self;
    bool isInvalidParam = (pipe == NULL || buffer == NULL || bufferLen == NULL || *bufferLen > MAX_BUFF_SIZE);
    if (isInvalidParam) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(pipe->interfaceHandle, &handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    struct UsbRequest *request = UsbAllocRequest((const UsbInterfaceHandle *)handle, 0, *bufferLen);
    if (request == NULL) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.pipeId = pipe->endpoint;
    params.pipeAddress = pipe->endpoint;
    params.requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params.timeout = pipe->timeout;
    params.dataReq.directon = USB_REQUEST_DIR_FROM_DEVICE;
    params.dataReq.length = *bufferLen;

    ret = UsbFillRequest(request, (const UsbInterfaceHandle *)handle, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = memcpy_s(buffer, *bufferLen, request->compInfo.buffer, request->compInfo.actualLength);
    if (ret != EOK) {
        HDF_LOGE("%{public}s memcpy failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    *bufferLen = request->compInfo.actualLength;
FINISHED:
    (void)UsbFreeRequest(request);
    return ret;
}

static int32_t UsbDdkSendPipeWriteRequest(struct IUsbDdk *self, const struct UsbRequestPipe *pipe,
    const uint8_t *buffer, uint32_t bufferLen, uint32_t *transferredLength)
{
    (void)self;
    bool isInvalidParam = (pipe == NULL || buffer == NULL || transferredLength == NULL || bufferLen > MAX_BUFF_SIZE);
    if (isInvalidParam) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint64_t handle = 0;
    int32_t ret = UsbDdkUnHash(pipe->interfaceHandle, &handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s unhash failed %{public}d", __func__, ret);
        return ret;
    }

    struct UsbRequest *request = UsbAllocRequest((const UsbInterfaceHandle *)handle, 0, bufferLen);
    if (request == NULL) {
        HDF_LOGE("%{public}s alloc request failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    struct UsbRequestParams params;
    (void)memset_s(&params, sizeof(struct UsbRequestParams), 0, sizeof(struct UsbRequestParams));
    params.pipeId = pipe->endpoint;
    params.pipeAddress = pipe->endpoint;
    params.requestType = USB_REQUEST_PARAMS_DATA_TYPE;
    params.timeout = pipe->timeout;
    params.dataReq.directon = USB_REQUEST_DIR_TO_DEVICE;
    params.dataReq.length = bufferLen;
    params.dataReq.buffer = (unsigned char *)buffer;

    ret = UsbFillRequest(request, (const UsbInterfaceHandle *)handle, &params);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fill request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    ret = UsbSubmitRequestSync(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s submit request failed %{public}d", __func__, ret);
        goto FINISHED;
    }

    *transferredLength = request->compInfo.actualLength;
FINISHED:
    (void)UsbFreeRequest(request);
    return ret;
}

static int32_t UsbDdkGetVersion(struct IUsbDdk *self, uint32_t *majorVer, uint32_t *minorVer)
{
    (void)self;
    *majorVer = IUSB_DDK_MAJOR_VERSION;
    *minorVer = IUSB_DDK_MINOR_VERSION;
    return HDF_SUCCESS;
}

struct IUsbDdk *UsbDdkImplGetInstance(void)
{
    struct UsbDdkService *service = (struct UsbDdkService *)OsalMemCalloc(sizeof(struct UsbDdkService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc UsbDdkService obj failed!", __func__);
        return NULL;
    }

    OsalMutexInit(&g_listenerList.lock);
    DListHeadInit(&g_listenerList.head);

    service->interface.init = UsbDdkInit;
    service->interface.release = UsbDdkRelease;
    service->interface.registerNotification = UsbDdkRegisterNotification;
    service->interface.unRegisterNotification = UsbDdkUnRegisterNotification;
    service->interface.getDeviceDescriptor = UsbDdkGetDeviceDescriptor;
    service->interface.getConfigDescriptor = UsbDdkGetConfigDescriptor;
    service->interface.claimInterface = UsbDdkClaimInterface;
    service->interface.releaseInterface = UsbDdkReleaseInterface;
    service->interface.selectInterfaceSetting = UsbDdkSelectInterfaceSetting;
    service->interface.getCurrentInterfaceSetting = UsbDdkGetCurrentInterfaceSetting;
    service->interface.sendControlReadRequest = UsbDdkSendControlReadRequest;
    service->interface.sendControlWriteRequest = UsbDdkSendControlWriteRequest;
    service->interface.sendPipeReadRequest = UsbDdkSendPipeReadRequest;
    service->interface.sendPipeWriteRequest = UsbDdkSendPipeWriteRequest;
    service->interface.getVersion = UsbDdkGetVersion;
    return &service->interface;
}

void UsbDdkImplRelease(struct IUsbDdk *instance)
{
    if (instance == NULL) {
        return;
    }
    OsalMutexDestroy(&g_listenerList.lock);
    OsalMemFree(instance);
}
