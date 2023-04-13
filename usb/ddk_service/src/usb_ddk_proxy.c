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

#include "iusb_ddk.h"
#include <hdf_base.h>
#include <hdf_dlist.h>
#include <hdf_log.h>
#include <hdf_sbuf.h>
#include <hdi_support.h>
#include <osal_mem.h>
#include <securec.h>
#include <servmgr_hdi.h>
#include <stub_collector.h>

#include "usb_config_desc_parser.h"

#define HDF_LOG_TAG usb_ddk_proxy

struct UsbDdkProxy {
    struct IUsbDdk impl;
    struct HdfRemoteService *remote;
};

static bool ReadPodArray(struct HdfSBuf *parcel, void *data, uint32_t elementSize, uint32_t *count)
{
    uint32_t elementCount = 0;
    if (!HdfSbufReadUint32(parcel, &elementCount)) {
        HDF_LOGE("%{public}s: failed to read array size", __func__);
        return false;
    }

    if (elementCount > HDI_BUFF_MAX_SIZE / elementSize) {
        HDF_LOGE("%{public}s: invalid elementCount", __func__);
        return false;
    }

    if (elementCount == 0) {
        goto FINISHED;
    }

    const void *dataPtr = HdfSbufReadUnpadBuffer(parcel, elementSize * elementCount);
    if (dataPtr == NULL) {
        HDF_LOGE("%{public}s: failed to read array", __func__);
        return false;
    }

    if (memcpy_s(data, elementSize * elementCount, dataPtr, elementSize * elementCount) != EOK) {
        HDF_LOGE("%{public}s: failed to copy array data", __func__);
        return false;
    }

FINISHED:
    *count = elementCount;
    return true;
}

static bool WriteInterface(struct HdfSBuf *parcel, const char *desc, void *interface)
{
    if (interface == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        return false;
    }

    struct HdfRemoteService **stub = StubCollectorGetOrNewObject(desc, interface);
    if (stub == NULL) {
        HDF_LOGE("%{public}s: failed to get stub of '%{public}s'", __func__, desc);
        return false;
    }

    if (HdfSbufWriteRemoteService(parcel, *stub) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to write remote service", __func__);
        return false;
    }

    return true;
}

static int32_t UsbDdkProxyCall(
    struct IUsbDdk *self, int32_t id, struct HdfSBuf *data, struct HdfSBuf *reply, bool isOneWay)
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

static int32_t UsbDdkProxyInit(struct IUsbDdk *self)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_INIT, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyRelease(struct IUsbDdk *self)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_RELEASE, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyRegisterNotification(struct IUsbDdk *self, struct INotificationCallback *cb)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!WriteInterface(usbDdkData, INOTIFICATIONCALLBACK_INTERFACE_DESC, cb)) {
        HDF_LOGE("%{public}s: write cb failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_REGISTER_NOTIFICATION, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyUnRegisterNotification(struct IUsbDdk *self, struct INotificationCallback *cb)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!WriteInterface(usbDdkData, INOTIFICATIONCALLBACK_INTERFACE_DESC, cb)) {
        HDF_LOGE("%{public}s: write cb failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_UN_REGISTER_NOTIFICATION, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyGetDeviceDescriptor(
    struct IUsbDdk *self, uint64_t devHandle, struct UsbDeviceDescriptor *desc)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(usbDdkData, devHandle)) {
        HDF_LOGE("%{public}s: write devHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_GET_DEVICE_DESCRIPTOR, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!UsbDeviceDescriptorBlockUnmarshalling(usbDdkReply, desc)) {
        HDF_LOGE("%{public}s: read desc failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyFillGetCfgDescParam(
    struct HdfSBuf *usbDdkData, uint64_t devHandle, uint8_t configIndex, uint32_t configDescLen)
{
    if (!HdfSbufWriteUint64(usbDdkData, devHandle)) {
        HDF_LOGE("%{public}s: write devHandle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint8(usbDdkData, configIndex)) {
        HDF_LOGE("%{public}s: write configIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(usbDdkData, configDescLen)) {
        HDF_LOGE("%{public}s: write configDesc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t UsbDdkProxyGetConfigDescriptor(
    struct IUsbDdk *self, uint64_t devHandle, uint8_t configIndex, uint8_t *configDesc, uint32_t *configDescLen)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyFillGetCfgDescParam(usbDdkData, devHandle, configIndex, *configDescLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: fill param failed!", __func__);
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_GET_CONFIG_DESCRIPTOR, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!ReadPodArray(usbDdkReply, configDesc, sizeof(uint8_t), configDescLen)) {
        HDF_LOGE("%{public}s: failed to read configDesc", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyFillClaimInterfaceParam(
    struct HdfSBuf *usbDdkData, uint64_t devHandle, uint8_t interfaceIndex, enum UsbClaimMode claimMode)
{
    if (!HdfSbufWriteUint64(usbDdkData, devHandle)) {
        HDF_LOGE("%{public}s: write devHandle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint8(usbDdkData, interfaceIndex)) {
        HDF_LOGE("%{public}s: write interfaceIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint64(usbDdkData, (uint64_t)claimMode)) {
        HDF_LOGE("%{public}s: write claimMode failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t UsbDdkProxyClaimInterface(struct IUsbDdk *self, uint64_t devHandle, uint8_t interfaceIndex,
    enum UsbClaimMode claimMode, uint64_t *interfaceHandle)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyFillClaimInterfaceParam(usbDdkData, devHandle, interfaceIndex, claimMode);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: fill param failed", __func__);
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_CLAIM_INTERFACE, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!HdfSbufReadUint64(usbDdkReply, interfaceHandle)) {
        HDF_LOGE("%{public}s: read interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyReleaseInterface(struct IUsbDdk *self, uint64_t interfaceHandle)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(usbDdkData, interfaceHandle)) {
        HDF_LOGE("%{public}s: write interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_RELEASE_INTERFACE, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxySelectInterfaceSetting(struct IUsbDdk *self, uint64_t interfaceHandle, uint8_t settingIndex)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(usbDdkData, interfaceHandle)) {
        HDF_LOGE("%{public}s: write interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint8(usbDdkData, settingIndex)) {
        HDF_LOGE("%{public}s: write settingIndex failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_SELECT_INTERFACE_SETTING, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyGetCurrentInterfaceSetting(
    struct IUsbDdk *self, uint64_t interfaceHandle, uint8_t *settingIndex)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(usbDdkData, interfaceHandle)) {
        HDF_LOGE("%{public}s: write interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_GET_CURRENT_INTERFACE_SETTING, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!HdfSbufReadUint8(usbDdkReply, settingIndex)) {
        HDF_LOGE("%{public}s: read settingIndex failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyFillControlReadParam(
    struct HdfSBuf *usbDdkData, uint64_t interfaceHandle, const struct UsbControlRequestSetup *setup, uint32_t dataLen)
{
    if (!HdfSbufWriteUint64(usbDdkData, interfaceHandle)) {
        HDF_LOGE("%{public}s: write interfaceHandle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!UsbControlRequestSetupBlockMarshalling(usbDdkData, setup)) {
        HDF_LOGE("%{public}s: write setup failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(usbDdkData, dataLen)) {
        HDF_LOGE("%{public}s: write data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t UsbDdkProxySendControlReadRequest(struct IUsbDdk *self, uint64_t interfaceHandle,
    const struct UsbControlRequestSetup *setup, uint8_t *data, uint32_t *dataLen)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyFillControlReadParam(usbDdkData, interfaceHandle, setup, *dataLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: fill param failed", __func__);
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_SEND_CONTROL_READ_REQUEST, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!ReadPodArray(usbDdkReply, data, sizeof(uint8_t), dataLen)) {
        HDF_LOGE("%{public}s: failed to read data", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxySendControlWriteRequest(struct IUsbDdk *self, uint64_t interfaceHandle,
    const struct UsbControlRequestSetup *setup, const uint8_t *data, uint32_t dataLen)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(usbDdkData, interfaceHandle)) {
        HDF_LOGE("%{public}s: write interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!UsbControlRequestSetupBlockMarshalling(usbDdkData, setup)) {
        HDF_LOGE("%{public}s: write setup failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!WritePodArray(usbDdkData, data, sizeof(uint8_t), dataLen)) {
        HDF_LOGE("%{public}s: failed to write data", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_SEND_CONTROL_WRITE_REQUEST, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxySendPipeReadRequest(
    struct IUsbDdk *self, const struct UsbRequestPipe *pipe, uint8_t *buffer, uint32_t *bufferLen)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!UsbRequestPipeBlockMarshalling(usbDdkData, pipe)) {
        HDF_LOGE("%{public}s: write pipe failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint32(usbDdkData, *bufferLen)) {
        HDF_LOGE("%{public}s: write buffer failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_SEND_PIPE_READ_REQUEST, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!ReadPodArray(usbDdkReply, buffer, sizeof(uint8_t), bufferLen)) {
        HDF_LOGE("%{public}s: failed to read buffer", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxySendPipeWriteRequest(struct IUsbDdk *self, const struct UsbRequestPipe *pipe,
    const uint8_t *buffer, uint32_t bufferLen, uint32_t *transferredLength)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!UsbRequestPipeBlockMarshalling(usbDdkData, pipe)) {
        HDF_LOGE("%{public}s: write pipe failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!WritePodArray(usbDdkData, buffer, sizeof(uint8_t), bufferLen)) {
        HDF_LOGE("%{public}s: failed to write buffer", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_SEND_PIPE_WRITE_REQUEST, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!HdfSbufReadUint32(usbDdkReply, transferredLength)) {
        HDF_LOGE("%{public}s: read transferredLength failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static int32_t UsbDdkProxyGetVersion(struct IUsbDdk *self, uint32_t *majorVer, uint32_t *minorVer)
{
    int32_t usbDdkRet = HDF_FAILURE;

    struct HdfSBuf *usbDdkData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *usbDdkReply = HdfSbufTypedObtain(SBUF_IPC);

    if (usbDdkData == NULL || usbDdkReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (self == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->asObject(self), usbDdkData)) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    usbDdkRet = UsbDdkProxyCall(self, CMD_USB_DDK_GET_VERSION, usbDdkData, usbDdkReply, false);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, usbDdkRet);
        goto FINISHED;
    }

    if (!HdfSbufReadUint32(usbDdkReply, majorVer)) {
        HDF_LOGE("%{public}s: read majorVer failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufReadUint32(usbDdkReply, minorVer)) {
        HDF_LOGE("%{public}s: read minorVer failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (usbDdkData != NULL) {
        HdfSbufRecycle(usbDdkData);
    }
    if (usbDdkReply != NULL) {
        HdfSbufRecycle(usbDdkReply);
    }
    return usbDdkRet;
}

static struct HdfRemoteService *UsbDdkProxyAsObject(struct IUsbDdk *self)
{
    if (self == NULL) {
        return NULL;
    }
    struct UsbDdkProxy *proxy = CONTAINER_OF(self, struct UsbDdkProxy, impl);
    return proxy->remote;
}

static void UsbDdkProxyConstruct(struct IUsbDdk *impl)
{
    impl->init = UsbDdkProxyInit;
    impl->release = UsbDdkProxyRelease;
    impl->registerNotification = UsbDdkProxyRegisterNotification;
    impl->unRegisterNotification = UsbDdkProxyUnRegisterNotification;
    impl->getDeviceDescriptor = UsbDdkProxyGetDeviceDescriptor;
    impl->getConfigDescriptor = UsbDdkProxyGetConfigDescriptor;
    impl->claimInterface = UsbDdkProxyClaimInterface;
    impl->releaseInterface = UsbDdkProxyReleaseInterface;
    impl->selectInterfaceSetting = UsbDdkProxySelectInterfaceSetting;
    impl->getCurrentInterfaceSetting = UsbDdkProxyGetCurrentInterfaceSetting;
    impl->sendControlReadRequest = UsbDdkProxySendControlReadRequest;
    impl->sendControlWriteRequest = UsbDdkProxySendControlWriteRequest;
    impl->sendPipeReadRequest = UsbDdkProxySendPipeReadRequest;
    impl->sendPipeWriteRequest = UsbDdkProxySendPipeWriteRequest;
    impl->getVersion = UsbDdkProxyGetVersion;
    impl->asObject = UsbDdkProxyAsObject;
}

struct IUsbDdk *IUsbDdkGet(bool isStub)
{
    return IUsbDdkGetInstance("usb_ddk_service", isStub);
}

struct IUsbDdk *IUsbDdkGetInstance(const char *serviceName, bool isStub)
{
    if (isStub) {
        const char *instName = serviceName;
        if (strcmp(instName, "usb_ddk_service") == 0) {
            instName = "service";
        }
        return LoadHdiImpl(IUSBDDK_INTERFACE_DESC, instName);
    }

    struct HDIServiceManager *serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        HDF_LOGE("%{public}s: HDIServiceManager not found!", __func__);
        return NULL;
    }

    struct HdfRemoteService *remote = serviceMgr->GetService(serviceMgr, serviceName);
    HDIServiceManagerRelease(serviceMgr);
    if (remote == NULL) {
        HDF_LOGE("%{public}s: failed to get remote!", __func__);
        return NULL;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(remote, IUSBDDK_INTERFACE_DESC)) {
        HDF_LOGE("%{public}s: set interface token failed!", __func__);
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }

    struct UsbDdkProxy *proxy = (struct UsbDdkProxy *)OsalMemCalloc(sizeof(struct UsbDdkProxy));
    if (proxy == NULL) {
        HDF_LOGE("%{public}s: malloc IUsbDdk proxy failed!", __func__);
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }

    proxy->remote = remote;
    UsbDdkProxyConstruct(&proxy->impl);
    struct IUsbDdk *client = &proxy->impl;

    uint32_t serMajorVer = 0;
    uint32_t serMinorVer = 0;
    int32_t usbDdkRet = client->getVersion(client, &serMajorVer, &serMinorVer);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get version failed!", __func__);
        IUsbDdkRelease(false, client);
        return NULL;
    }

    if (serMajorVer != IUSB_DDK_MAJOR_VERSION) {
        HDF_LOGE("%{public}s:check version failed! version of service:%u.%u, version of client:%u.%u", __func__,
            serMajorVer, serMinorVer, IUSB_DDK_MAJOR_VERSION, IUSB_DDK_MINOR_VERSION);
        IUsbDdkRelease(false, client);
        return NULL;
    }

    return client;
}

void IUsbDdkRelease(struct IUsbDdk *instance, bool isStub)
{
    IUsbDdkReleaseInstance("usb_ddk_service", instance, isStub);
}

void IUsbDdkReleaseInstance(const char *serviceName, struct IUsbDdk *instance, bool isStub)
{
    if (instance == NULL) {
        return;
    }

    if (isStub) {
        const char *instName = serviceName;
        if (strcmp(instName, "usb_ddk_service") == 0) {
            instName = "service";
        }
        UnloadHdiImpl(IUSBDDK_INTERFACE_DESC, instName, instance);
        return;
    }

    struct UsbDdkProxy *proxy = CONTAINER_OF(instance, struct UsbDdkProxy, impl);
    HdfRemoteServiceRecycle(proxy->remote);
    OsalMemFree(proxy);
}

int32_t UsbDdkWapperGetConfigDescriptor(
    struct IUsbDdk *self, uint64_t devHandle, uint8_t configIndex, struct UsbDdkConfigDescriptor ** const config)
{
    if (self == NULL || config == NULL) {
        HDF_LOGE("%{public}s: invalid interface object", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    struct UsbConfigDescriptor cfgDesc;
    uint32_t descLen = sizeof(struct UsbConfigDescriptor);

    int32_t ret = self->getConfigDescriptor(self, devHandle, configIndex, (uint8_t *)&cfgDesc, &descLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get config descriptor failed %{public}d", __func__, ret);
        return ret;
    }

    uint8_t *buffer = (uint8_t *)OsalMemCalloc(cfgDesc.wTotalLength);

    if (buffer == NULL) {
        HDF_LOGE("%{public}s: get memory failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    descLen = cfgDesc.wTotalLength;

    ret = self->getConfigDescriptor(self, devHandle, configIndex, buffer, &descLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get config descriptor failed %{public}d", __func__, ret);
        OsalMemFree((buffer));
        return ret;
    }

    ret = DescToConfig(buffer, cfgDesc.wTotalLength, (struct UsbRawConfigDescriptor **)config);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: desc to config failed %{public}d", __func__, ret);
    }
    OsalMemFree(buffer);
    return ret;
}

void UsbDdkFreeConfigDescriptor(const struct UsbDdkConfigDescriptor * const config)
{
    UsbRawFreeConfigDescriptor((struct UsbRawConfigDescriptor *)config);
}