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

#include "usb_ddk_stub.h"
#include <hdf_base.h>
#include <hdf_dlist.h>
#include <hdf_log.h>
#include <hdi_support.h>
#include <osal_mem.h>
#include <securec.h>
#include <stub_collector.h>

#define HDF_LOG_TAG usb_ddk_stub

struct IUsbDdk *IUsbDdkGet(bool isStub)
{
    return IUsbDdkGetInstance("usb_ddk_service", isStub);
}

struct IUsbDdk *IUsbDdkGetInstance(const char *serviceName, bool isStub)
{
    if (!isStub) {
        return NULL;
    }

    const char *instName = serviceName;
    if (strcmp(serviceName, "usb_ddk_service") == 0) {
        instName = "service";
    }
    return (struct IUsbDdk *)LoadHdiImpl(IUSBDDK_INTERFACE_DESC, instName);
}

void IUsbDdkRelease(struct IUsbDdk *instance, bool isStub)
{
    IUsbDdkReleaseInstance("usb_ddk_service", instance, isStub);
}

void IUsbDdkReleaseInstance(const char *serviceName, struct IUsbDdk *instance, bool isStub)
{
    if (serviceName == NULL || !isStub || instance == NULL) {
        return;
    }
    const char *instName = serviceName;
    if (strcmp(serviceName, "usb_ddk_service") == 0) {
        instName = "service";
    }
    UnloadHdiImpl(IUSBDDK_INTERFACE_DESC, instName, instance);
}

static struct INotificationCallback *ReadINotificationCallback(struct HdfSBuf *parcel)
{
    struct HdfRemoteService *remote = HdfSbufReadRemoteService(parcel);
    if (remote == NULL) {
        HDF_LOGE("%{public}s:  failed to read remote service of 'INotificationCallback'", __func__);
        return NULL;
    }

    return INotificationCallbackGet(remote);
}

static bool ReadPodArray(struct HdfSBuf *parcel, void **data, uint32_t elementSize, uint32_t *count)
{
    const void *dataPtr = NULL;
    void *memPtr = NULL;
    uint32_t elementCount = 0;
    if (count == NULL || data == NULL || elementSize == 0) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return false;
    }

    if (!HdfSbufReadUint32(parcel, &elementCount)) {
        HDF_LOGE("%{public}s: failed to read element count", __func__);
        return false;
    }

    if (elementCount > HDI_BUFF_MAX_SIZE / elementSize) {
        HDF_LOGE("%{public}s: invalid elementCount", __func__);
        return false;
    }

    if (elementCount == 0) {
        *count = elementCount;
        return true;
    }

    dataPtr = HdfSbufReadUnpadBuffer(parcel, elementSize * elementCount);
    if (dataPtr == NULL) {
        HDF_LOGE("%{public}s: failed to read buffer data", __func__);
        return false;
    }

    memPtr = OsalMemCalloc(elementSize * elementCount);
    if (memPtr == NULL) {
        HDF_LOGE("%{public}s: failed to malloc buffer", __func__);
        return false;
    }

    if (memcpy_s(memPtr, elementSize * elementCount, dataPtr, elementSize * elementCount) != EOK) {
        HDF_LOGE("%{public}s: failed to memcpy buffer", __func__);
        OsalMemFree(memPtr);
        return false;
    }

    *data = memPtr;
    *count = elementCount;
    return true;
}
static int32_t SerStubInit(struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->init == NULL) {
        HDF_LOGE("%{public}s: invalid interface function init ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->init(serviceImpl);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call init function failed!", __func__);
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static int32_t SerStubRelease(struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->release == NULL) {
        HDF_LOGE("%{public}s: invalid interface function release ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->release(serviceImpl);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call release function failed!", __func__);
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static int32_t SerStubRegisterNotification(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    struct INotificationCallback *cb = NULL;

    cb = ReadINotificationCallback(usbDdkData);
    if (cb == NULL) {
        HDF_LOGE("%{public}s: read cb failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (serviceImpl->registerNotification == NULL) {
        HDF_LOGE("%{public}s: invalid interface function registerNotification ", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    int32_t usbDdkRet = serviceImpl->registerNotification(serviceImpl, cb);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call registerNotification function failed!", __func__);
    }

    return usbDdkRet;
}

static int32_t SerStubUnRegisterNotification(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    struct INotificationCallback *cb = NULL;

    cb = ReadINotificationCallback(usbDdkData);
    if (cb == NULL) {
        HDF_LOGE("%{public}s: read cb failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->unRegisterNotification == NULL) {
        HDF_LOGE("%{public}s: invalid interface function unRegisterNotification ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->unRegisterNotification(serviceImpl, cb);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call unRegisterNotification function failed!", __func__);
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static int32_t SerStubGetDeviceDescriptor(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    uint64_t devHandle = 0;
    struct UsbDeviceDescriptor *desc = NULL;

    if (!HdfSbufReadUint64(usbDdkData, &devHandle)) {
        HDF_LOGE("%{public}s: read &devHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    desc = (struct UsbDeviceDescriptor *)OsalMemCalloc(sizeof(struct UsbDeviceDescriptor));
    if (desc == NULL) {
        HDF_LOGE("%{public}s: malloc desc failed", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->getDeviceDescriptor == NULL) {
        HDF_LOGE("%{public}s: invalid interface function getDeviceDescriptor ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->getDeviceDescriptor(serviceImpl, devHandle, desc);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call getDeviceDescriptor function failed!", __func__);
        goto FINISHED;
    }

    if (!UsbDeviceDescriptorBlockMarshalling(usbDdkReply, desc)) {
        HDF_LOGE("%{public}s: write desc failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (desc != NULL) {
        UsbDeviceDescriptorFree(desc, true);
        desc = NULL;
    }
    return usbDdkRet;
}

static int32_t SerStubGetConfigDescriptorParam(struct HdfSBuf *usbDdkData, uint64_t *devHandle, uint8_t *configIndex,
    uint8_t **configDesc, uint32_t *configDescLen)
{
    if (!HdfSbufReadUint64(usbDdkData, devHandle)) {
        HDF_LOGE("%{public}s: read &devHandle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint8(usbDdkData, configIndex)) {
        HDF_LOGE("%{public}s: read &configIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(usbDdkData, configDescLen)) {
        HDF_LOGE("%{public}s: read configDesc size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if ((*configDescLen > (HDI_BUFF_MAX_SIZE / sizeof(uint8_t))) || (*configDescLen == 0)) {
        HDF_LOGE("%{public}s: invalid configDescLen", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    *configDesc = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (*configDescLen));
    if (*configDesc == NULL) {
        HDF_LOGE("%{public}s: malloc configDesc failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    return HDF_SUCCESS;
}

static int32_t SerStubGetConfigDescriptor(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    uint64_t devHandle = 0;
    uint8_t configIndex = 0;
    uint8_t *configDesc = NULL;
    uint32_t configDescLen = 0;

    int32_t usbDdkRet =
        SerStubGetConfigDescriptorParam(usbDdkData, &devHandle, &configIndex, &configDesc, &configDescLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get param failed", __func__);
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->getConfigDescriptor == NULL) {
        HDF_LOGE("%{public}s: invalid interface function getConfigDescriptor ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->getConfigDescriptor(serviceImpl, devHandle, configIndex, configDesc, &configDescLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call getConfigDescriptor function failed!", __func__);
        goto FINISHED;
    }

    if (!WritePodArray(usbDdkReply, configDesc, sizeof(uint8_t), configDescLen)) {
        HDF_LOGE("%{public}s: failed to write configDesc", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (configDesc != NULL) {
        OsalMemFree(configDesc);
    }
    return usbDdkRet;
}

static int32_t SerStubClaimInterface(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    uint64_t devHandle = 0;
    uint8_t interfaceIndex = 0;
    enum UsbClaimMode claimMode;
    uint64_t interfaceHandle = 0;

    if (!HdfSbufReadUint64(usbDdkData, &devHandle)) {
        HDF_LOGE("%{public}s: read &devHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufReadUint8(usbDdkData, &interfaceIndex)) {
        HDF_LOGE("%{public}s: read &interfaceIndex failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    {
        uint64_t enumTmp = 0;
        if (!HdfSbufReadUint64(usbDdkData, &enumTmp)) {
            HDF_LOGE("%{public}s: read claimMode failed!", __func__);
            usbDdkRet = HDF_ERR_INVALID_PARAM;
            goto FINISHED;
        }
        claimMode = (enum UsbClaimMode)enumTmp;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->claimInterface == NULL) {
        HDF_LOGE("%{public}s: invalid interface function claimInterface ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->claimInterface(serviceImpl, devHandle, interfaceIndex, claimMode, &interfaceHandle);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call claimInterface function failed!", __func__);
        goto FINISHED;
    }

    if (!HdfSbufWriteUint64(usbDdkReply, interfaceHandle)) {
        HDF_LOGE("%{public}s: write interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static int32_t SerStubReleaseInterface(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    uint64_t interfaceHandle = 0;

    if (!HdfSbufReadUint64(usbDdkData, &interfaceHandle)) {
        HDF_LOGE("%{public}s: read &interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->releaseInterface == NULL) {
        HDF_LOGE("%{public}s: invalid interface function releaseInterface ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->releaseInterface(serviceImpl, interfaceHandle);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call releaseInterface function failed!", __func__);
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static int32_t SerStubSelectInterfaceSetting(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    uint64_t interfaceHandle = 0;
    uint8_t settingIndex = 0;

    if (!HdfSbufReadUint64(usbDdkData, &interfaceHandle)) {
        HDF_LOGE("%{public}s: read &interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufReadUint8(usbDdkData, &settingIndex)) {
        HDF_LOGE("%{public}s: read &settingIndex failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->selectInterfaceSetting == NULL) {
        HDF_LOGE("%{public}s: invalid interface function selectInterfaceSetting ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->selectInterfaceSetting(serviceImpl, interfaceHandle, settingIndex);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call selectInterfaceSetting function failed!", __func__);
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static int32_t SerStubGetCurrentInterfaceSetting(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    uint64_t interfaceHandle = 0;
    uint8_t settingIndex = 0;

    if (!HdfSbufReadUint64(usbDdkData, &interfaceHandle)) {
        HDF_LOGE("%{public}s: read &interfaceHandle failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->getCurrentInterfaceSetting == NULL) {
        HDF_LOGE("%{public}s: invalid interface function getCurrentInterfaceSetting ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->getCurrentInterfaceSetting(serviceImpl, interfaceHandle, &settingIndex);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call getCurrentInterfaceSetting function failed!", __func__);
        goto FINISHED;
    }

    if (!HdfSbufWriteUint8(usbDdkReply, settingIndex)) {
        HDF_LOGE("%{public}s: write settingIndex failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static int32_t SerStubGetControlReadRequestParam(struct HdfSBuf *usbDdkData, uint64_t *interfaceHandle,
    struct UsbControlRequestSetup **setup, uint8_t **data, uint32_t *dataLen)
{
    uint8_t *dataTmp = NULL;
    uint32_t dataLenTmp = 0;

    if (!HdfSbufReadUint64(usbDdkData, interfaceHandle)) {
        HDF_LOGE("%{public}s: read interfaceHandle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbControlRequestSetup *setupTmp =
        (struct UsbControlRequestSetup *)OsalMemCalloc(sizeof(struct UsbControlRequestSetup));
    if (setupTmp == NULL) {
        HDF_LOGE("%{public}s: malloc setup failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    if (!UsbControlRequestSetupBlockUnmarshalling(usbDdkData, setupTmp)) {
        HDF_LOGE("%{public}s: read setup failed!", __func__);
        UsbControlRequestSetupFree(setupTmp, true);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(usbDdkData, &dataLenTmp)) {
        HDF_LOGE("%{public}s: read data size failed!", __func__);
        UsbControlRequestSetupFree(setupTmp, true);
        return HDF_ERR_INVALID_PARAM;
    }

    if ((dataLenTmp > (HDI_BUFF_MAX_SIZE / sizeof(uint8_t))) || dataLenTmp == 0) {
        HDF_LOGE("%{public}s: invalid dataLen", __func__);
        UsbControlRequestSetupFree(setupTmp, true);
        return HDF_ERR_INVALID_PARAM;
    }

    dataTmp = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * dataLenTmp);
    if (dataTmp == NULL) {
        HDF_LOGE("%{public}s: malloc data failed", __func__);
        UsbControlRequestSetupFree(setupTmp, true);
        return HDF_ERR_MALLOC_FAIL;
    }

    *setup = setupTmp;
    *data = dataTmp;
    *dataLen = dataLenTmp;
    return HDF_SUCCESS;
}

static int32_t SerStubSendControlReadRequest(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    uint64_t interfaceHandle = 0;
    struct UsbControlRequestSetup *setup = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    int32_t usbDdkRet = SerStubGetControlReadRequestParam(usbDdkData, &interfaceHandle, &setup, &data, &dataLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get param failed", __func__);
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->sendControlReadRequest == NULL) {
        HDF_LOGE("%{public}s: invalid interface function sendControlReadRequest ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->sendControlReadRequest(serviceImpl, interfaceHandle, setup, data, &dataLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call sendControlReadRequest function failed!", __func__);
        goto FINISHED;
    }

    if (!WritePodArray(usbDdkReply, data, sizeof(uint8_t), dataLen)) {
        HDF_LOGE("%{public}s: failed to write data", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (setup != NULL) {
        UsbControlRequestSetupFree(setup, true);
        setup = NULL;
    }
    if (data != NULL) {
        OsalMemFree(data);
    }
    return usbDdkRet;
}

static int32_t SerStubSendControlWriteRequest(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    uint64_t interfaceHandle = 0;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    if (!HdfSbufReadUint64(usbDdkData, &interfaceHandle)) {
        HDF_LOGE("%{public}s: read &interfaceHandle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbControlRequestSetup *setup =
        (struct UsbControlRequestSetup *)OsalMemCalloc(sizeof(struct UsbControlRequestSetup));
    if (setup == NULL) {
        HDF_LOGE("%{public}s: malloc setup failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    if (!UsbControlRequestSetupBlockUnmarshalling(usbDdkData, setup)) {
        HDF_LOGE("%{public}s: read setup failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!ReadPodArray(usbDdkData, (void **)&data, sizeof(uint8_t), &dataLen)) {
        HDF_LOGE("%{public}s: failed to read data", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->sendControlWriteRequest == NULL) {
        HDF_LOGE("%{public}s: invalid interface function sendControlWriteRequest ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->sendControlWriteRequest(serviceImpl, interfaceHandle, setup, data, dataLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call sendControlWriteRequest function failed!", __func__);
        goto FINISHED;
    }

FINISHED:
    if (setup != NULL) {
        UsbControlRequestSetupFree(setup, true);
        setup = NULL;
    }
    if (data != NULL) {
        OsalMemFree(data);
    }
    return usbDdkRet;
}

static int32_t SerStubGetPipeReadRequestParam(
    struct HdfSBuf *usbDdkData, struct UsbRequestPipe **pipe, uint8_t **buffer, uint32_t *bufferLen)
{
    int32_t usbDdkRet = HDF_FAILURE;
    struct UsbRequestPipe *pipeTmp = NULL;
    uint8_t *bufferTmp = NULL;
    uint32_t bufferLenTmp = 0;

    pipeTmp = (struct UsbRequestPipe *)OsalMemCalloc(sizeof(struct UsbRequestPipe));
    if (pipeTmp == NULL) {
        HDF_LOGE("%{public}s: malloc pipeTmp failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    if (!UsbRequestPipeBlockUnmarshalling(usbDdkData, pipeTmp)) {
        HDF_LOGE("%{public}s: read pipeTmp failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufReadUint32(usbDdkData, &bufferLenTmp)) {
        HDF_LOGE("%{public}s: read buffer size failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    HDI_CHECK_VALUE_RET_GOTO(
        bufferLenTmp, >, HDI_BUFF_MAX_SIZE / sizeof(uint8_t), usbDdkRet, HDF_ERR_INVALID_PARAM, FINISHED);
    if (bufferLenTmp == 0) {
        HDF_LOGE("%{public}s: invalid bufferLenTmp", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    bufferTmp = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * bufferLenTmp);
    if (bufferTmp == NULL) {
        HDF_LOGE("%{public}s: malloc bufferTmp failed", __func__);
        usbDdkRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    *pipe = pipeTmp;
    *buffer = bufferTmp;
    *bufferLen = bufferLenTmp;
    return HDF_SUCCESS;

FINISHED:
    if (pipeTmp != NULL) {
        UsbRequestPipeFree(pipeTmp, true);
        pipeTmp = NULL;
    }
    if (bufferTmp != NULL) {
        OsalMemFree(bufferTmp);
    }
    return usbDdkRet;
}

static int32_t SerStubSendPipeReadRequest(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    struct UsbRequestPipe *pipe = NULL;
    uint8_t *buffer = NULL;
    uint32_t bufferLen = 0;

    int32_t usbDdkRet = SerStubGetPipeReadRequestParam(usbDdkData, &pipe, &buffer, &bufferLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get param failed", __func__);
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->sendPipeReadRequest == NULL) {
        HDF_LOGE("%{public}s: invalid interface function sendPipeReadRequest ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->sendPipeReadRequest(serviceImpl, pipe, buffer, &bufferLen);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call sendPipeReadRequest function failed!", __func__);
        goto FINISHED;
    }

    if (!WritePodArray(usbDdkReply, buffer, sizeof(uint8_t), bufferLen)) {
        HDF_LOGE("%{public}s: failed to write buffer", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (pipe != NULL) {
        UsbRequestPipeFree(pipe, true);
        pipe = NULL;
    }
    if (buffer != NULL) {
        OsalMemFree(buffer);
    }
    return usbDdkRet;
}

static int32_t SerStubSendPipeWriteRequest(
    struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_FAILURE;
    uint8_t *buffer = NULL;
    uint32_t bufferLen = 0;
    uint32_t transferredLength = 0;

    struct UsbRequestPipe *pipe = (struct UsbRequestPipe *)OsalMemCalloc(sizeof(struct UsbRequestPipe));
    if (pipe == NULL) {
        HDF_LOGE("%{public}s: malloc pipe failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    if (!UsbRequestPipeBlockUnmarshalling(usbDdkData, pipe)) {
        HDF_LOGE("%{public}s: read pipe failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!ReadPodArray(usbDdkData, (void **)&buffer, sizeof(uint8_t), &bufferLen)) {
        HDF_LOGE("%{public}s: failed to read buffer", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: invalid serviceImpl object", __func__);
        usbDdkRet = HDF_ERR_INVALID_OBJECT;
        goto FINISHED;
    }

    if (serviceImpl->sendPipeWriteRequest == NULL) {
        HDF_LOGE("%{public}s: invalid interface function sendPipeWriteRequest ", __func__);
        usbDdkRet = HDF_ERR_NOT_SUPPORT;
        goto FINISHED;
    }

    usbDdkRet = serviceImpl->sendPipeWriteRequest(serviceImpl, pipe, buffer, bufferLen, &transferredLength);
    if (usbDdkRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call sendPipeWriteRequest function failed!", __func__);
        goto FINISHED;
    }

    if (!HdfSbufWriteUint32(usbDdkReply, transferredLength)) {
        HDF_LOGE("%{public}s: write transferredLength failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (pipe != NULL) {
        UsbRequestPipeFree(pipe, true);
        pipe = NULL;
    }
    if (buffer != NULL) {
        OsalMemFree(buffer);
    }
    return usbDdkRet;
}

static int32_t SerStubGetVersion(struct IUsbDdk *serviceImpl, struct HdfSBuf *usbDdkData, struct HdfSBuf *usbDdkReply)
{
    int32_t usbDdkRet = HDF_SUCCESS;
    if (!HdfSbufWriteUint32(usbDdkReply, IUSB_DDK_MAJOR_VERSION)) {
        HDF_LOGE("%{public}s: write IUSB_DDK_MAJOR_VERSION failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteUint32(usbDdkReply, IUSB_DDK_MINOR_VERSION)) {
        HDF_LOGE("%{public}s: write IUSB_DDK_MINOR_VERSION failed!", __func__);
        usbDdkRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    return usbDdkRet;
}

static struct HdfRemoteService *UsbDdkStubAsObject(struct IUsbDdk *self)
{
    return NULL;
}

static int32_t UsbDdkOnRemoteRequest(
    struct HdfRemoteService *remote, int code, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct UsbDdkStub *stub = (struct UsbDdkStub *)remote;
    if (stub == NULL || stub->remote == NULL || stub->interface == NULL) {
        HDF_LOGE("%{public}s: invalid stub object", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (!HdfRemoteServiceCheckInterfaceToken(stub->remote, data)) {
        HDF_LOGE("%{public}s: interface token check failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    switch (code) {
        case CMD_USB_DDK_INIT:
            return SerStubInit(stub->interface, data, reply);
        case CMD_USB_DDK_RELEASE:
            return SerStubRelease(stub->interface, data, reply);
        case CMD_USB_DDK_REGISTER_NOTIFICATION:
            return SerStubRegisterNotification(stub->interface, data, reply);
        case CMD_USB_DDK_UN_REGISTER_NOTIFICATION:
            return SerStubUnRegisterNotification(stub->interface, data, reply);
        case CMD_USB_DDK_GET_DEVICE_DESCRIPTOR:
            return SerStubGetDeviceDescriptor(stub->interface, data, reply);
        case CMD_USB_DDK_GET_CONFIG_DESCRIPTOR:
            return SerStubGetConfigDescriptor(stub->interface, data, reply);
        case CMD_USB_DDK_CLAIM_INTERFACE:
            return SerStubClaimInterface(stub->interface, data, reply);
        case CMD_USB_DDK_RELEASE_INTERFACE:
            return SerStubReleaseInterface(stub->interface, data, reply);
        case CMD_USB_DDK_SELECT_INTERFACE_SETTING:
            return SerStubSelectInterfaceSetting(stub->interface, data, reply);
        case CMD_USB_DDK_GET_CURRENT_INTERFACE_SETTING:
            return SerStubGetCurrentInterfaceSetting(stub->interface, data, reply);
        case CMD_USB_DDK_SEND_CONTROL_READ_REQUEST:
            return SerStubSendControlReadRequest(stub->interface, data, reply);
        case CMD_USB_DDK_SEND_CONTROL_WRITE_REQUEST:
            return SerStubSendControlWriteRequest(stub->interface, data, reply);
        case CMD_USB_DDK_SEND_PIPE_READ_REQUEST:
            return SerStubSendPipeReadRequest(stub->interface, data, reply);
        case CMD_USB_DDK_SEND_PIPE_WRITE_REQUEST:
            return SerStubSendPipeWriteRequest(stub->interface, data, reply);
        case CMD_USB_DDK_GET_VERSION:
            return SerStubGetVersion(stub->interface, data, reply);
        default: {
            HDF_LOGE("%{public}s: not support cmd %{public}d", __func__, code);
            return HDF_ERR_INVALID_PARAM;
        }
    }
}

static struct HdfRemoteDispatcher g_usbddkDispatcher = {
    .Dispatch = UsbDdkOnRemoteRequest,
    .DispatchAsync = NULL,
};

static struct HdfRemoteService **UsbDdkStubNewInstance(void *impl)
{
    if (impl == NULL) {
        HDF_LOGE("%{public}s: impl is null", __func__);
        return NULL;
    }

    struct IUsbDdk *serviceImpl = (struct IUsbDdk *)impl;
    struct UsbDdkStub *stub = OsalMemCalloc(sizeof(struct UsbDdkStub));
    if (stub == NULL) {
        HDF_LOGE("%{public}s: failed to malloc stub object", __func__);
        return NULL;
    }
    stub->remote = HdfRemoteServiceObtain((struct HdfObject *)stub, &g_usbddkDispatcher);
    if (stub->remote == NULL) {
        OsalMemFree(stub);
        return NULL;
    }
    (void)HdfRemoteServiceSetInterfaceDesc(stub->remote, IUSBDDK_INTERFACE_DESC);
    stub->dispatcher.Dispatch = UsbDdkOnRemoteRequest;
    stub->interface = serviceImpl;
    stub->interface->asObject = UsbDdkStubAsObject;
    return &stub->remote;
}

static void UsbDdkStubRelease(struct HdfRemoteService **remote)
{
    if (remote == NULL) {
        return;
    }
    struct UsbDdkStub *stub = CONTAINER_OF(remote, struct UsbDdkStub, remote);
    HdfRemoteServiceRecycle(stub->remote);
    OsalMemFree(stub);
}

__attribute__((unused)) static struct StubConstructor g_usbddkConstructor = {
    .constructor = UsbDdkStubNewInstance,
    .destructor = UsbDdkStubRelease,
};

__attribute__((constructor)) static void UsbDdkStubRegister(void)
{
    HDF_LOGI("%{public}s: register stub constructor of '%{public}s'", __func__, IUSBDDK_INTERFACE_DESC);
    StubConstructorRegister(IUSBDDK_INTERFACE_DESC, &g_usbddkConstructor);
}
