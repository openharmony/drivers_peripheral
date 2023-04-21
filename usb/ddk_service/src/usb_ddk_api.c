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

#include "usb_ddk_api.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "iusb_ddk.h"
#include "usb_ddk_types.h"

#define HDF_LOG_TAG usb_ddk_api

struct IUsbDdk *g_ddk = NULL;

int32_t OH_Usb_Init()
{
    g_ddk = IUsbDdkGet(false);
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s get ddk failed", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    return g_ddk->init(g_ddk);
}

void OH_Usb_Release()
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s ddk is null", __func__);
        return;
    }
    g_ddk->release(g_ddk);
    IUsbDdkRelease(g_ddk, false);
}

int32_t OH_Usb_RegisterNotification(struct INotificationCallback *cb)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (cb == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->registerNotification(g_ddk, cb);
}

int32_t OH_Usb_UnRegisterNotification(struct INotificationCallback *cb)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (cb == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->unRegisterNotification(g_ddk, cb);
}

int32_t OH_Usb_GetDeviceDescriptor(uint64_t devHandle, struct UsbDeviceDescriptor *desc)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (desc == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->getDeviceDescriptor(g_ddk, devHandle, desc);
}

int32_t OH_Usb_GetConfigDescriptor(
    uint64_t devHandle, uint8_t configIndex, struct UsbDdkConfigDescriptor ** const config)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (config == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return UsbDdkWapperGetConfigDescriptor(g_ddk, devHandle, configIndex, config);
}

void OH_Usb_FreeConfigDescriptor(const struct UsbDdkConfigDescriptor * const config)
{
    return UsbDdkFreeConfigDescriptor(config);
}

int32_t OH_Usb_ClaimInterface(
    uint64_t devHandle, uint8_t interfaceIndex, enum UsbClaimMode claimMode, uint64_t *interfaceHandle)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (interfaceHandle == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->claimInterface(g_ddk, devHandle, interfaceIndex, claimMode, interfaceHandle);
}

int32_t OH_Usb_ReleaseInterface(uint64_t interfaceHandle)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    return g_ddk->releaseInterface(g_ddk, interfaceHandle);
}

int32_t OH_Usb_SelectInterfaceSetting(uint64_t interfaceHandle, uint8_t settingIndex)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    return g_ddk->selectInterfaceSetting(g_ddk, interfaceHandle, settingIndex);
}

int32_t OH_Usb_GetCurrentInterfaceSetting(uint64_t interfaceHandle, uint8_t *settingIndex)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (settingIndex == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->getCurrentInterfaceSetting(g_ddk, interfaceHandle, settingIndex);
}

int32_t OH_Usb_SendControlReadRequest(
    uint64_t interfaceHandle, const struct UsbControlRequestSetup *setup, uint8_t *data, uint32_t *dataLen)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (setup == NULL || data == NULL || dataLen == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->sendControlReadRequest(g_ddk, interfaceHandle, setup, data, dataLen);
}

int32_t OH_Usb_SendControlWriteRequest(
    uint64_t interfaceHandle, const struct UsbControlRequestSetup *setup, const uint8_t *data, uint32_t dataLen)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (setup == NULL || data == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->sendControlWriteRequest(g_ddk, interfaceHandle, setup, data, dataLen);
}

int32_t OH_Usb_SendPipeReadRequest(const struct UsbRequestPipe *pipe, uint8_t *buffer, uint32_t *bufferLen)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (pipe == NULL || buffer == NULL || bufferLen == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->sendPipeReadRequest(g_ddk, pipe, buffer, bufferLen);
}

int32_t OH_Usb_SendPipeWriteRequest(
    const struct UsbRequestPipe *pipe, const uint8_t *buffer, uint32_t bufferLen, uint32_t *transferredLength)
{
    if (g_ddk == NULL) {
        HDF_LOGE("%{public}s invalid obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (pipe == NULL || buffer == NULL || transferredLength == NULL) {
        HDF_LOGE("%{public}s param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return g_ddk->sendPipeWriteRequest(g_ddk, pipe, buffer, bufferLen, transferredLength);
}