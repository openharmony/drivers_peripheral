/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "usb_protocol.h"
#include "usb_io_manage.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG USB_PROTOCOL

int32_t UsbProtocalFillControlSetup(const unsigned char *setup, const struct UsbControlRequest *ctrlReq)
{
    if ((setup == NULL) || (ctrlReq == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid parameter", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbRawControlSetup *setupData = (struct UsbRawControlSetup *)setup;
    int32_t ret = HDF_SUCCESS;
   
    setupData->requestType = ctrlReq->reqType;
    setupData->request     = ctrlReq->request;
    setupData->value       = CPU_TO_LE16(ctrlReq->value);
    setupData->index       = CPU_TO_LE16(ctrlReq->index);
    setupData->length      = CPU_TO_LE16(ctrlReq->length);
     
    return ret;
}

static int32_t CreateCtrPipe(const struct UsbInterfacePool *pool)
{
    int32_t ret = 0;
    struct UsbSdkInterface *interfaceObj = NULL;
    struct UsbPipe *pipe = NULL;

    if (pool == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param pool", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = UsbIfCreatInterfaceObj(pool, &interfaceObj);
    if (ret != HDF_SUCCESS) {
        return HDF_ERR_MALLOC_FAIL;
    }
    interfaceObj->interface.info.interfaceIndex = USB_CTRL_INTERFACE_ID;
    interfaceObj->interface.info.pipeNum = 1;
    interfaceObj->altSettingId = 0;
    interfaceObj->interface.info.curAltSetting = 0;
    ret = UsbIfCreatPipeObj(interfaceObj, &pipe);
    if (ret != HDF_SUCCESS) {
        return HDF_ERR_IO;
    }

    pipe->info.pipeId = 0;
    pipe->info.pipeAddress = 0;
    pipe->info.pipeDirection = USB_PIPE_DIRECTION_OUT;
    pipe->info.pipeType = USB_PIPE_TYPE_CONTROL;

    return ret;
}

static int32_t UsbInterfaceInit(struct UsbSdkInterface *interfaceObj,
    const struct UsbRawInterfaceDescriptor *iface, const struct UsbRawInterface *altsettings)
{
    struct UsbInterfaceInfo *ptr = NULL;

    if ((interfaceObj == NULL) || (iface == NULL)) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ptr = &interfaceObj->interface.info;
    ptr->pipeNum = iface->interfaceDescriptor.bNumEndpoints;
    ptr->interfaceClass = iface->interfaceDescriptor.bInterfaceClass;
    ptr->interfaceSubClass = iface->interfaceDescriptor.bInterfaceSubClass;
    ptr->interfaceProtocol = iface->interfaceDescriptor.bInterfaceProtocol;
    ptr->interfaceIndex = iface->interfaceDescriptor.bInterfaceNumber;
    ptr->altSettings = altsettings->numAltsetting;
    ptr->curAltSetting = USB_DEFAULT_ALTSETTING;

    interfaceObj->altSettingId = iface->interfaceDescriptor.bAlternateSetting;

    return HDF_SUCCESS;
}

static int32_t UsbPipeInit(struct UsbPipe *pipe, const struct UsbRawEndpointDescriptor *ep)
{
    if ((pipe == NULL) || (ep == NULL)) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    pipe->info.pipeId = ep->endpointDescriptor.bEndpointAddress;
    pipe->info.maxPacketSize = ep->endpointDescriptor.wMaxPacketSize;
    pipe->info.interval = ep->endpointDescriptor.bInterval;
    pipe->info.pipeType =  ep->endpointDescriptor.bmAttributes & USB_DDK_ENDPOINT_XFERTYPE_MASK;
    pipe->info.pipeAddress = ep->endpointDescriptor.bEndpointAddress & USB_DDK_ENDPOINT_NUMBER_MASK;
    pipe->info.pipeDirection = ep->endpointDescriptor.bEndpointAddress & USB_DDK_ENDPOINT_DIR_MASK;
    return HDF_SUCCESS;
}

static const struct UsbRawInterface *UsbGetInterfaceFromConfig(
    const struct UsbRawConfigDescriptor *config, uint8_t idx)
{
    if (config == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return NULL;
    }
    if (config->configDescriptor.bNumInterfaces < idx + 1) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return NULL;
    }

    return config->interface[idx];
}

/* The default AltSetting is 0 */
static const struct UsbRawInterfaceDescriptor *UsbGetInterfaceDesc(
    const struct UsbRawInterface *altSetting, uint8_t settingIndex)
{
    if (altSetting == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param altSetting", __func__, __LINE__);
        return NULL;
    }

    return &altSetting->altsetting[settingIndex];
}

static const struct UsbRawEndpointDescriptor *UsbGetEpDesc(
    const struct UsbRawInterfaceDescriptor *ifDes, uint8_t idx)
{
    if (ifDes == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param ifDes", __func__, __LINE__);
        return NULL;
    }
    if (ifDes->interfaceDescriptor.bNumEndpoints < (idx + 1)) {
        HDF_LOGE("%{public}s:invalid param numEp:%{public}d+idx:%{public}hhu",
            __func__, ifDes->interfaceDescriptor.bNumEndpoints, idx);
        return NULL;
    }

    return &ifDes->endPoint[idx];
}

static int32_t UsbProtocalCreatePipeObj(
    const struct UsbRawInterfaceDescriptor *ifDes, const struct UsbSdkInterface *interfaceObj)
{
    int32_t ret = HDF_SUCCESS;
    const struct UsbRawEndpointDescriptor *ep = NULL;
    struct UsbPipe *pipe = NULL;

    for (int32_t cnep = 0; cnep < ifDes->interfaceDescriptor.bNumEndpoints; cnep++) {
        if (ifDes->interfaceDescriptor.bNumEndpoints > USB_MAXENDPOINTS) {
            HDF_LOGE("%{public}s:%{public}d bNumEndpoints=%{public}d is error",
                __func__, __LINE__, ifDes->interfaceDescriptor.bNumEndpoints);
            ret = HDF_DEV_ERR_NORANGE;
            break;
        }
        ep = UsbGetEpDesc(ifDes, cnep);
        if (ep == NULL) {
            ret = HDF_ERR_INVALID_PARAM;
            break;
        }
        ret = UsbIfCreatPipeObj(interfaceObj, &pipe);
        if (ret != HDF_SUCCESS) {
            break;
        }
        ret = UsbPipeInit(pipe, ep);
        if (ret != HDF_SUCCESS) {
            break;
        }
    }

    return ret;
}

static int32_t UsbProtocalCreatInterfaceObj(const struct UsbRawConfigDescriptor *config,
    const struct UsbInterfacePool *interfacePool)
{
    uint8_t j;
    int32_t ret = HDF_SUCCESS;
    const struct UsbRawInterface *itface = NULL;
    const struct UsbRawInterfaceDescriptor *ifDes = NULL;
    struct UsbSdkInterface *interfaceObj = NULL;

    for (int32_t i = 0; i < config->configDescriptor.bNumInterfaces; i++) {
        itface = UsbGetInterfaceFromConfig(config, i);
        if (itface == NULL) {
            ret = HDF_ERR_INVALID_PARAM;
            goto ERROR;
        }

        for (j = 0; j < itface->numAltsetting; j++) {
            ifDes = UsbGetInterfaceDesc(itface, j);
            if (ifDes == NULL) {
                ret = HDF_ERR_INVALID_PARAM;
                goto ERROR;
            }

            ret = UsbIfCreatInterfaceObj(interfacePool, &interfaceObj);
            if (ret != HDF_SUCCESS) {
                goto ERROR;
            }

            ret = UsbInterfaceInit(interfaceObj, ifDes, itface);
            if (ret != 0) {
                ret = HDF_ERR_IO;
                goto ERROR;
            }

            ret = UsbProtocalCreatePipeObj(ifDes, interfaceObj);
            if (ret != HDF_SUCCESS) {
                goto ERROR;
            }
        }
    }

ERROR:
    return ret;
}

int32_t UsbProtocalParseDescriptor(struct UsbDeviceHandle *devHandle, uint8_t busNum, uint8_t devAddr)
{
    int32_t ret;
    int32_t activeConfig = -1;
    struct UsbInterfacePool *interfacePool = NULL;
    struct UsbRawConfigDescriptor *config = NULL;

    if ((devHandle == NULL) || (devHandle->dev == NULL) || (devHandle->dev->session == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = UsbIfCreatInterfacePool(devHandle->dev->session, busNum, devAddr, &interfacePool);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbIfCreatInterfacePool error", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    interfacePool->session = devHandle->dev->session;
    interfacePool->device = devHandle->dev;
    devHandle->dev->privateObject = (void *)interfacePool;
    HDF_LOGE("%{public}s:%{public}d devHandle = %{public}p", __func__, __LINE__, devHandle);
    ret = CreateCtrPipe(interfacePool);
    if (ret != HDF_SUCCESS) {
        goto ERR;
    }

    ret = RawGetConfiguration(devHandle, &activeConfig);
    if (ret != HDF_SUCCESS) {
        goto ERR;
    }

    ret = RawGetConfigDescriptor(devHandle->dev, activeConfig, &config);
    if (ret != HDF_SUCCESS) {
        goto FREE_CONFIG;
    }

    ret = UsbProtocalCreatInterfaceObj(config, interfacePool);
    if (ret != HDF_SUCCESS) {
        goto FREE_CONFIG;
    }

FREE_CONFIG:
    if (config != NULL) {
        RawClearConfiguration(config);
        RawUsbMemFree(config);
        config = NULL;
    }

    if (ret == HDF_SUCCESS) {
        return ret;
    }

ERR:
    (void)UsbIfDestroyInterfaceObj(interfacePool, NULL);
    return ret;
}

