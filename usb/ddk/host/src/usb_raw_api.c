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

#include "usb_raw_api.h"
#include "usb_raw_api_library.h"

#define HDF_LOG_TAG USB_RAW_API

int UsbRawInit(struct UsbSession **session)
{
    return RawInit(session);
}

int UsbRawExit(struct UsbSession *session)
{
    return RawExit(session);
}

UsbRawHandle *UsbRawOpenDevice(struct UsbSession *session, uint8_t busNum, uint8_t usbAddr)
{
    return (UsbRawHandle *)RawOpenDevice(session, busNum, usbAddr);
}

int UsbRawCloseDevice(UsbRawHandle *devHandle)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawCloseDevice((struct UsbDeviceHandle *)devHandle);
}

int UsbRawSendControlRequest(struct UsbRawRequest *request, UsbRawHandle *devHandle,
    struct UsbControlRequestData *requestData)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;

    if ((request == NULL) || (devHandle == NULL) || (requestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawSendControlRequest(hostRequest, (struct UsbDeviceHandle *)devHandle, requestData);
}

int UsbRawSendBulkRequest(struct UsbRawRequest *request, UsbRawHandle *devHandle,
    struct UsbRequestData *requestData)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;

    if ((request == NULL) || (devHandle == NULL) || (requestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawSendBulkRequest(hostRequest, (struct UsbDeviceHandle *)devHandle, requestData);
}

int UsbRawSendInterruptRequest(struct UsbRawRequest *request, UsbRawHandle *devHandle,
    struct UsbRequestData *requestData)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;

    if ((request == NULL) || (devHandle == NULL) || (requestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawSendInterruptRequest(hostRequest, (struct UsbDeviceHandle *)devHandle, requestData);
}

int UsbRawGetConfigDescriptor(UsbRawDevice *rawDev, uint8_t configIndex,
    struct UsbRawConfigDescriptor **config)
{
    struct UsbDevice *dev = (struct UsbDevice *)rawDev;

    if ((dev == NULL) || (config == NULL)) {
        HDF_LOGE("%{public}s:%{public}d dev or config is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawGetConfigDescriptor(dev, configIndex, config);
}

void UsbRawFreeConfigDescriptor(struct UsbRawConfigDescriptor *config)
{
    if (config == NULL) {
        HDF_LOGE("%{public}s:%{public}d config is NULL", __func__, __LINE__);
        return;
    }

    RawClearConfiguration(config);
    OsalMemFree(config);
    config = NULL;
}

int UsbRawGetConfiguration(UsbRawHandle *devHandle, int *config)
{
    if ((devHandle == NULL) || (config == NULL)) {
        HDF_LOGE("%{public}s:%{public}d dev or config is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawGetConfiguration((struct UsbDeviceHandle *)devHandle, config);
}

int UsbRawSetConfiguration(UsbRawHandle *devHandle, int config)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d dev is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawSetConfiguration((struct UsbDeviceHandle *)devHandle, config);
}

int UsbRawGetDescriptor(struct UsbRawRequest *request, UsbRawHandle *devHandle, struct UsbRawDescriptorParam *param,
    unsigned char *data)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;

    if ((request == NULL) || (devHandle == NULL) || (param == NULL) || (data == NULL)) {
        HDF_LOGE("%{public}s:%{public}d request or devHandle is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawGetDescriptor(hostRequest, (struct UsbDeviceHandle *)devHandle, param, data);
}

UsbRawDevice *UsbRawGetDevice(UsbRawHandle *devHandle)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is NULL ", __func__, __LINE__);
        return NULL;
    }

    return (UsbRawDevice *)RawGetDevice((struct UsbDeviceHandle *)devHandle);
}

int UsbRawGetDeviceDescriptor(UsbRawDevice *rawDev, struct UsbDeviceDescriptor *desc)
{
    struct UsbDevice *dev = (struct UsbDevice *)rawDev;

    if ((dev == NULL) || (desc == NULL)) {
        HDF_LOGE("%{public}s:%{public}d dev or desc is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawGetDeviceDescriptor(dev, desc);
}

int UsbRawClaimInterface(UsbRawHandle *devHandle, int interfaceNumber)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawClaimInterface((struct UsbDeviceHandle *)devHandle, interfaceNumber);
}

int UsbRawReleaseInterface(UsbRawHandle *devHandle, int interfaceNumber)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawReleaseInterface((struct UsbDeviceHandle *)devHandle, interfaceNumber);
}

int UsbRawResetDevice(UsbRawHandle *devHandle)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawResetDevice((struct UsbDeviceHandle *)devHandle);
}

struct UsbRawRequest *UsbRawAllocRequest(UsbRawHandle *devHandle, int isoPackets, int length)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is NULL", __func__, __LINE__);
        return NULL;
    }

    return (struct UsbRawRequest *)RawAllocRequest((struct UsbDeviceHandle *)devHandle, isoPackets, length);
}

int UsbRawFreeRequest(struct UsbRawRequest *request)
{
    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d request is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;

    return RawFreeRequest(hostRequest);
}

int UsbRawFillBulkRequest(struct UsbRawRequest *request, UsbRawHandle *devHandle,
    struct UsbRawFillRequestData *fillData)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;
    struct UsbFillRequestData *fillRequestData = (struct UsbFillRequestData *)fillData;

    if ((request == NULL) || (devHandle == NULL) || (fillRequestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawFillBulkRequest(hostRequest, (struct UsbDeviceHandle *)devHandle, fillRequestData);
}

int UsbRawFillControlSetup(unsigned char *setup, struct UsbControlRequestData *requestData)
{
    if ((setup == NULL) || (requestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d setup or requestData is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawFillControlSetup(setup, requestData);
}

int UsbRawFillControlRequest(struct UsbRawRequest *request, UsbRawHandle *devHandle,
    struct UsbRawFillRequestData *fillData)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;
    struct UsbFillRequestData *fillRequestData = (struct UsbFillRequestData *)fillData;

    if ((request == NULL) || (devHandle == NULL) || (fillRequestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawFillControlRequest(hostRequest, (struct UsbDeviceHandle *)devHandle, fillRequestData);
}

int UsbRawFillInterruptRequest(struct UsbRawRequest *request, UsbRawHandle *devHandle,
    struct UsbRawFillRequestData *fillData)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;
    struct UsbFillRequestData *fillRequestData = (struct UsbFillRequestData *)fillData;

    if ((request == NULL) || (devHandle == NULL) || (fillRequestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawFillInterruptRequest(hostRequest, (struct UsbDeviceHandle *)devHandle, fillRequestData);
}

int UsbRawFillIsoRequest(struct UsbRawRequest *request, UsbRawHandle *devHandle,
    struct UsbRawFillRequestData *fillData)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;
    struct UsbFillRequestData *fillRequestData = (struct UsbFillRequestData *)fillData;

    if ((request == NULL) || (devHandle == NULL) || (fillRequestData == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawFillIsoRequest(hostRequest, (struct UsbDeviceHandle *)devHandle, fillRequestData);
}

int UsbRawSubmitRequest(struct UsbRawRequest *request)
{
    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;

    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d request is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawSubmitRequest(hostRequest);
}

int UsbRawCancelRequest(struct UsbRawRequest *request)
{
    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d request is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbHostRequest *hostRequest = (struct UsbHostRequest *)request;

    return RawCancelRequest(hostRequest);
}

int UsbRawHandleRequests(UsbRawHandle *devHandle)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d devHandle is NULL", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return RawHandleRequest((struct UsbDeviceHandle *)devHandle);
}
