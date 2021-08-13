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

#include "usb_raw_api_library.h"
#include "linux_adapter.h"

#define HDF_LOG_TAG USB_RAW_API_LIBRARY

struct UsbSession *g_usbRawDefaultSession = NULL;

static void SyncRequestCallback(void *requestArg)
{
    struct UsbHostRequest *request = (struct UsbHostRequest *)requestArg;
    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d request is NULL!", __func__, __LINE__);
        return;
    }
    int *completed = request->userData;
    *completed = 1;
    OsalSemPost(&request->sem);
}

static inline unsigned char *ControlRequestGetData(struct UsbHostRequest *request)
{
    return request->buffer + USB_RAW_CONTROL_SETUP_SIZE;
}

static int32_t HandleSyncRequestCompletion(struct UsbHostRequest *request, struct UsbRequestData *requestData)
{
    int32_t ret;
    uint32_t waitTime;

    if (request->timeout == USB_RAW_REQUEST_TIME_ZERO_MS) {
        waitTime = HDF_WAIT_FOREVER;
    } else {
        waitTime = request->timeout;
    }

    ret = OsalSemWait(&request->sem, waitTime);
    if (ret == HDF_ERR_TIMEOUT) {
        RawCancelRequest(request);
        RawHandleRequestCompletion(request, USB_REQUEST_TIMEOUT);
    } else if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalSemWait faile, ret=%{public}d ", __func__, __LINE__, ret);
        goto out;
    }

    if (requestData->requested) {
        *(requestData->requested) = request->actualLength;
    }

    switch (request->status) {
        case USB_REQUEST_COMPLETED:
            ret = HDF_SUCCESS;
            break;
        case USB_REQUEST_TIMEOUT:
            ret = HDF_ERR_TIMEOUT;
            break;
        case USB_REQUEST_NO_DEVICE:
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
        case USB_REQUEST_STALL:
        case USB_REQUEST_OVERFLOW:
        case USB_REQUEST_ERROR:
        case USB_REQUEST_CANCELLED:
            ret = HDF_ERR_IO;
            break;
        default:
            HDF_LOGW("%{public}s: unrecognised status code %{public}d", __func__, request->status);
            ret = HDF_FAILURE;
            break;
    }

out:
    OsalSemDestroy(&request->sem);
    return ret;
}

static int32_t HandleSyncRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbRequestData *requestData, unsigned char type)
{
    int32_t ret;
    int completed = 0;

    if (UsbEndpointDirOut(requestData->endPoint)) {
        ret = memcpy_s(request->buffer, request->bufLen, requestData->data, requestData->length);
        if (ret != EOK) {
            HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
            return ret;
        }
    }

    request->devHandle      = devHandle;
    request->endPoint       = requestData->endPoint;
    request->requestType    = type;
    request->timeout        = requestData->timeout;
    request->length         = requestData->length;
    request->userData       = &completed;
    request->callback       = SyncRequestCallback;
    request->userCallback   = NULL;

    ret = OsalSemInit(&request->sem, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalSemInit faile, ret=%{public}d ", __func__, __LINE__, ret);
        return ret;
    }

    ret = RawSubmitRequest(request);
    if (ret < 0) {
        OsalSemDestroy(&request->sem);
        return ret;
    }

    return HandleSyncRequestCompletion(request, requestData);
}

static void GetInterfaceNumberDes(
    struct UsbiDescriptorHeader *header, uint8_t nIntf[], uint8_t nAlts[], int *num)
{
    int inum;
    int i;
    struct UsbiInterfaceDescriptor *desc = NULL;

    desc = (struct UsbiInterfaceDescriptor *)header;
    if (desc->bLength < USB_DDK_DT_INTERFACE_SIZE) {
        HDF_LOGW("%{public}s: invalid interface descriptor length %{public}d, skipping", \
            __func__, desc->bLength);
        return;
    }

    inum = desc->bInterfaceNumber;
    for (i = 0; i < *num; ++i) {
        if (nIntf[i] == inum) {
            break;
        }
    }
    if (i < *num) {
        if (nAlts[i] < USB_MAXALTSETTING) {
            ++nAlts[i];
        }
    } else if (*num < USB_MAXINTERFACES) {
        nIntf[*num] = inum;
        nAlts[*num] = 1;
        ++*num;
    }
}

static int GetInterfaceNumber(const uint8_t *buffer, size_t size, uint8_t nIntf[], uint8_t nAlts[])
{
    struct UsbiDescriptorHeader *header = NULL;
    const uint8_t *buffer2;
    size_t size2;
    int num = 0;

    for ((buffer2 = buffer, size2 = size);
         size2 > 0;
         (buffer2 += header->bLength, size2 -= header->bLength)) {
        if (size2 < sizeof(struct UsbiDescriptorHeader)) {
            HDF_LOGW("%{public}s: descriptor has %{public}zu excess bytes", __func__, size2);
            break;
        }
        header = (struct UsbiDescriptorHeader *)buffer2;
        if ((header->bLength > size2) || (header->bLength < sizeof(struct UsbDescriptorHeader))) {
            HDF_LOGW("%{public}s: invalid descriptor lenght %{public}d, skipping remainder",
                     __func__, header->bLength);
            break;
        }

        if (header->bDescriptorType == USB_DDK_DT_INTERFACE) {
            GetInterfaceNumberDes(header, nIntf, nAlts, &num);
        }
    }

    return num;
}

static int FindNextDescriptor(const uint8_t *buffer, size_t size)
{
    struct UsbDescriptorHeader *h = NULL;
    const uint8_t *buffer0 = buffer;

    while (size > 0) {
        h = (struct UsbDescriptorHeader *)buffer;
        if (h->bDescriptorType == USB_DDK_DT_INTERFACE || h->bDescriptorType == USB_DDK_DT_ENDPOINT) {
            break;
        }
        buffer += h->bLength;
        size -= h->bLength;
    }

    return buffer - buffer0;
}
static int GetConfigDescriptor(struct UsbDevice *dev, uint8_t configIdx,
    uint8_t *buffer, size_t size)
{
    int ret;
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (dev == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!osAdapterOps->getConfigDescriptor) {
        HDF_LOGE("%{public}s: getConfigDescriptor is NULL", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ret = osAdapterOps->getConfigDescriptor(dev, configIdx, buffer, size);
    if (ret < 0) {
        HDF_LOGE("%{public}s: getConfigDescriptor error = %{public}d", __func__, ret);
        return ret;
    }

    if (ret < USB_DDK_DT_CONFIG_SIZE) {
        HDF_LOGE("%{public}s: short config descriptor read error = %{public}d", __func__, ret);
        return HDF_ERR_IO;
    } else if (ret != (int)size) {
        HDF_LOGE("%{public}s: short config descriptor read size=%{public}d, ret=%{public}d",
            __func__, (int)size, ret);
    }

    return ret;
}

static void ParseDescriptor(const void *source, enum UsbRawDescriptorType bDescriptorType, void *dest)
{
    int32_t ret;

    if (source == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return;
    }

    switch (bDescriptorType) {
        case USB_RAW_CONFIG_DESCRIPTOR_TYPE: {
            struct UsbConfigDescriptor *desc = (struct UsbConfigDescriptor *)dest;
            ret = memcpy_s(dest, USB_DDK_DT_CONFIG_SIZE, source, USB_DDK_DT_CONFIG_SIZE);
            if (ret != EOK) {
                HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
                break;
            }
            desc->wTotalLength = Le16ToCpu(desc->wTotalLength);
            break;
        }
        case USB_RAW_INTERFACE_DESCRIPTOR_TYPE: {
            ret = memcpy_s(dest, USB_DDK_DT_INTERFACE_SIZE, source, USB_DDK_DT_INTERFACE_SIZE);
            if (ret != EOK) {
                HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
            }
            break;
        }
        case USB_RAW_ENDPOINT_DESCRIPTOR_TYPE: {
            struct UsbEndpointDescriptor *desc = (struct UsbEndpointDescriptor *)dest;
            ret = memcpy_s(dest, USB_DDK_DT_ENDPOINT_SIZE, source, USB_DDK_DT_ENDPOINT_SIZE);
            if (ret != EOK) {
                HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
                break;
            }
            desc->wMaxPacketSize = Le16ToCpu(desc->wMaxPacketSize);
            break;
        }
        case USB_RAW_AUDIO_ENDPOINT_DESCRIPTOR_TYPE: {
            struct UsbEndpointDescriptor *desc = (struct UsbEndpointDescriptor *)dest;
            ret = memcpy_s(dest, USB_DDK_DT_ENDPOINT_AUDIO_SIZE, source, USB_DDK_DT_ENDPOINT_AUDIO_SIZE);
            if (ret != EOK) {
                HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
                break;
            }
            desc->wMaxPacketSize = Le16ToCpu(desc->wMaxPacketSize);
            break;
        }
        default:
            HDF_LOGE("%{public}s: error bDescriptorType=%{public}d", __func__, bDescriptorType);
            break;
    }
}

static void ClearEndpoint(struct UsbRawEndpointDescriptor *endPoint)
{
    if ((endPoint != NULL) && (endPoint->extra != NULL)) {
        OsalMemFree((void *)endPoint->extra);
        endPoint->extra = NULL;
    }
}

static int ParseEndpoint(struct UsbRawEndpointDescriptor *endPoint, const uint8_t *buffer, int size)
{
    const uint8_t *buffer0 = buffer;
    const struct UsbiDescriptorHeader *header = NULL;
    void *extra = NULL;
    int len;
    int32_t ret;

    if (size < DESC_HEADER_LENGTH) {
        HDF_LOGE("%{public}s: size = %{public}d is short endPoint descriptor ", __func__, size);
        return HDF_ERR_IO;
    }

    header = (const struct UsbiDescriptorHeader *)buffer;
    if ((header->bDescriptorType != USB_DDK_DT_ENDPOINT) ||
        (header->bLength > size)) {
        HDF_LOGE("%{public}s: unexpected descriptor, type = 0x%{public}x, length = %u",
                 __func__, header->bDescriptorType, header->bLength);
        return buffer - buffer0;
    } else if (header->bLength < USB_DDK_DT_ENDPOINT_SIZE) {
        HDF_LOGE("%{public}s: invalid endpoint length = %u", __func__, header->bLength);
        return HDF_ERR_IO;
    }

    if (header->bLength >= USB_DDK_DT_ENDPOINT_AUDIO_SIZE) {
        ParseDescriptor(buffer, USB_RAW_AUDIO_ENDPOINT_DESCRIPTOR_TYPE, endPoint);
    } else {
        ParseDescriptor(buffer, USB_RAW_ENDPOINT_DESCRIPTOR_TYPE, endPoint);
    }

    buffer += header->bLength;
    size -= header->bLength;

    len = FindNextDescriptor(buffer, size);
    if (!len) {
        return buffer - buffer0;
    }

    extra = OsalMemAlloc((size_t)len);
    if (extra == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = memcpy_s(extra, len, buffer, len);
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
        return HDF_ERR_IO;
    }
    endPoint->extra = extra;
    endPoint->extraLength = len;

    return buffer + len - buffer0;
}

static void ClearInterface(struct UsbRawInterface *usbInterface)
{
    struct UsbRawInterfaceDescriptor *infPtr = NULL;
    uint8_t i;
    uint8_t j;

    if (usbInterface == NULL) {
        HDF_LOGE("%{public}s:%{public}d usbInterface is NULL", __func__, __LINE__);
        return;
    }

    if (usbInterface->numAltsetting > USB_MAXALTSETTING) {
        HDF_LOGE("%{public}s:%{public}d numAltsetting=%{public}d is error",
            __func__, __LINE__, usbInterface->numAltsetting);
        return;
    }

    for (i = 0; i < usbInterface->numAltsetting; i++) {
        infPtr = (struct UsbRawInterfaceDescriptor *)(usbInterface->altsetting + i);
        if (infPtr == NULL) {
            HDF_LOGE("%{public}s:%{public}d altsetting is NULL", __func__, __LINE__);
            continue;
        }

        if (infPtr->extra != NULL) {
            OsalMemFree((void *)infPtr->extra);
            infPtr->extra = NULL;
        }

        if (infPtr->endPoint != NULL) {
            for (j = 0; j < infPtr->interfaceDescriptor.bNumEndpoints; j++) {
                ClearEndpoint((struct UsbRawEndpointDescriptor *)infPtr->endPoint + j);
            }

            OsalMemFree((void *)infPtr->endPoint);
            infPtr->endPoint = NULL;
        }
    }

    OsalMemFree((void *)usbInterface);
}

static int RawParseDescriptor(int size, const uint8_t *buffer, enum UsbRawDescriptorType bDescriptorType,
    struct UsbRawInterfaceDescriptor *ifp)
{
    int ret = HDF_SUCCESS;

    ParseDescriptor(buffer, bDescriptorType, ifp);
    if ((ifp->interfaceDescriptor.bDescriptorType != USB_DDK_DT_INTERFACE) ||
        (ifp->interfaceDescriptor.bLength > size)) {
        HDF_LOGE("%{public}s: unexpected descriptor: type = 0x%{public}x, size = %{public}d",
                 __func__, ifp->interfaceDescriptor.bDescriptorType, size);
        ret = HDF_FAILURE;
    } else if ((ifp->interfaceDescriptor.bLength < USB_DDK_DT_INTERFACE_SIZE) ||
               (ifp->interfaceDescriptor.bNumEndpoints > USB_MAXENDPOINTS)) {
        HDF_LOGE("%{public}s: invalid descriptor: length = %u, numEndpoints = %u ", __func__,
                 ifp->interfaceDescriptor.bLength, ifp->interfaceDescriptor.bNumEndpoints);
        ret = HDF_ERR_IO;
    }

    return ret;
}

static int ParseInterfaceMemcpy(struct UsbRawInterfaceDescriptor *ifp, int len, const uint8_t *buffer)
{
    int ret;

    ifp->extra = OsalMemAlloc((size_t)len);
    if (!ifp->extra) {
        ret = HDF_ERR_MALLOC_FAIL;
        goto err;
    }

    ret = memcpy_s((void *)ifp->extra, len, buffer, len);
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
        goto err;
    }
    ifp->extraLength = len;
err:
    return ret;
}

static int ParseInterfaceEndpoint(struct UsbRawInterfaceDescriptor *ifp, const uint8_t **buffer, int *size)
{
    struct UsbRawEndpointDescriptor *endPoint = NULL;
    int ret = HDF_SUCCESS;
    uint8_t i;

    if (ifp->interfaceDescriptor.bNumEndpoints > 0) {
        endPoint = OsalMemCalloc(ifp->interfaceDescriptor.bNumEndpoints * sizeof(*endPoint));
        if (endPoint == NULL) {
            ret = HDF_ERR_MALLOC_FAIL;
            goto err;
        }

        ifp->endPoint = endPoint;
        for (i = 0; i < ifp->interfaceDescriptor.bNumEndpoints; i++) {
            ret = ParseEndpoint(endPoint + i, *buffer, *size);
            if (ret == 0) {
                ifp->interfaceDescriptor.bNumEndpoints = i;
                break;
            } else if (ret < 0) {
                goto err;
            }

            *buffer += ret;
            *size -= ret;
        }
    }

err:
    return ret;
}

static int ParseInterface(struct UsbRawInterface *usbInterface, const uint8_t *buffer, int size)
{
    int len;
    int ret;
    const uint8_t *buffer0 = buffer;
    int interfaceNumber = -1;
    const struct UsbiInterfaceDescriptor *ifDesc = NULL;
    struct UsbRawInterfaceDescriptor *ifp = NULL;
    bool tempFlag = false;

    if (usbInterface == NULL) {
        HDF_LOGD("%{public}s:%{public}d usbInterface is NULL", __func__, __LINE__);
        ret = HDF_DEV_ERR_NORANGE;
        goto err;
    }
    if (usbInterface->numAltsetting > USB_MAXALTSETTING) {
        HDF_LOGE("%{public}s:%{public}d numAltsetting=%{public}d is error",
            __func__, __LINE__, usbInterface->numAltsetting);
        ret = HDF_DEV_ERR_NORANGE;
        goto err;
    }

    while (size >= USB_DDK_DT_INTERFACE_SIZE) {
        ifp = (struct UsbRawInterfaceDescriptor *)(usbInterface->altsetting + usbInterface->numAltsetting);
        ret = RawParseDescriptor(size, buffer, USB_RAW_INTERFACE_DESCRIPTOR_TYPE, ifp);
        if (ret == HDF_FAILURE) {
            return buffer - buffer0;
        } else if (ret == HDF_ERR_IO) {
            HDF_LOGD("%{public}s:%{public}d ret=%{public}d", __func__, __LINE__, ret);
            goto err;
        }

        usbInterface->numAltsetting++;
        ifp->extra = NULL;
        ifp->extraLength = 0;
        ifp->endPoint = NULL;

        if (interfaceNumber == -1) {
            interfaceNumber = ifp->interfaceDescriptor.bInterfaceNumber;
        }

        buffer += ifp->interfaceDescriptor.bLength;
        size -= ifp->interfaceDescriptor.bLength;

        len = FindNextDescriptor(buffer, size);
        if (len) {
            ret = ParseInterfaceMemcpy(ifp, len, buffer);
            if (ret != EOK) {
                goto err;
            }

            buffer += len;
            size -= len;
        }

        ret = ParseInterfaceEndpoint(ifp, &buffer, &size);
        if (ret < HDF_SUCCESS) {
            goto err;
        }

        ifDesc = (const struct UsbiInterfaceDescriptor *)buffer;
        tempFlag = (size < USB_DDK_DT_INTERFACE_SIZE) ||
                   (ifDesc->bDescriptorType != USB_DDK_DT_INTERFACE) ||
                   (ifDesc->bInterfaceNumber != interfaceNumber);
        if (tempFlag) {
            return buffer - buffer0;
        }
    }

    return buffer - buffer0;

err:
    return ret;
}

static int ParseConfigurationDes(struct UsbRawConfigDescriptor *config, const uint8_t *buffer,
    int size, struct UsbRawInterface *usbInterface, uint8_t nIntf[])
{
    int ret, len;
    uint8_t i;

    len = FindNextDescriptor(buffer, size);
    if (len) {
        config->extra = OsalMemAlloc(len);
        if (!config->extra) {
            ret = HDF_ERR_MALLOC_FAIL;
            goto err;
        }

        ret = memcpy_s((void *)config->extra, len, buffer, len);
        if (ret != EOK) {
            HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
            goto err;
        }
        config->extraLength = len;

        buffer += len;
        size -= len;
    }

    while (size > 0) {
        struct UsbiInterfaceDescriptor *ifDesc = (struct UsbiInterfaceDescriptor *)buffer;
        for (i = 0; i < config->configDescriptor.bNumInterfaces; ++i) {
            if (nIntf[i] == ifDesc->bInterfaceNumber) {
                usbInterface = (struct UsbRawInterface *)config->interface[i];
                break;
            }
        }
        ret = ParseInterface(usbInterface, buffer, size);
        if (ret < 0) {
            goto err;
        }

        buffer += ret;
        size -= ret;
    }

    return size;

err:
    RawClearConfiguration(config);
    return ret;
}

static int ParseConfiguration(struct UsbRawConfigDescriptor *config, const uint8_t *buffer, int size)
{
    uint8_t i;
    uint8_t j;
    int len;
    struct UsbRawInterface *usbInterface = NULL;
    uint8_t nIntf[USB_MAXINTERFACES];
    uint8_t nAlts[USB_MAXINTERFACES];
    int intfNum;

    if (size < USB_DDK_DT_CONFIG_SIZE) {
        HDF_LOGE("%{public}s: size=%{public}d is short", __func__, size);
        return HDF_ERR_IO;
    }

    ParseDescriptor(buffer, USB_RAW_CONFIG_DESCRIPTOR_TYPE, config);
    if ((config->configDescriptor.bDescriptorType != USB_DDK_DT_CONFIG) ||
        (config->configDescriptor.bLength < USB_DDK_DT_CONFIG_SIZE) ||
        (config->configDescriptor.bLength > size) ||
        (config->configDescriptor.bNumInterfaces > USB_MAXINTERFACES)) {
        HDF_LOGE("%{public}s: invalid descriptor: type = 0x%x, length = %u", __func__,
                 config->configDescriptor.bDescriptorType, config->configDescriptor.bLength);
        return HDF_ERR_IO;
    }

    intfNum = GetInterfaceNumber(buffer, size, nIntf, nAlts);
    config->configDescriptor.bNumInterfaces = (uint8_t)intfNum;

    for (i = 0; i < intfNum; ++i) {
        j = nAlts[i];
        if (j > USB_MAXALTSETTING) {
            HDF_LOGW("%{public}s: too many alternate settings: %{public}d", __func__, j);
            nAlts[i] = USB_MAXALTSETTING;
            j = USB_MAXALTSETTING;
        }
        len = sizeof(struct UsbRawInterface) + sizeof(struct UsbRawInterfaceDescriptor) * j;
        usbInterface = OsalMemCalloc(len);
        config->interface[i] = usbInterface;
        if (usbInterface == NULL) {
            return HDF_ERR_MALLOC_FAIL;
        }
    }

    buffer += config->configDescriptor.bLength;
    size -= config->configDescriptor.bLength;

    return ParseConfigurationDes(config, buffer, size, usbInterface, nIntf);
}

static int32_t DescToConfig(const uint8_t *buf, int size, struct UsbRawConfigDescriptor **config)
{
    struct UsbRawConfigDescriptor *tempConfig = OsalMemCalloc(sizeof(*tempConfig));
    int32_t ret;

    if (tempConfig == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = ParseConfiguration(tempConfig, buf, size);
    if (ret < 0) {
        HDF_LOGE("%{public}s: ParseConfiguration failed with error = %{public}d", __func__, ret);
        if (tempConfig != NULL) {
            OsalMemFree(tempConfig);
            tempConfig = NULL;
        }
        return ret;
    } else if (ret > 0) {
        HDF_LOGW("%{public}s: still %{public}d bytes of descriptor data left", __func__, ret);
    }

    *config = tempConfig;

    return ret;
}

static int32_t ControlRequestCompletion(struct UsbHostRequest *request, struct UsbControlRequestData *requestData)
{
    int32_t ret;
    uint32_t waitTime;

    if (request->timeout == USB_RAW_REQUEST_TIME_ZERO_MS) {
        waitTime = HDF_WAIT_FOREVER;
    } else {
        waitTime = request->timeout;
    }

    ret = OsalSemWait(&request->sem, waitTime);
    if (ret == HDF_ERR_TIMEOUT) {
        RawCancelRequest(request);
        RawHandleRequestCompletion(request, USB_REQUEST_TIMEOUT);
    } else if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalSemWait faile, ret=%{public}d ", __func__, __LINE__, ret);
        goto out;
    }

    if ((requestData->requestType & USB_DDK_ENDPOINT_DIR_MASK) == USB_PIPE_DIRECTION_IN) {
        ret = memcpy_s(requestData->data, request->actualLength, ControlRequestGetData(request), request->actualLength);
        if (ret != EOK) {
            HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
            goto out;
        }
    }

    switch (request->status) {
        case USB_REQUEST_COMPLETED:
            ret = request->actualLength;
            break;
        case USB_REQUEST_TIMEOUT:
            ret = HDF_ERR_TIMEOUT;
            break;
        case USB_REQUEST_NO_DEVICE:
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
        case USB_REQUEST_STALL:
        case USB_REQUEST_OVERFLOW:
        case USB_REQUEST_ERROR:
        case USB_REQUEST_CANCELLED:
            ret = HDF_ERR_IO;
            break;
        default:
            HDF_LOGW("%{public}s: status=%{public}d is unrecognised", __func__, request->status);
            ret = HDF_FAILURE;
            break;
    }

out:
    OsalSemDestroy(&request->sem);
    return ret;
}

struct UsbSession *RawGetSession(struct UsbSession *session)
{
    return session ? session : g_usbRawDefaultSession;
}

int32_t RawInit(struct UsbSession **session)
{
    int32_t ret;
    struct UsbSession *tempSession = NULL;
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if ((session == NULL) && (g_usbRawDefaultSession != NULL)) {
        AdapterAtomicInc(&g_usbRawDefaultSession->refCount);
        return HDF_SUCCESS;
    }

    tempSession = (struct UsbSession *)OsalMemCalloc(sizeof(*tempSession));
    if (tempSession == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }
    OsalAtomicSet(&tempSession->refCount, 1);
    HdfSListInit(&tempSession->usbDevs);
    DListHeadInit(&tempSession->ifacePoolList);
    OsalMutexInit(&tempSession->lock);
    if ((session == NULL) && (g_usbRawDefaultSession == NULL)) {
        g_usbRawDefaultSession = tempSession;
        HDF_LOGI("%{public}s: created default context", __func__);
    }

    if (osAdapterOps->init) {
        ret = osAdapterOps->init(tempSession);
        if (ret < 0) {
            HDF_LOGE("%{public}s: init error, return %{public}d", __func__, ret);
            goto err_free_session;
        }
    } else {
        ret = HDF_ERR_NOT_SUPPORT;
        goto err_free_session;
    }

    if (session) {
        *session = tempSession;
    }

    return HDF_SUCCESS;

err_free_session:
    if (tempSession == g_usbRawDefaultSession) {
        g_usbRawDefaultSession = NULL;
    }

    OsalMemFree(tempSession);
    return ret;
}

int32_t RawExit(struct UsbSession *session)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    session = RawGetSession(session);
    if ((session == NULL) || (AdapterAtomicDec(&session->refCount) > 0)) {
        return HDF_SUCCESS;
    }

    if (osAdapterOps->exit) {
        osAdapterOps->exit(session);
    }
    if (session == g_usbRawDefaultSession) {
        g_usbRawDefaultSession = NULL;
    }

    OsalMutexDestroy(&session->lock);
    OsalMemFree(session);

    return HDF_SUCCESS;
}

struct UsbDeviceHandle *RawOpenDevice(struct UsbSession *session, uint8_t busNum, uint8_t usbAddr)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();
    struct UsbSession *realSession = NULL;

    if (osAdapterOps->openDevice == NULL) {
        HDF_LOGE("%{public}s: openDevice is NULL", __func__);
        return NULL;
    }

    realSession = RawGetSession(session);
    if (realSession == NULL) {
        return NULL;
    }

    return osAdapterOps->openDevice(realSession, busNum, usbAddr);
}

int32_t RawCloseDevice(struct UsbDeviceHandle *devHandle)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (devHandle == NULL) {
        HDF_LOGE("%{public}s devHandle is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (osAdapterOps->closeDevice) {
        osAdapterOps->closeDevice(devHandle);
    } else {
        return HDF_ERR_NOT_SUPPORT;
    }

    return HDF_SUCCESS;
}

int32_t RawClaimInterface(struct UsbDeviceHandle *devHandle, int interfaceNumber)
{
    int32_t ret;
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if ((devHandle == NULL) || (interfaceNumber < 0) || (interfaceNumber >= USB_MAXINTERFACES)) {
        HDF_LOGE("%{public}s:%{public}d HDF_ERR_INVALID_PARAM", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&devHandle->lock);
    if ((devHandle->claimedInterfaces) & (1U << (uint32_t)interfaceNumber)) {
        ret = HDF_SUCCESS;
        goto out;
    }

    if (!osAdapterOps->claimInterface) {
        ret = HDF_ERR_NOT_SUPPORT;
        goto out;
    }

    ret = osAdapterOps->claimInterface(devHandle, (unsigned int)interfaceNumber);
    if (ret == HDF_SUCCESS) {
        devHandle->claimedInterfaces |= 1U << (uint32_t)interfaceNumber;
    }

out:
    OsalMutexUnlock(&devHandle->lock);

    return ret;
}

struct UsbHostRequest *AllocRequest(struct UsbDeviceHandle *devHandle,  int isoPackets, size_t length)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (osAdapterOps->allocRequest == NULL) {
        return NULL;
    }

    return osAdapterOps->allocRequest(devHandle,  isoPackets, length);
}

int32_t FreeRequest(struct UsbHostRequest *request)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (osAdapterOps->freeRequest == NULL) {
        return HDF_ERR_NOT_SUPPORT;
    }

    return osAdapterOps->freeRequest(request);
}

int32_t RawFillBulkRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbFillRequestData *fillRequestData)
{
    int32_t ret;

    if (request == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (UsbEndpointDirOut(fillRequestData->endPoint)) {
        ret = memcpy_s(request->buffer, request->bufLen, fillRequestData->buffer, fillRequestData->length);
        if (ret != EOK) {
            HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
            return ret;
        }
    }
    request->devHandle    = devHandle;
    request->endPoint     = fillRequestData->endPoint;
    request->requestType  = USB_PIPE_TYPE_BULK;
    request->timeout      = fillRequestData->timeout;
    request->length       = fillRequestData->length;
    request->userData     = fillRequestData->userData;
    request->callback     = fillRequestData->callback;
    request->userCallback = fillRequestData->userCallback;

    return HDF_SUCCESS;
}

int32_t RawFillControlSetup(unsigned char *setup, struct UsbControlRequestData *requestData)
{
    struct UsbRawControlSetup *setupData = (struct UsbRawControlSetup *)setup;

    setupData->requestType = requestData->requestType;
    setupData->request     = requestData->requestCmd;
    setupData->value       = CpuToLe16(requestData->value);
    setupData->index       = CpuToLe16(requestData->index);
    setupData->length      = CpuToLe16(requestData->length);

    return HDF_SUCCESS;
}

int32_t RawFillControlRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbFillRequestData *fillRequestData)
{
    if (request == NULL || devHandle == NULL || fillRequestData == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    request->devHandle    = devHandle;
    request->endPoint     = fillRequestData->endPoint;
    request->requestType  = USB_PIPE_TYPE_CONTROL;
    request->timeout      = fillRequestData->timeout;
    request->userData     = fillRequestData->userData;
    request->callback     = fillRequestData->callback;
    request->userCallback = fillRequestData->userCallback;
    request->length       = fillRequestData->length;

    return HDF_SUCCESS;
}

int32_t RawFillInterruptRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbFillRequestData *fillRequestData)
{
    int32_t ret;
    if (UsbEndpointDirOut(fillRequestData->endPoint)) {
        ret = memcpy_s(request->buffer, request->bufLen, fillRequestData->buffer, fillRequestData->length);
        if (ret != EOK) {
            HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
            return ret;
        }
    }
    request->devHandle    = devHandle;
    request->endPoint     = fillRequestData->endPoint;
    request->requestType  = USB_PIPE_TYPE_INTERRUPT;
    request->timeout      = fillRequestData->timeout;
    request->length       = fillRequestData->length;
    request->userData     = fillRequestData->userData;
    request->callback     = fillRequestData->callback;
    request->userCallback = fillRequestData->userCallback;

    return HDF_SUCCESS;
}

int32_t RawFillIsoRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbFillRequestData *fillRequestData)
{
    int32_t ret;
    if (UsbEndpointDirOut(fillRequestData->endPoint)) {
        ret = memcpy_s(request->buffer, request->bufLen, fillRequestData->buffer, fillRequestData->length);
        if (ret != EOK) {
            HDF_LOGE("%{public}s:%{public}d memcpy_s fail!", __func__, __LINE__);
            return ret;
        }
    }
    request->devHandle     = devHandle;
    request->endPoint      = fillRequestData->endPoint;
    request->requestType   = USB_PIPE_TYPE_ISOCHRONOUS;
    request->timeout       = fillRequestData->timeout;
    request->length        = fillRequestData->length;
    request->numIsoPackets = fillRequestData->numIsoPackets;
    request->userData      = fillRequestData->userData;
    request->callback      = fillRequestData->callback;
    request->userCallback  = fillRequestData->userCallback;

    return HDF_SUCCESS;
}

int32_t RawSendControlRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbControlRequestData *requestData)
{
    struct UsbFillRequestData fillRequestData;
    unsigned char *setup = NULL;
    int completed = 0;
    int32_t ret;

    if ((request == NULL) || (devHandle == NULL) || (requestData == NULL)) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    setup = request->buffer;
    RawFillControlSetup(setup, requestData);
    if ((requestData->requestType & USB_DDK_ENDPOINT_DIR_MASK) == USB_PIPE_DIRECTION_OUT) {
        fillRequestData.endPoint = 0;
        fillRequestData.length = requestData->length;
        if (requestData->length > 0) {
            ret = memcpy_s(request->buffer + USB_RAW_CONTROL_SETUP_SIZE, fillRequestData.length,
                requestData->data, fillRequestData.length);
            if (ret != EOK) {
                HDF_LOGE("%{public}s:%{public}d memcpy_s fail, requestData.length=%{public}d",
                         __func__, __LINE__, requestData->length);
                return ret;
            }
        }
        fillRequestData.length = USB_RAW_CONTROL_SETUP_SIZE + requestData->length;
    } else {
        fillRequestData.endPoint = (0x1  << USB_DIR_OFFSET);
    }
    fillRequestData.userCallback = NULL;
    fillRequestData.callback  = SyncRequestCallback;
    fillRequestData.userData  = &completed;
    fillRequestData.timeout   = requestData->timeout;
    RawFillControlRequest(request, devHandle, &fillRequestData);

    ret = OsalSemInit(&request->sem, 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsalSemInit faile, ret=%{public}d ", __func__, __LINE__, ret);
        return ret;
    }

    ret = RawSubmitRequest(request);
    if (ret < 0) {
        OsalSemDestroy(&request->sem);
        return ret;
    }

    return ControlRequestCompletion(request, requestData);
}

int32_t RawSendBulkRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbRequestData *requestData)
{
    if ((request == NULL) || (devHandle == NULL) || (requestData == NULL)) {
        return HDF_ERR_INVALID_PARAM;
    }

    return HandleSyncRequest(request, devHandle, requestData, USB_PIPE_TYPE_BULK);
}

int32_t RawSendInterruptRequest(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbRequestData *requestData)
{
    if ((request == NULL) || (devHandle == NULL) || (requestData == NULL)) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HandleSyncRequest(request, devHandle, requestData, USB_PIPE_TYPE_INTERRUPT);
}

struct UsbHostRequest *RawAllocRequest(struct UsbDeviceHandle *devHandle, int isoPackets, int length)
{
    struct UsbHostRequest *request = NULL;
    request = (struct UsbHostRequest *)AllocRequest(devHandle, isoPackets, length);
    if (request == NULL) {
        HDF_LOGE("%{public}s RawMemAlloc fail", __func__);
        return NULL;
    }
    return request;
}

int32_t RawFreeRequest(struct UsbHostRequest *request)
{
    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return FreeRequest(request);
}

int32_t RawGetConfigDescriptor(struct UsbDevice *dev, uint8_t configIndex,
    struct UsbRawConfigDescriptor **config)
{
    int32_t ret;
    union UsbiConfigDescBuf tempConfig;
    uint16_t configLen;
    uint8_t *buf = NULL;

    if (dev == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (configIndex > dev->deviceDescriptor.bNumConfigurations) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_BAD_FD;
    }

    ret = GetConfigDescriptor(dev, configIndex, tempConfig.buf, sizeof(tempConfig.buf));
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d ret=%{public}d", __func__, __LINE__, ret);
        return ret;
    }
    configLen = Le16ToCpu(tempConfig.desc.wTotalLength);
    buf = OsalMemAlloc(configLen);
    if (buf == NULL) {
        HDF_LOGE("%{public}s:%{public}d OsalMemAlloc failed", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = GetConfigDescriptor(dev, configIndex, buf, configLen);
    if (ret >= HDF_SUCCESS) {
        ret = DescToConfig(buf, ret, config);
    }

    OsalMemFree(buf);
    buf = NULL;

    return ret;
}

void RawClearConfiguration(struct UsbRawConfigDescriptor *config)
{
    uint8_t i;

    if (config == NULL) {
        HDF_LOGE("%{public}s:%{public}d config is NULL", __func__, __LINE__);
        return;
    }

    for (i = 0; i < config->configDescriptor.bNumInterfaces; i++) {
        ClearInterface((struct UsbRawInterface *)(config->interface[i]));
        config->interface[i] = NULL;
    }

    if (config->extra != NULL) {
        OsalMemFree((void *)config->extra);
        config->extra = NULL;
    }
}

int32_t RawGetConfiguration(struct UsbDeviceHandle *devHandle, int *config)
{
    int32_t ret;
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();
    uint8_t tmp = 0;

    if (!osAdapterOps->getConfiguration) {
        HDF_LOGE("%{public}s:%{public}d adapter don't support getConfiguration",
                 __func__, __LINE__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ret = osAdapterOps->getConfiguration(devHandle, &tmp);
    *config = tmp;
    return ret;
}

int32_t RawSetConfiguration(struct UsbDeviceHandle *devHandle, int configuration)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (configuration < -1 || configuration > (int)0xFF) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!osAdapterOps->setConfiguration) {
        return HDF_ERR_NOT_SUPPORT;
    }

    return osAdapterOps->setConfiguration(devHandle, configuration);
}

int32_t RawGetDescriptor(struct UsbHostRequest *request, struct UsbDeviceHandle *devHandle,
    struct UsbRawDescriptorParam *param, unsigned char *data)
{
    int32_t ret;
    struct UsbControlRequestData requestData;

    requestData.requestType = USB_PIPE_DIRECTION_IN;
    requestData.requestCmd  = USB_REQUEST_GET_DESCRIPTOR;
    requestData.value       = (uint16_t)((param->descType << BYTE_LENGTH) | param->descIndex);
    requestData.index       = 0;
    requestData.data        = data;
    requestData.length      = (uint16_t)param->length;
    requestData.timeout     = USB_RAW_REQUEST_DEFAULT_TIMEOUT;
    ret = RawSendControlRequest(request, devHandle, &requestData);

    return ret;
}

struct UsbDevice *RawGetDevice(struct UsbDeviceHandle *devHandle)
{
    if (devHandle == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return NULL;
    }

    return devHandle->dev;
}

int32_t RawGetDeviceDescriptor(struct UsbDevice *dev, struct UsbDeviceDescriptor *desc)
{
    if (sizeof(dev->deviceDescriptor) != USB_DDK_DT_DEVICE_SIZE) {
        HDF_LOGE("%{public}s: struct UsbDeviceDescriptor is not expected size", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    *desc = dev->deviceDescriptor;
    return HDF_SUCCESS;
}

int32_t RawReleaseInterface(struct UsbDeviceHandle *devHandle, int interfaceNumber)
{
    int32_t ret;
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (interfaceNumber < 0 || interfaceNumber >= USB_MAXINTERFACES) {
        HDF_LOGE("%{public}s: interfaceNumber = %{public}d is out of range", __func__, interfaceNumber);
        return HDF_ERR_INVALID_PARAM;
    }

    OsalMutexLock(&devHandle->lock);
    if (!(devHandle->claimedInterfaces & (1U << (uint32_t)interfaceNumber))) {
        ret = HDF_ERR_BAD_FD;
        goto out;
    }

    if (!osAdapterOps->releaseInterface) {
        ret = HDF_ERR_NOT_SUPPORT;
        goto out;
    }

    ret = osAdapterOps->releaseInterface(devHandle, (unsigned int)interfaceNumber);
    if (ret == HDF_SUCCESS) {
        devHandle->claimedInterfaces &= ~(1U << (uint32_t)interfaceNumber);
    }

out:
    OsalMutexUnlock(&devHandle->lock);

    return ret;
}

int32_t RawResetDevice(struct UsbDeviceHandle *devHandle)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (!osAdapterOps->resetDevice) {
        return HDF_ERR_NOT_SUPPORT;
    }

    return osAdapterOps->resetDevice(devHandle);
}

int32_t RawSubmitRequest(struct UsbHostRequest *request)
{
    int32_t ret;
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!osAdapterOps->submitRequest) {
        return HDF_ERR_NOT_SUPPORT;
    }

    ret = osAdapterOps->submitRequest(request);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d ret = %{public}d", __func__, __LINE__, ret);
    }

    return ret;
}

int32_t RawCancelRequest(struct UsbHostRequest *request)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (!osAdapterOps->cancelRequest) {
        return HDF_ERR_NOT_SUPPORT;
    }

    return osAdapterOps->cancelRequest(request);
}

int32_t RawHandleRequest(struct UsbDeviceHandle *devHandle)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();
    int ret;

    if (!osAdapterOps->urbCompleteHandle) {
        return HDF_ERR_NOT_SUPPORT;
    }

    ret = osAdapterOps->urbCompleteHandle(devHandle);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d handleEvents error, return %{public}d", __func__, __LINE__, ret);
    }

    return ret;
}

int32_t RawClearHalt(struct UsbDeviceHandle *devHandle, uint8_t pipeAddress)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();
    unsigned int endPoint = pipeAddress;

    if (osAdapterOps->clearHalt == NULL) {
        return HDF_ERR_NOT_SUPPORT;
    }

    return osAdapterOps->clearHalt(devHandle, endPoint);
}

int RawHandleRequestCompletion(struct UsbHostRequest *request, UsbRequestStatus status)
{
    request->status = status;
    if (request->callback) {
        request->callback((void *)request);
    }

    return HDF_SUCCESS;
}

int32_t RawSetInterfaceAltsetting(
    struct UsbDeviceHandle *devHandle, uint8_t interfaceNumber, uint8_t settingIndex)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();

    if (osAdapterOps->setInterfaceAltsetting == NULL) {
        return HDF_ERR_NOT_SUPPORT;
    }

    return osAdapterOps->setInterfaceAltsetting(devHandle, interfaceNumber, settingIndex);
}

UsbRawTidType RawGetTid(void)
{
    return UsbAdapterGetTid();
}

int32_t RawRegisterSignal(void)
{
    return UsbAdapterRegisterSignal();
}

int32_t RawKillSignal(struct UsbDeviceHandle *devHandle, UsbRawTidType tid)
{
    return UsbAdapterKillSignal(devHandle, tid);
}

int RawInitPnpService(enum UsbPnpNotifyServiceCmd cmdType, struct UsbPnpAddRemoveInfo infoData)
{
    int ret;
    struct HdfSBuf *pnpData = NULL;
    struct HdfSBuf *pnpReply = NULL;
    int replyData = 0;
    bool flag = false;

    if ((cmdType != USB_PNP_NOTIFY_ADD_INTERFACE) && (cmdType != USB_PNP_NOTIFY_REMOVE_INTERFACE)) {
        return HDF_ERR_INVALID_PARAM;
    }

    struct HdfIoService *serv = HdfIoServiceBind(USB_HOST_PNP_SERVICE_NAME);
    if (serv == NULL) {
        ret = HDF_FAILURE;
        HDF_LOGE("%{public}s:%{public}d fail to get service %s", __func__, __LINE__, USB_HOST_PNP_SERVICE_NAME);
        return ret;
    }

    pnpData = HdfSBufObtainDefaultSize();
    pnpReply = HdfSBufObtainDefaultSize();
    if (pnpData == NULL || pnpReply == NULL) {
        ret = HDF_FAILURE;
        HDF_LOGE("%{public}s:%{public}d GetService err", __func__, __LINE__);
        goto error_sbuf;
    }

    if (!HdfSbufWriteBuffer(pnpData, (const void *)(&infoData), sizeof(struct UsbPnpAddRemoveInfo))) {
        HDF_LOGE("%{public}s: sbuf write infoData failed", __func__);
        ret = HDF_FAILURE;
        goto out;
    }

    ret = serv->dispatcher->Dispatch(&serv->object, cmdType, pnpData, pnpReply);
    if (ret) {
        HDF_LOGE("%{public}s: Dispatch USB_PNP_NOTIFY_REMOVE_TEST failed ret = %{public}d", __func__, ret);
        goto out;
    }

    flag = HdfSbufReadInt32(pnpReply, &replyData);
    if ((flag == false) || (replyData != INT32_MAX)) {
        ret = HDF_FAILURE;
        HDF_LOGE("%{public}s:%{public}d cmdType=%{public}d reply faile.", __func__, __LINE__, cmdType);
        goto out;
    } else if ((flag == true) && (replyData == INT32_MAX)) {
        HDF_LOGE("%{public}s:%{public}d cmdType=%{public}d reply success.", __func__, __LINE__, cmdType);
    }

    ret = HDF_SUCCESS;

out:
    HdfSBufRecycle(pnpData);
    HdfSBufRecycle(pnpReply);
error_sbuf:
    HdfIoServiceRecycle(serv);

    return ret;
}

void RawRequestListInit(struct UsbDevice *deviceObj)
{
    if (deviceObj == NULL) {
        HDF_LOGE("%{public}s:%{public}d deviceObj is NULL!", __func__, __LINE__);
        return;
    }

    OsalMutexInit(&deviceObj->requestLock);
    HdfSListInit(&deviceObj->requestList);
}
