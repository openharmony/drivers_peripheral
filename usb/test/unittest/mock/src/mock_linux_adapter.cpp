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

#include "mock_linux_adapter.h"

constexpr uint32_t DESCRIPTORSLENGTH = 111;
constexpr uint32_t SEM_WAIT_FOREVER = 0xFFFFFFFF;
constexpr uint8_t ACTIVE_NUM = 1;
constexpr uint32_t BULK_LEN = 256;
constexpr uint32_t CAPS = 509;
constexpr uint8_t BLENGTH = 18;
constexpr uint16_t BCDUSB = 800;
constexpr uint8_t MAX_PACKET_SIZE = 9;
constexpr uint16_t ID_VENDOR = 8711;
constexpr uint16_t ID_PRODUCT = 24;
constexpr uint16_t BCD_DEVICE = 547;
constexpr uint8_t I_PRODUCT = 2;
constexpr uint8_t I_SERIAL_NUMBER = 3;
constexpr uint32_t CFG_LEN = 93;

static UsbDeviceHandle *g_usbHandle = nullptr;
static UsbDevice *g_dev = nullptr;
static UsbHostRequest *g_sprq = nullptr;
static OsalSem g_completeSem;

static std::array<uint8_t, DESCRIPTORSLENGTH> g_buf = {
    0x12, 0x01, 0x20, 0x03, 0x00, 0x00, 0x00, 0x09, 0x07, 0x22, 0x18, 0x00, 0x23, 0x02, 0x01, 0x02,
    0x03, 0x01, 0x09, 0x02, 0x5D, 0x00, 0x02, 0x01, 0x04, 0xC0, 0x3E, 0x08, 0x0B, 0x00, 0x02, 0x02,
    0x02, 0x01, 0x07, 0x09, 0x04, 0x00, 0x00, 0x01, 0x02, 0x02, 0x01, 0x05, 0x05, 0x24, 0x00, 0x10,
    0x01, 0x05, 0x24, 0x01, 0x00, 0x01, 0x04, 0x24, 0x02, 0x02, 0x05, 0x24, 0x06, 0x00, 0x01, 0x07,
    0x05, 0x81, 0x03, 0x0A, 0x00, 0x09, 0x06, 0x30, 0x00, 0x00, 0x00, 0x00, 0x09, 0x04, 0x01, 0x00,
    0x02, 0x0A, 0x00, 0x02, 0x06, 0x07, 0x05, 0x82, 0x02, 0x00, 0x04, 0x00, 0x06, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x05, 0x01, 0x02, 0x00, 0x04, 0x00, 0x06, 0x30, 0x00, 0x00, 0x00, 0x00
};

static int32_t FillUsbDeviceHandle(UsbDeviceHandle *handle)
{
    UsbDeviceDescriptor dec = {BLENGTH, 1, BCDUSB, 0, 0, 0, MAX_PACKET_SIZE, ID_VENDOR,
        ID_PRODUCT, BCD_DEVICE, 1, I_PRODUCT, I_SERIAL_NUMBER, 1};

    handle->claimedInterfaces = 0;
    handle->caps = CAPS;
    handle->dev->portNum = 0;
    handle->dev->speed = USB_DDK_SPEED_UNKNOWN;
    handle->dev->activeConfig = 0;
    handle->dev->deviceDescriptor = dec;
    handle->dev->configDescriptors->actualLen = CFG_LEN;
    return HDF_SUCCESS;
}

int32_t FuncAdapterInit(const UsbSession *session)
{
    (void)session;
    OsalSemInit(&g_completeSem, 0);
    return HDF_SUCCESS;
}

void FuncAdapterExit(const UsbSession *session)
{
    (void)session;
    OsalSemDestroy(&g_completeSem);
}

static bool OsDeviceCompare(HdfSListNode *listEntry, uint32_t searchKey)
{
    UsbDevice *dev = reinterpret_cast<UsbDevice *>(listEntry);
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: invalid param listEntry", __func__);
        return false;
    }

    if ((dev->busNum == (searchKey >> BUS_OFFSET)) && (dev->devAddr == (searchKey & 0xFF))) {
        return true;
    }

    return false;
}

static UsbDeviceHandle *OsGetDeviceHandle(UsbSession *session, uint8_t busNum, uint8_t usbAddr)
{
    if (session == nullptr) {
        HDF_LOGE("%{public}s: invalid param session", __func__);
        return nullptr;
    }
    UsbDeviceHandle *handle = nullptr;
    OsalMutexLock(&session->lock);
    UsbDevice *dev = reinterpret_cast<UsbDevice *>(
        HdfSListSearch(&session->usbDevs, (busNum << BUS_OFFSET) | usbAddr, OsDeviceCompare));
    if (dev != nullptr) {
        handle = dev->devHandle;
        AdapterAtomicInc(&dev->refcnt);
    }
    OsalMutexUnlock(&session->lock);

    return handle;
}

static UsbDeviceHandle *OsCallocDeviceHandle(void)
{
    UsbDeviceHandle *usbHandle = static_cast<UsbDeviceHandle *>(RawUsbMemCalloc(sizeof(UsbDeviceHandle)));
    if (usbHandle == nullptr) {
        HDF_LOGE("%{public}s: allocate g_usbHandle failed", __func__);
        return nullptr;
    }
    OsalMutexInit(&usbHandle->lock);

    return usbHandle;
}

static UsbDevice *OsAllocDevice(UsbSession *session, UsbDeviceHandle *handle)
{
    UsbDevice *dev = static_cast<UsbDevice *>(RawUsbMemCalloc(sizeof(UsbDevice)));
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: RawUsbMemCalloc failed", __func__);
        return nullptr;
    }

    dev->session = session;
    dev->devHandle = handle;
    RawRequestListInit(dev);
    handle->dev = dev;

    return dev;
}
static int32_t OsReadDescriptors(UsbDevice *dev)
{
    dev->descriptors = static_cast<uint8_t *>(RawUsbMemAlloc(DESCRIPTORSLENGTH));
    dev->descriptorsLength = DESCRIPTORSLENGTH;
    if (memcpy_s(dev->descriptors, dev->descriptorsLength, g_buf.data(), DESCRIPTORSLENGTH) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t OsParseConfigDescriptors(UsbDevice *dev)
{
    UsbDeviceDescriptor *deviceDesc = static_cast<UsbDeviceDescriptor *>(dev->descriptors);
    uint8_t numConfigs = deviceDesc->bNumConfigurations;
    if (numConfigs == 0) {
        return HDF_SUCCESS;
    }
    dev->configDescriptors =
        static_cast<UsbDeviceConfigDescriptor *>(RawUsbMemAlloc(numConfigs * sizeof(UsbDeviceConfigDescriptor)));
    if (dev->configDescriptors == nullptr) {
        HDF_LOGE("%{public}s: RawUsbMemAlloc failed.", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    uint8_t *buffer = static_cast<uint8_t *>(dev->descriptors) + USB_DDK_DT_DEVICE_SIZE;
    size_t descLen = dev->descriptorsLength - USB_DDK_DT_DEVICE_SIZE;
    for (uint8_t i = 0; i < numConfigs; i++) {
        if (descLen < USB_DDK_DT_CONFIG_SIZE) {
            HDF_LOGE("%{public}s: read %{public}zu", __func__, descLen);
            RawUsbMemFree(dev->configDescriptors);
            return HDF_ERR_IO;
        }
        UsbConfigDescriptor *configDesc = reinterpret_cast<UsbConfigDescriptor *>(buffer);
        if ((configDesc->bDescriptorType != USB_DDK_DT_CONFIG) || (configDesc->bLength < USB_DDK_DT_CONFIG_SIZE)) {
            HDF_LOGE("%{public}s: config desc error: type 0x%{public}02x, length %{public}u",
                __func__, configDesc->bDescriptorType, configDesc->bLength);
            RawUsbMemFree(dev->configDescriptors);
            return HDF_ERR_IO;
        }
        uint16_t configLen = LE16_TO_CPU(configDesc->wTotalLength);
        if (configLen < USB_DDK_DT_CONFIG_SIZE) {
            HDF_LOGE("invalid wTotalLength value %{public}u", configLen);
            RawUsbMemFree(dev->configDescriptors);
            return HDF_ERR_IO;
        }
        if (configLen > descLen) {
            HDF_LOGI("%{public}s: read %{public}zu/%{public}u", __func__, descLen, configLen);
            configLen = static_cast<uint16_t>(descLen);
        }
        dev->configDescriptors[i].desc = configDesc;
        dev->configDescriptors[i].actualLen = configLen;
        buffer += configLen;
        descLen -= configLen;
    }
    return HDF_SUCCESS;
}

static int32_t OsInitDevice(UsbDevice *dev, uint8_t busNum, uint8_t devAddr)
{
    UsbDeviceHandle *devHandle = dev->devHandle;
    dev->busNum = busNum;
    dev->devAddr = devAddr;
    devHandle->caps = CAPS;
    dev->descriptorsLength = 0;

    int32_t ret = OsReadDescriptors(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsReadDescriptors failed ret = %{pubilc}d", __func__, ret);
        return ret;
    }
    ret = OsParseConfigDescriptors(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsParseConfigDescriptors failed ret = %{pubilc}d", __func__, ret);
        return ret;
    }
    ret = memcpy_s(&dev->deviceDescriptor, sizeof(UsbDeviceDescriptor), dev->descriptors, USB_DDK_DT_DEVICE_SIZE);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed ret = %{public}d", __func__, ret);
        ret = HDF_ERR_IO;
    }
    return ret;
}

UsbDeviceHandle *FuncAdapterOpenDevice(UsbSession *session, uint8_t busNum, uint8_t usbAddr)
{
    g_usbHandle = OsGetDeviceHandle(session, busNum, usbAddr);
    if (g_usbHandle != nullptr) {
        return g_usbHandle;
    }

    g_usbHandle = OsCallocDeviceHandle();
    if (g_usbHandle == nullptr) {
        return nullptr;
    }

    g_dev = OsAllocDevice(session, g_usbHandle);
    if (g_dev == nullptr) {
        OsalMutexDestroy(&g_usbHandle->lock);
        RawUsbMemFree(g_usbHandle);
        return nullptr;
    }

    int32_t ret = OsInitDevice(g_dev, busNum, usbAddr);
    if (ret != HDF_SUCCESS) {
        RawUsbMemFree(g_dev);
        return nullptr;
    }

    OsalAtomicSet(&g_dev->refcnt, 1);
    // add the new device to the device list on session
    OsalMutexLock(&session->lock);
    HdfSListAdd(&session->usbDevs, &g_dev->list);
    OsalMutexUnlock(&session->lock);
    (void)FillUsbDeviceHandle(g_usbHandle);
    return g_usbHandle;
}

void FuncAdapterCloseDevice(UsbDeviceHandle *handle)
{
    struct UsbDevice *dev = NULL;

    if ((handle == NULL) || (handle->dev == NULL)) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return;
    }

    dev = handle->dev;
    if (AdapterAtomicDec(&dev->refcnt) > 0) {
        return;
    }

    OsalMutexLock(&dev->session->lock);
    HdfSListRemove(&dev->session->usbDevs, &dev->list);
    OsalMutexUnlock(&dev->session->lock);

    if (dev->configDescriptors) {
        RawUsbMemFree(dev->configDescriptors);
    }
    if (dev->descriptors) {
        RawUsbMemFree(dev->descriptors);
    }
    RawUsbMemFree(dev);
    OsalMutexDestroy(&handle->lock);
    RawUsbMemFree(handle);
}

int32_t FuncAdapterGetConfigDescriptor(const UsbDevice *dev, uint8_t configIndex, void *buffer, size_t len)
{
    UsbDeviceConfigDescriptor *config = nullptr;
    uint8_t i;
    if (dev == nullptr || buffer == nullptr || (configIndex > dev->deviceDescriptor.bNumConfigurations)) {
        return HDF_ERR_INVALID_PARAM;
    }
    configIndex = 1;
    for (i = 0; i < dev->deviceDescriptor.bNumConfigurations; i++) {
        if (configIndex == dev->configDescriptors[i].desc->bConfigurationValue) {
            config = &dev->configDescriptors[i];
            break;
        }
    }

    if (config == nullptr) {
        HDF_LOGE("%{public}s: config is null", __func__);
        return HDF_ERR_BAD_FD;
    }
    int32_t lenTmp = MIN(static_cast<int32_t>(len), static_cast<int32_t>(config->actualLen));
    if (memcpy_s(buffer, lenTmp, config->desc, lenTmp) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_ERR_IO;
    }
    return lenTmp;
}

static int32_t OsGetActiveConfig(UsbDevice *dev, int32_t fd)
{
    (void)fd;
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: invalid param dev", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    dev->activeConfig = 0;
    return HDF_SUCCESS;
}

int32_t FuncAdapterGetConfiguration(const UsbDeviceHandle *handle, uint8_t *activeConfig)
{
    if (handle == nullptr || activeConfig == nullptr || handle->dev == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = OsGetActiveConfig(handle->dev, handle->fd);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    *activeConfig = handle->dev->activeConfig;
    if (*activeConfig == 0) {
        HDF_LOGI("%{public}s: activeConfig is zero", __func__);
    }
    return HDF_SUCCESS;
}

int32_t FuncAdapterSetConfiguration(UsbDeviceHandle *handle, int32_t activeConfig)
{
    if (handle == nullptr || handle->dev == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    handle->dev->activeConfig = ACTIVE_NUM;
    return HDF_SUCCESS;
}

int32_t FuncAdapterClaimInterface(const UsbDeviceHandle *handle, uint32_t interfaceNumber)
{
    (void)handle;
    (void)interfaceNumber;
    return HDF_SUCCESS;
}

int32_t FuncAdapterReleaseInterface(const UsbDeviceHandle *handle, uint32_t interfaceNumber)
{
    (void)handle;
    (void)interfaceNumber;
    return HDF_SUCCESS;
}

int32_t FuncAdapterSetInterface(const UsbDeviceHandle *handle, uint8_t interface, uint8_t altSetting)
{
    (void)handle;
    (void)interface;
    (void)altSetting;
    return HDF_SUCCESS;
}

int32_t FuncAdapterClearHalt(const UsbDeviceHandle *handle, uint32_t endPoint)
{
    (void)handle;
    (void)endPoint;
    return HDF_SUCCESS;
}

int32_t FuncAdapterResetDevice(const UsbDeviceHandle *handle)
{
    (void)handle;
    return HDF_SUCCESS;
}

UsbHostRequest *FuncAdapterAllocRequest(const UsbDeviceHandle *handle, int32_t isoPackets, size_t len)
{
    void *memBuf = nullptr;
    UsbHostRequest *request;

    if (handle == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return nullptr;
    }
    size_t allocSize = sizeof(UsbHostRequest) + (sizeof(UsbIsoPacketDesc) * static_cast<size_t>(isoPackets)) +
        (sizeof(unsigned char) * len);
    memBuf = RawUsbMemCalloc(allocSize);
    if (memBuf == nullptr) {
        HDF_LOGE("%{public}s: alloc UsbHostRequest failed", __func__);
        return nullptr;
    }
    request = static_cast<UsbHostRequest *>(memBuf);
    g_sprq = request;
    request->numIsoPackets = isoPackets;
    request->buffer = static_cast<unsigned char *>(memBuf) + allocSize - len;
    request->bufLen = len;
    request->bulkUrb = RawUsbMemCalloc(sizeof(UsbAdapterUrb));
    if (request->bulkUrb == nullptr) {
        HDF_LOGE("%{public}s RawUsbMemAlloc fail", __func__);
        RawUsbMemFree(memBuf);
        return nullptr;
    }
    request->urbs = request->bulkUrb;
    return request;
}

int32_t FuncAdapterFreeRequest(UsbHostRequest *request)
{
    if (request == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (request->bulkUrb != nullptr) {
        RawUsbMemFree(request->bulkUrb);
        request->urbs = nullptr;
    }
    if (request != nullptr) {
        RawUsbMemFree(request);
        request = nullptr;
    }
    return HDF_SUCCESS;
}

int32_t FuncAdapterSubmitRequest(UsbHostRequest *request)
{
    if (g_sprq == nullptr) {
        HDF_LOGE("%{public}s: g_sprq nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    g_sprq->status = request->status;
    OsalSemPost(&g_completeSem);
    return HDF_SUCCESS;
}

int32_t FuncAdapterCancelRequest(UsbHostRequest * const request)
{
    if (!((request->requestType == USB_REQUEST_TYPE_BULK) && (request->reqStatus == USB_REQUEST_ERROR))) {
        request->reqStatus = USB_REQUEST_CANCELLED;
    }
    return HDF_SUCCESS;
}

static int32_t RequestCompletion(UsbHostRequest *request, UsbRequestStatus status)
{
    if (request == nullptr) {
        HDF_LOGE("%{public}s: request is nullptr!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    request->status = status;
    int32_t ret = memset_s(request->buffer, request->bufLen, ACTIVE_NUM, request->bufLen);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memset_s failed", __func__);
        return ret;
    }
    if (request->callback) {
        request->callback(static_cast<void *>(request));
    }
    return HDF_SUCCESS;
}

int32_t FuncAdapterUrbCompleteHandle(const UsbDeviceHandle *devHandle)
{
    uint32_t waitTime;
    if (devHandle == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    waitTime = SEM_WAIT_FOREVER;
    (void)OsalSemWait(&g_completeSem, waitTime);
    if (g_sprq == nullptr) {
        return HDF_SUCCESS;
    }

    UsbRequestStatus status = USB_REQUEST_COMPLETED;
    if (g_sprq->length <= BULK_LEN) {
        g_sprq->actualLength = ACTIVE_NUM;
    } else {
        g_sprq->actualLength = BULK_LEN;
    }
    return RequestCompletion(g_sprq, status);
}
