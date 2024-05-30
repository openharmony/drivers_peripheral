/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "linux_adapter.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "usbd_wrapper.h"

#define HDF_LOG_TAG USB_LINUX_ADAPTER
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define PATH_LEN             50
#define DESC_READ_LEN        256
#define EP_NUM_MAX           30
#define SLEEP_TIME           500000
#define USB_DEVICE_MMAP_PATH "/data/service/el1/public/usb/"

static void *OsAdapterRealloc(void *ptr, size_t oldSize, size_t newSize)
{
    void *mem = RawUsbMemAlloc(newSize);
    if (mem == NULL) {
        HDF_LOGE("%{public}s:%{public}d RawUsbMemAlloc failed.", __func__, __LINE__);
        return NULL;
    }

    if (oldSize > 0) {
        if (memmove_s(mem, newSize, ptr, oldSize) != EOK) {
            HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
            RawUsbMemFree(mem);
            mem = NULL;
            return NULL;
        }
    }

    RawUsbMemFree(ptr);
    return mem;
}

static bool OsDeviceCompare(struct HdfSListNode *listEntry, uint32_t searchKey)
{
    struct UsbDevice *dev = (struct UsbDevice *)listEntry;
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param listEntry.", __func__, __LINE__);
        return false;
    }

    if ((dev->busNum == (searchKey >> BUS_OFFSET)) && (dev->devAddr == (searchKey & 0xFF))) {
        return true;
    }

    return false;
}

static struct UsbDeviceHandle *OsGetDeviceHandle(struct UsbSession *session, uint8_t busNum, uint8_t usbAddr)
{
    struct UsbDevice *dev = NULL;
    struct UsbDeviceHandle *handle = NULL;

    if (session == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param session.\n", __func__, __LINE__);
        return NULL;
    }

    OsalMutexLock(&session->lock);
    dev = (struct UsbDevice *)HdfSListSearch(&session->usbDevs, (busNum << BUS_OFFSET) | usbAddr, OsDeviceCompare);
    if (dev != NULL) {
        handle = dev->devHandle;
        AdapterAtomicInc(&dev->refcnt);
    }
    OsalMutexUnlock(&session->lock);

    return handle;
}

static struct UsbDeviceHandle *OsCallocDeviceHandle(void)
{
    struct UsbDeviceHandle *handle = NULL;

    handle = RawUsbMemCalloc(sizeof(*handle));
    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d allocate handle failed", __func__, __LINE__);
        return NULL;
    }

    OsalMutexInit(&handle->lock);

    return handle;
}

static struct UsbDevice *OsAllocDevice(struct UsbSession *session, struct UsbDeviceHandle *handle)
{
    struct UsbDevice *dev = RawUsbMemCalloc(sizeof(*dev));
    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d RawUsbMemCalloc failed.", __func__, __LINE__);
        return NULL;
    }

    dev->session = session;
    dev->devHandle = handle;

    RawRequestListInit(dev);

    handle->dev = dev;

    return dev;
}

static int32_t GetMmapFd(struct UsbDevice *dev)
{
    char path[PATH_LEN] = {'\0'};
    int32_t ret = sprintf_s(path, PATH_LEN, USB_DEVICE_MMAP_PATH "%03u_%03u", dev->busNum, dev->devAddr);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d path error", __func__, __LINE__);
        return HDF_FAILURE;
    }

    int32_t fd = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HDF_LOGE("%{public}s: open error:%{public}s", __func__, path);
        return HDF_FAILURE;
    }
    dev->devHandle->mmapFd = fd;
    return HDF_SUCCESS;
}

static int32_t GetUsbDevicePath(struct UsbDevice *dev, char *pathBuf, size_t length)
{
    char path[PATH_LEN] = {'\0'};
    int32_t ret = sprintf_s(path, sizeof(path), USB_DEV_FS_PATH "/%03u/%03u", dev->busNum, dev->devAddr);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d path error", __func__, __LINE__);
        return HDF_FAILURE;
    }

    if (realpath(path, pathBuf) == NULL) {
        HDF_LOGE("%{public}s: path conversion failed, path: %{public}s", __func__, path);
        return HDF_FAILURE;
    }

    if (length < strlen(USB_DEV_FS_PATH)) {
        HDF_LOGE("%{public}s: invalid length, path: %{public}s", __func__, path);
        return HDF_FAILURE;
    }

    if (strncmp(USB_DEV_FS_PATH, pathBuf, strlen(USB_DEV_FS_PATH)) != 0) {
        HDF_LOGE("%{public}s: The file path is incorrect, path: %{public}s", __func__, path);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t OsGetUsbFd(struct UsbDevice *dev, mode_t mode)
{
    if (dev == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = GetMmapFd(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get mmap fd failed:%{public}d", __func__, ret);
        return ret;
    }

    char pathBuf[PATH_LEN] = {'\0'};
    ret = GetUsbDevicePath(dev, pathBuf, PATH_LEN);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get usb device path failed:%{public}d", __func__, ret);
        return ret;
    }

    int32_t fd = open(pathBuf, mode | O_CLOEXEC);
    if (fd != HDF_FAILURE) {
        return fd;
    }

    usleep(SLEEP_TIME);
    switch (errno) {
        case ENOENT:
            fd = open(pathBuf, mode | O_CLOEXEC);
            if (fd != HDF_FAILURE) {
                return fd;
            }
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
        case EACCES:
            ret = HDF_ERR_BAD_FD;
            break;
        default:
            ret = HDF_FAILURE;
            break;
    }

    return ret;
}

static int32_t OsReadDescriptors(struct UsbDevice *dev)
{
    int32_t fd = dev->devHandle->fd;
    size_t allocLen = 0;

    do {
        size_t oldLen = allocLen;
        allocLen += DESC_READ_LEN;
        dev->descriptors = OsAdapterRealloc(dev->descriptors, oldLen, allocLen);
        if (!dev->descriptors) {
            HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
            return HDF_ERR_MALLOC_FAIL;
        }
        uint8_t *ptr = (uint8_t *)dev->descriptors + dev->descriptorsLength;
        if (memset_s(ptr, DESC_READ_LEN, 0, DESC_READ_LEN) != EOK) {
            HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
            return HDF_FAILURE;
        }

        int32_t len = read(fd, ptr, DESC_READ_LEN);
        if (len < 0) {
            HDF_LOGE("read descriptor failed, errno=%{public}d", errno);
            return HDF_ERR_IO;
        }
        dev->descriptorsLength += (size_t)len;
    } while (dev->descriptorsLength == allocLen);

    return HDF_SUCCESS;
}

static int32_t OsParseConfigDescriptors(struct UsbDevice *dev)
{
    struct UsbDeviceDescriptor *deviceDesc = NULL;
    uint8_t i;
    uint8_t numConfigs;
    uint8_t *buffer = NULL;
    size_t descLen;

    deviceDesc = dev->descriptors;
    numConfigs = deviceDesc->bNumConfigurations;
    if (numConfigs == 0) {
        return HDF_SUCCESS;
    }
    dev->configDescriptors = RawUsbMemAlloc(numConfigs * sizeof(struct UsbDeviceConfigDescriptor));
    if (dev->configDescriptors == NULL) {
        HDF_LOGE("%{public}s:%{public}d RawUsbMemAlloc failed.", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    buffer = (uint8_t *)dev->descriptors + USB_DDK_DT_DEVICE_SIZE;
    descLen = dev->descriptorsLength - USB_DDK_DT_DEVICE_SIZE;

    for (i = 0; i < numConfigs; i++) {
        struct UsbConfigDescriptor *configDesc = NULL;
        uint16_t configLen;

        if (descLen < USB_DDK_DT_CONFIG_SIZE) {
            HDF_LOGE("%{public}s:%{public}d read %{public}zu", __func__, __LINE__, descLen);
            RawUsbMemFree(dev->configDescriptors);
            return HDF_ERR_IO;
        }
        configDesc = (struct UsbConfigDescriptor *)buffer;
        if ((configDesc->bDescriptorType != USB_DDK_DT_CONFIG) || (configDesc->bLength < USB_DDK_DT_CONFIG_SIZE)) {
            HDF_LOGE("%{public}s:%{public}d config desc error: type 0x%{public}02x, length %{public}u",
                __func__, __LINE__, configDesc->bDescriptorType, configDesc->bLength);
            RawUsbMemFree(dev->configDescriptors);
            return HDF_ERR_IO;
        }
        configLen = LE16_TO_CPU(configDesc->wTotalLength);
        if (configLen < USB_DDK_DT_CONFIG_SIZE) {
            HDF_LOGE("invalid wTotalLength value %{public}u", configLen);
            RawUsbMemFree(dev->configDescriptors);
            return HDF_ERR_IO;
        }
        if (configLen > descLen) {
            HDF_LOGD("%{public}s:%{public}d read %{public}zu/%{public}u", __func__, __LINE__, descLen, configLen);
            configLen = (uint16_t)descLen;
        }
        dev->configDescriptors[i].desc = configDesc;
        dev->configDescriptors[i].actualLen = configLen;
        buffer += configLen;
        descLen -= configLen;
    }
    return HDF_SUCCESS;
}

static int32_t OsInitDevice(struct UsbDevice *dev, uint8_t busNum, uint8_t devAddr)
{
    struct UsbDeviceHandle *devHandle = dev->devHandle;
    int32_t fd;
    int32_t ret;

    dev->busNum = busNum;
    dev->devAddr = devAddr;

    fd = OsGetUsbFd(dev, O_RDWR);
    if (fd < 0) {
        return fd;
    }
    devHandle->fd = fd;

    ret = ioctl(fd, USBDEVFS_GET_CAPABILITIES, &devHandle->caps);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d get capabilities failed, errno=%{public}d", __func__, __LINE__, errno);
        devHandle->caps = USB_ADAPTER_CAP_BULK_CONTINUATION;
    }

    dev->descriptorsLength = 0;
    ret = OsReadDescriptors(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsReadDescriptors failed ret = %{pubilc}d", __func__, __LINE__, ret);
        return ret;
    }
    ret = OsParseConfigDescriptors(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d OsParseConfigDescriptors failed ret = %{pubilc}d", __func__, __LINE__, ret);
        return ret;
    }
    ret =
        memcpy_s(&dev->deviceDescriptor, sizeof(struct UsbDeviceDescriptor), dev->descriptors, USB_DDK_DT_DEVICE_SIZE);
    if (ret != EOK) {
        HDF_LOGE("%{public}s:%{public}d memcpy_s failed ret = %{public}d", __func__, __LINE__, ret);
        ret = HDF_ERR_IO;
    }
    return ret;
}

static int32_t OsGetActiveConfig(struct UsbDevice *dev, int32_t fd)
{
    int32_t ret;
    uint8_t activeConfig = 0;
    struct UsbControlRequestData ctrlData;

    if (dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param dev.", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ctrlData.requestType = USB_PIPE_DIRECTION_IN;
    ctrlData.requestCmd = USB_REQUEST_GET_CONFIGURATION;
    ctrlData.value = 0;
    ctrlData.index = 0;
    ctrlData.length = 1;
    ctrlData.timeout = USB_RAW_REQUEST_DEFAULT_TIMEOUT;
    ctrlData.data = &activeConfig;
    ret = ioctl(fd, USBDEVFS_CONTROL, &ctrlData);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d ioctl failed errno = %{public}d", __func__, __LINE__, errno);
        return HDF_FAILURE;
    }
    dev->activeConfig = activeConfig;

    return HDF_SUCCESS;
}

static int32_t AdapterUsbControlMsg(const struct UsbDeviceHandle *handle, struct UsbControlRequestData *ctrlData)
{
    if (handle == NULL || handle->dev == NULL || ctrlData == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return ioctl(handle->fd, USBDEVFS_CONTROL, ctrlData);
}

static int32_t AdapterGetUsbSpeed(const struct UsbDeviceHandle *handle)
{
    if (handle == NULL || handle->dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = ioctl(handle->fd, USBDEVFS_GET_SPEED, NULL);
    HDF_LOGI("%{public}s:%{public}d speed = %{public}d", __func__, __LINE__, ret);
    return ret;
}

static void OsFreeIsoUrbs(struct UsbHostRequest *request)
{
    struct UsbAdapterUrb *urb = NULL;

    for (int32_t i = 0; i < request->numUrbs; i++) {
        urb = request->isoUrbs[i];
        if (urb == NULL) {
            break;
        }
        RawUsbMemFree(urb);
    }

    RawUsbMemFree(request->isoUrbs);
    request->isoUrbs = NULL;
}

static void OsDiscardUrbs(const struct UsbHostRequest *request, int32_t first, int32_t last)
{
    struct UsbAdapterUrb *urb = NULL;

    if (request == NULL || request->devHandle == NULL || first > URBS_PER_REQUEST || first > last) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return;
    }

    for (int32_t i = last - 1; i >= first; i--) {
        if (request->requestType == USB_REQUEST_TYPE_ISOCHRONOUS) {
            urb = request->isoUrbs[i];
        } else {
            urb = &request->urbs[i];
        }
        if (ioctl(request->devHandle->fd, USBDEVFS_DISCARDURB, urb) == 0) {
            continue;
        }
    }
}

static int32_t OsSubmitControlRequest(struct UsbHostRequest *request)
{
    struct UsbAdapterUrb *urb = NULL;
    int32_t ret;
    int32_t fd;

    if (request == NULL || request->devHandle == NULL || request->length > MAX_BULK_DATA_BUFFER_LENGTH) {
        HDF_LOGD("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    fd = request->devHandle->fd;
    urb = RawUsbMemCalloc(sizeof(*urb));
    if (urb == NULL) {
        HDF_LOGE("%{public}s:%{public}d RawUsbMemCalloc failed.", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }

    urb->type = USB_ADAPTER_URB_TYPE_CONTROL;
    urb->endPoint = request->endPoint;
    urb->buffer = request->buffer;
    urb->bufferLength = (int32_t)request->length;
    urb->userContext = request;
    request->urbs = urb;
    request->numUrbs = 1;

    ret = ioctl(fd, USBDEVFS_SUBMITURB, urb);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d submiturb failed, errno = %{public}d", __func__, __LINE__, errno);
        RawUsbMemFree(urb);
        request->urbs = NULL;
        if (errno == ENODEV) {
            return HDF_DEV_ERR_NO_DEVICE;
        }
        return HDF_ERR_IO;
    }
    return HDF_SUCCESS;
}

static int32_t OsSubmitBulkRequestHandleUrb(
    struct UsbHostRequest *request, struct UsbAdapterUrb *urb, int32_t bulkBufferLen, int32_t number)
{
    if (bulkBufferLen == 0) {
        HDF_LOGE("%{public}s:%{public}d bulkBufferLen can not be zero", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    urb->userContext = (void *)request;
    switch (request->requestType) {
        case USB_REQUEST_TYPE_BULK:
            urb->type = USB_ADAPTER_URB_TYPE_BULK;
            break;
        case USB_REQUEST_TYPE_INTERRUPT:
            urb->type = USB_ADAPTER_URB_TYPE_INTERRUPT;
            break;
        default:
            HDF_LOGE("%{public}s:%{public}d unknown requestType = %{public}u",
                __func__, __LINE__, request->requestType);
            return HDF_ERR_INVALID_PARAM;
    }
    urb->endPoint = request->endPoint;
    urb->buffer = request->buffer + (number * bulkBufferLen);
    if (number == request->numUrbs - 1) {
        uint32_t len = (uint32_t)(request->length % bulkBufferLen);
        urb->bufferLength = (int32_t)(len == 0) ? bulkBufferLen : len;
    } else {
        urb->bufferLength = bulkBufferLen;
    }

    return HDF_SUCCESS;
}

static int32_t OsSubmitBulkRequestHandle(
    struct UsbHostRequest *request, struct UsbAdapterUrb *urbs, int32_t bulkBufferLen)
{
    int32_t fd = request->devHandle->fd;
    int32_t numUrbs = request->numUrbs;

    for (int32_t i = 0; i < numUrbs; i++) {
        struct UsbAdapterUrb *urb = &urbs[i];
        int32_t ret = OsSubmitBulkRequestHandleUrb(request, urb, bulkBufferLen, i);
        if (ret != HDF_SUCCESS) {
            return ret;
        }

        ret = ioctl(fd, USBDEVFS_SUBMITURB, urb);
        if (ret == 0) {
            continue;
        }

        if (i == 0) {
            HDF_LOGE("submitUrb: ret=%{public}d errno=%{public}d length=%{public}d endPoint=%{public}d type=%{public}d",
                ret, errno, urb->bufferLength, urb->endPoint, urb->type);
            return HDF_ERR_IO;
        }
        request->numRetired += numUrbs - i;
        if (errno != EREMOTEIO) {
            request->reqStatus = USB_REQUEST_ERROR;
        }

        return HDF_SUCCESS;
    }

    return HDF_SUCCESS;
}

static int32_t OsSubmitBulkRequest(struct UsbHostRequest *request)
{
    struct UsbAdapterUrb *urbs = NULL;
    int32_t bulkBufferLen;
    int32_t numUrbs;

    if (request == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (request->length <= 0) {
        HDF_LOGE("request->length less than the minimum");
        return HDF_FAILURE;
    }

    if (request->length > MAX_BULK_DATA_BUFFER_LENGTH) {
        HDF_LOGE("request->length greater than the maximum");
        return HDF_FAILURE;
    }

    if (request->devHandle->caps & USB_ADAPTER_CAP_BULK_SCATTER_GATHER) {
        // The 1 is to prevent division by zero errors
        bulkBufferLen = (int32_t)request->length ? request->length : 1;
    } else if (request->devHandle->caps & USB_ADAPTER_CAP_BULK_CONTINUATION) {
        bulkBufferLen = MAX_BULK_DATA_BUFFER_LENGTH;
    } else if (request->devHandle->caps & USB_ADAPTER_CAP_NO_PACKET_SIZE_LIM) {
        // The 1 is to prevent division by zero errors
        bulkBufferLen = (int32_t)request->length ? request->length : 1;
    } else {
        bulkBufferLen = MAX_BULK_DATA_BUFFER_LENGTH;
    }
    numUrbs = request->length / bulkBufferLen;
    if ((request->length % bulkBufferLen) > 0) {
        numUrbs++;
    }

    if (numUrbs != 1) {
        urbs = RawUsbMemCalloc(numUrbs * sizeof(*urbs));
        if (request->bulkUrb) {
            RawUsbMemFree(request->bulkUrb);
        }
        request->bulkUrb = urbs;
        request->urbs = NULL;
    } else {
        urbs = request->bulkUrb;
    }

    if (urbs == NULL) {
        HDF_LOGE("%{public}s:%{public}d no mem", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    request->urbs = urbs;
    request->numUrbs = numUrbs;
    request->numRetired = 0;
    request->reqStatus = USB_REQUEST_COMPLETED;

    return OsSubmitBulkRequestHandle(request, urbs, bulkBufferLen);
}

static int32_t OsAllocIsoUrbs(struct UsbHostRequest *request, int32_t numUrbs, struct UsbAdapterUrb **urbs)
{
    struct UsbAdapterUrb *urb = NULL;
    unsigned char *urbBuffer = request->buffer;
    int32_t numPacketsLeft = request->numIsoPackets;
    int32_t packetIdx = 0;
    int32_t i, j;

    for (i = 0; i < numUrbs; i++) {
        int32_t numPackets = MIN(numPacketsLeft, MAX_ISO_PACKETS_PER_URB);
        urb = RawUsbMemCalloc(sizeof(struct UsbAdapterUrb));
        if (urb == NULL) {
            OsFreeIsoUrbs(request);
            return HDF_ERR_MALLOC_FAIL;
        }
        urbs[i] = urb;

        for (j = 0; j < numPackets; j++) {
            unsigned int packetLen = request->isoPacketDesc[packetIdx++].length;
            urb->bufferLength += (int32_t)packetLen;
            urb->isoFrameDesc[j].length = packetLen;
        }
        urb->type = USB_ADAPTER_URB_TYPE_ISO;
        urb->flags = USB_ADAPTER_URB_ISO_ASAP;
        urb->endPoint = request->endPoint;
        urb->numberOfPackets = numPackets;
        urb->buffer = (void *)urbBuffer;
        urb->userContext = request;
        urbBuffer += urb->bufferLength;
        numPacketsLeft -= numPackets;
    }

    return HDF_SUCCESS;
}

static int32_t OsSubmitIsoUrbs(struct UsbHostRequest *request, int32_t numUrbs, struct UsbAdapterUrb **pUrbs)
{
    for (int32_t i = 0; i < numUrbs; i++) {
        int32_t ret = ioctl(request->devHandle->fd, USBDEVFS_SUBMITURB, *pUrbs[i]);
        if (ret == 0) {
            continue;
        }

        if (errno == ENODEV) {
            ret = HDF_DEV_ERR_NO_DEVICE;
        } else {
            HDF_LOGE("%{public}s:%{public}d submit iso urb failed errno=%{public}d", __func__, __LINE__, errno);
            ret = HDF_ERR_IO;
        }

        if (i == 0) {
            HDF_LOGE("first URB failed");
            OsFreeIsoUrbs(request);
            return ret;
        }
        request->reqStatus = USB_REQUEST_ERROR;
        request->numRetired += numUrbs - i;
        if (request->numRetired == numUrbs) {
            RawUsbMemFree(pUrbs);
            request->urbs = NULL;
        }
        break;
    }

    return HDF_SUCCESS;
}

static int32_t OsSubmitIsoRequest(struct UsbHostRequest *request)
{
    if (request == NULL || request->devHandle == NULL || request->numIsoPackets < 1) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (request->length > MAX_ISO_DATA_BUFFER_LEN) {
        HDF_LOGE("%{public}s:%{public}d request length exceed the maximum", __func__, __LINE__);
        return -1;
    }

    unsigned int totalLen = 0;
    for (int32_t i = 0; i < request->numIsoPackets; i++) {
        unsigned int packetLen = request->isoPacketDesc[i].length;
        if (packetLen > MAX_ISO_DATA_BUFFER_LEN) {
            HDF_LOGE("%{public}s:%{public}d packet length: %{public}u exceeds maximum: %{public}u",
                __func__, __LINE__, packetLen, MAX_ISO_DATA_BUFFER_LEN);
            return HDF_ERR_INVALID_PARAM;
        }
        totalLen += packetLen;
    }
    if (request->length < totalLen) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t numUrbs = (request->numIsoPackets + (MAX_ISO_PACKETS_PER_URB - 1)) / MAX_ISO_PACKETS_PER_URB;
    struct UsbAdapterUrb **pUrbs = RawUsbMemCalloc(numUrbs * sizeof(struct UsbAdapterUrb *));
    if (pUrbs == NULL) {
        HDF_LOGE("%{public}s:%{public}d RawUsbMemCalloc pUrbs failed", __func__, __LINE__);
        return HDF_ERR_MALLOC_FAIL;
    }
    request->isoUrbs = (void **)pUrbs;
    request->numUrbs = numUrbs;
    request->numRetired = 0;
    request->isoPacketOffset = 0;
    int32_t ret = OsAllocIsoUrbs(request, numUrbs, pUrbs);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d alloc iso urbs failed", __func__, __LINE__);
        return ret;
    }

    return OsSubmitIsoUrbs(request, numUrbs, pUrbs);
}

static int32_t OsControlCompletion(struct UsbHostRequest *request, struct UsbAdapterUrb *urb)
{
    int32_t status;

    request->actualLength += urb->actualLength;
    if (request->reqStatus == USB_REQUEST_CANCELLED) {
        RawUsbMemFree(request->urbs);
        request->urbs = NULL;
        return RawHandleRequestCompletion(request, USB_REQUEST_CANCELLED);
    }

    switch (urb->status) {
        case 0:
            status = USB_REQUEST_COMPLETED;
            break;
        case -ENOENT:
            status = USB_REQUEST_CANCELLED;
            break;
        case -EPIPE:
            status = USB_REQUEST_STALL;
            break;
        case -EOVERFLOW:
            status = USB_REQUEST_OVERFLOW;
            break;
        case -ENODEV:
        case -ESHUTDOWN:
            status = USB_REQUEST_NO_DEVICE;
            break;
        default:
            status = USB_REQUEST_ERROR;
            break;
    }
    RawUsbMemFree(request->urbs);
    request->urbs = NULL;
    return RawHandleRequestCompletion(request, status);
}

static void OsIsoRequestDesStatus(struct UsbHostRequest *request, struct UsbAdapterUrb *urb)
{
    int32_t i;
    struct UsbIsoPacketDesc *urbDesc = NULL;
    struct UsbIsoPacketDesc *requestDesc = NULL;

    for (i = 0; i < urb->numberOfPackets; i++) {
        urbDesc = &urb->isoFrameDesc[i];
        requestDesc = &request->isoPacketDesc[request->isoPacketOffset++];

        switch (urbDesc->status) {
            case HDF_SUCCESS:
                requestDesc->status = USB_REQUEST_COMPLETED;
                break;
            case -ENODEV:
            case -ESHUTDOWN:
                requestDesc->status = USB_REQUEST_NO_DEVICE;
                break;
            case -EPIPE:
                requestDesc->status = USB_REQUEST_STALL;
                break;
            case -EOVERFLOW:
                requestDesc->status = USB_REQUEST_OVERFLOW;
                break;
            default:
                requestDesc->status = USB_REQUEST_ERROR;
                break;
        }

        requestDesc->actualLength = urbDesc->actualLength;
    }
}

static int32_t OsIsoCompletion(struct UsbHostRequest *request, struct UsbAdapterUrb *urb)
{
    UsbRequestStatus status;
    int32_t urbIndex = 0;
    int32_t numUrbs;

    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    numUrbs = request->numUrbs;

    for (int32_t i = 0; i < numUrbs; i++) {
        if (urb == request->isoUrbs[i]) {
            urbIndex = i + 1;
            break;
        }
    }
    if (urbIndex == 0) {
        HDF_LOGE("%{public}s:%{public}d urbIndex is zero", __func__, __LINE__);
        return HDF_ERR_BAD_FD;
    }

    OsIsoRequestDesStatus(request, urb);
    request->numRetired++;
    if (request->reqStatus != USB_REQUEST_COMPLETED) {
        HDF_LOGE("%{public}s:%{public}d urb status=%{public}d", __func__, __LINE__, urb->status);
        if (request->numRetired == numUrbs) {
            OsFreeIsoUrbs(request);
            return RawHandleRequestCompletion(request, USB_REQUEST_ERROR);
        }
        goto OUT;
    }

    if (urb->status == -ESHUTDOWN) {
        status = USB_REQUEST_NO_DEVICE;
    } else if (!((urb->status == HDF_SUCCESS) || (urb->status == -ENOENT) || (urb->status == -ECONNRESET))) {
        status = USB_REQUEST_ERROR;
    } else {
        status = USB_REQUEST_COMPLETED;
    }

    if (request->numRetired == numUrbs) {
        OsFreeIsoUrbs(request);
        return RawHandleRequestCompletion(request, status);
    }
OUT:
    return 0;
}

static int32_t OsProcessAbnormalReap(struct UsbHostRequest *request, const struct UsbAdapterUrb *urb)
{
    if (urb->actualLength > 0) {
        unsigned char *target = request->buffer + request->actualLength;
        if (urb->buffer != target) {
            if (memmove_s(target, urb->actualLength, urb->buffer, urb->actualLength) != EOK) {
                HDF_LOGE("%{public}s: memmove_s failed", __func__);
                return HDF_FAILURE;
            }
        }
        request->actualLength += urb->actualLength;
    }
    if (request->numRetired == request->numUrbs) {
        return HDF_SUCCESS;
    }

    return HDF_ERR_IO;
}

static int32_t OsUrbStatusToRequestStatus(struct UsbHostRequest *request, const struct UsbAdapterUrb *urb)
{
    int32_t ret;

    switch (urb->status) {
        case 0:
            ret = HDF_SUCCESS;
            break;
        case -ESHUTDOWN:
            request->reqStatus = USB_REQUEST_NO_DEVICE;
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
        case -EPIPE:
            if (request->reqStatus == USB_REQUEST_COMPLETED) {
                request->reqStatus = USB_REQUEST_STALL;
            }
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
        case -EOVERFLOW:
            if (request->reqStatus == USB_REQUEST_COMPLETED) {
                request->reqStatus = USB_REQUEST_OVERFLOW;
            }
            ret = HDF_FAILURE;
            break;
        default:
            if (request->reqStatus == USB_REQUEST_COMPLETED) {
                request->reqStatus = USB_REQUEST_ERROR;
            }
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
    }

    return ret;
}

static int32_t OsBulkCompletion(struct UsbHostRequest * const request, const struct UsbAdapterUrb *urb)
{
    int32_t ret;
    int32_t urbIdx = urb - (struct UsbAdapterUrb *)request->urbs;

    request->numRetired++;
    if (request->reqStatus != USB_REQUEST_COMPLETED) {
        if (OsProcessAbnormalReap(request, urb) == HDF_SUCCESS) {
            goto COMPLETED;
        } else {
            goto OUT;
        }
    }
    request->actualLength += urb->actualLength;

    ret = OsUrbStatusToRequestStatus(request, urb);
    if (ret == HDF_DEV_ERR_NO_DEVICE) {
        goto CANCEL;
    } else if (ret == HDF_FAILURE) {
        goto COMPLETED;
    }

    if (request->numRetired == request->numUrbs) {
        goto COMPLETED;
    } else if (urb->actualLength < urb->bufferLength) {
        if (request->reqStatus == USB_REQUEST_COMPLETED) {
            request->reqStatus = USB_REQUEST_COMPLETED_SHORT;
        }
    } else {
        goto OUT;
    }

CANCEL:
    if (request->numRetired == request->numUrbs) {
        goto COMPLETED;
    }
    OsDiscardUrbs(request, urbIdx + 1, request->numUrbs);
OUT:
    return HDF_SUCCESS;
COMPLETED:
    return RawHandleRequestCompletion(request, request->reqStatus);
}

static int32_t AdapterInit(const struct UsbSession *session)
{
    (void)session;
    return HDF_SUCCESS;
}

static void AdapterExit(const struct UsbSession *session)
{
    (void)session;
    return;
}

static struct UsbDeviceHandle *AdapterOpenDevice(struct UsbSession *session, uint8_t busNum, uint8_t usbAddr)
{
    int32_t ret;
    struct UsbDevice *dev = NULL;
    struct UsbDeviceHandle *handle = NULL;

    if (session == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param session.\n", __func__, __LINE__);
        return NULL;
    }

    handle = OsGetDeviceHandle(session, busNum, usbAddr);
    if (handle != NULL) {
        return handle;
    }

    handle = OsCallocDeviceHandle();
    if (handle == NULL) {
        return NULL;
    }

    dev = OsAllocDevice(session, handle);
    if (dev == NULL) {
        goto ERR;
    }

    ret = OsInitDevice(dev, busNum, usbAddr);
    if (ret) {
        RawUsbMemFree(dev);
        goto ERR;
    }

    OsalAtomicSet(&dev->refcnt, 1);
    /* add the new device to the device list on session */
    OsalMutexLock(&session->lock);
    HdfSListAdd(&session->usbDevs, &dev->list);
    OsalMutexUnlock(&session->lock);

    return handle;

ERR:
    OsalMutexDestroy(&handle->lock);
    RawUsbMemFree(handle);
    return NULL;
}

static void AdapterCloseDevice(struct UsbDeviceHandle *handle)
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

    close(handle->fd);
    close(handle->mmapFd);
    OsalMutexDestroy(&handle->lock);
    RawUsbMemFree(handle);
}

static int32_t AdapterGetConfigDescriptor(const struct UsbDevice *dev, uint8_t configIndex, void *buffer, size_t len)
{
    struct UsbDeviceConfigDescriptor *config = NULL;
    uint8_t i;

    if (dev == NULL || buffer == NULL || (configIndex > dev->deviceDescriptor.bNumConfigurations)) {
        HDF_LOGE("%{public}s:%{public}d Invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    for (i = 0; i < dev->deviceDescriptor.bNumConfigurations; i++) {
        if (configIndex == dev->configDescriptors[i].desc->bConfigurationValue) {
            config = &dev->configDescriptors[i];
            break;
        }
    }

    if (config == NULL) {
        if (dev->deviceDescriptor.bNumConfigurations == 1) {
            HDF_LOGW("%{public}s: return default config", __func__);
            config = &dev->configDescriptors[0];
        } else {
            HDF_LOGE("%{public}s: config is null", __func__);
            return HDF_ERR_BAD_FD;
        }
    }

    len = MIN(len, config->actualLen);
    if (memcpy_s(buffer, len, config->desc, len) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_ERR_IO;
    }

    return (int32_t)len;
}

static int32_t AdapterGetConfiguration(const struct UsbDeviceHandle *handle, uint8_t *activeConfig)
{
    if (handle == NULL || activeConfig == NULL || handle->dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = OsGetActiveConfig(handle->dev, handle->fd);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    *activeConfig = handle->dev->activeConfig;
    if (*activeConfig == 0) {
        HDF_LOGD("%{public}s:%{public}d activeConfig is zero", __func__, __LINE__);
    }

    return HDF_SUCCESS;
}

static int32_t AdapterSetConfiguration(struct UsbDeviceHandle *handle, int32_t activeConfig)
{
    int32_t ret;

    if (handle == NULL || handle->dev == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ioctl(handle->fd, USBDEVFS_SETCONFIGURATION, &activeConfig);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d set config failed errno=%{public}d", __func__, __LINE__, errno);
        return HDF_FAILURE;
    }
    if (activeConfig == HDF_FAILURE) {
        activeConfig = 0;
    }
    handle->dev->activeConfig = (uint8_t)activeConfig;

    return HDF_SUCCESS;
}

static int32_t AdapterClaimInterface(const struct UsbDeviceHandle *handle, unsigned int interfaceNumber)
{
    int32_t ret;

    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ioctl(handle->fd, USBDEVFS_CLAIMINTERFACE, &interfaceNumber);
    if (ret < 0) {
        HDF_LOGE("%{public}s;%{public}d claim failed errno=%{public}d", __func__, __LINE__, errno);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AdapterDetachKernelDriver(const struct UsbDeviceHandle *handle, uint8_t interfaceNumber)
{
    int32_t ret;
    if (handle == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbAdapterIoctl command = {interfaceNumber, USBDEVFS_DISCONNECT, NULL};
    ret = ioctl(handle->fd, USBDEVFS_IOCTL, &command);
    if (ret < 0) {
        HDF_LOGE("%{public}s connect failed, ret = %{public}d, errno:%{public}d", __func__, ret, errno);
        return ret;
    }
    HDF_LOGI("%{public}s ret = %{public}d, errno = %{public}d ", __func__, ret, errno);
    return ret;
}

static int32_t AdapterAttachKernelDriver(const struct UsbDeviceHandle *handle, uint8_t interfaceNumber)
{
    int32_t ret;
    if (handle == NULL) {
        HDF_LOGE("%{public}s invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbAdapterIoctl cmd = {interfaceNumber, USBDEVFS_CONNECT, NULL};
    ret = ioctl(handle->fd, USBDEVFS_IOCTL, &cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s connect failed, ret = %{public}d, errno:%{public}d", __func__, ret, errno);
        return ret;
    }
    HDF_LOGI("%{public}s ret = %{public}d, errno = %{public}d ", __func__, ret, errno);
    return ret;
}

static int32_t AdapterDetachKernelDriverAndClaim(const struct UsbDeviceHandle *handle, uint32_t interfaceNumber)
{
    int32_t ret;
    if (handle == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbAdapterDisconnectClaim dc;
    struct UsbAdapterGetdriver getDriver = {interfaceNumber, {0}};
    ret = ioctl(handle->fd, USBDEVFS_GETDRIVER, &getDriver);
    if (ret != 0 && errno == ENODATA) {
        HDF_LOGI("%{public}s: no usb driver", __func__);
        return AdapterClaimInterface(handle, interfaceNumber);
    }
    if (ret == 0 && strcmp(getDriver.driver, "usbfs") == 0) {
        HDF_LOGI("%{public}s: usbfs already claimed", __func__);
        return HDF_SUCCESS;
    }

    dc.interface = interfaceNumber;
    ret = strcpy_s(dc.driver, MAX_DRIVER_NAME_LENGTH, "usbfs");
    if (ret != EOK) {
        HDF_LOGE("%{public}s: strcpy_s failed", __func__);
        return ret;
    }
    dc.flags = DISCONNECT_CLAIM_EXCEPT_DRIVER;
    ret = ioctl(handle->fd, USBDEVFS_DISCONNECT_CLAIM, &dc);
    if (ret == 0) {
        return HDF_SUCCESS;
    }
    if (errno != ENOTTY) {
        HDF_LOGE("%{public}s: disconnect-and-claim failed errno %{public}d", __func__, errno);
        return ret;
    }

    struct UsbAdapterIoctl command = {interfaceNumber, USBDEVFS_DISCONNECT, NULL};
    ret = ioctl(handle->fd, USBDEVFS_IOCTL, &command);
    if (ret != 0) {
        HDF_LOGE("%{public}s; disconnet failed errno = %{public}d", __func__, errno);
        return ret;
    }
    return AdapterClaimInterface(handle, interfaceNumber);
}

static int32_t AdapterReleaseInterface(const struct UsbDeviceHandle *handle, unsigned int interfaceNumber)
{
    int32_t ret;

    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ioctl(handle->fd, USBDEVFS_RELEASEINTERFACE, &interfaceNumber);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d release failed errno=%{public}d", __func__, __LINE__, errno);
        if (errno == ENODEV) {
            return HDF_DEV_ERR_NO_DEVICE;
        }
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AdapterSetInterface(const struct UsbDeviceHandle *handle, uint8_t interface, uint8_t altSetting)
{
    struct UsbAdapterSetInterface setIntf;
    int32_t ret;

    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    setIntf.interface = interface;
    setIntf.altSetting = altSetting;
    ret = ioctl(handle->fd, USBDEVFS_SETINTERFACE, &setIntf);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d set interface failed errno=%{public}d", __func__, __LINE__, errno);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AdapterClearHalt(const struct UsbDeviceHandle *handle, unsigned int endPoint)
{
    int32_t ret;

    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ioctl(handle->fd, USBDEVFS_CLEAR_HALT, &endPoint);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d clear halt failed errno=%{public}d", __func__, __LINE__, errno);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AdapterResetDevice(const struct UsbDeviceHandle *handle)
{
    int32_t ret;
    uint8_t i;

    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    for (i = 0; i < USB_MAXINTERFACES; i++) {
        if (handle->claimedInterfaces & (1UL << i)) {
            AdapterReleaseInterface(handle, i);
        }
    }

    ret = ioctl(handle->fd, USBDEVFS_RESET, NULL);
    if (ret < 0) {
        HDF_LOGE("%{public}s:%{public}d errno=%{public}d", __func__, __LINE__, errno);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static struct UsbHostRequest *AdapterAllocRequest(const struct UsbDeviceHandle *handle, int32_t isoPackets, size_t len)
{
    void *memBuf = NULL;
    struct UsbHostRequest *request = NULL;
    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return NULL;
    }
    size_t allocSize = sizeof(struct UsbHostRequest) + (sizeof(struct UsbIsoPacketDesc) * (size_t)isoPackets) +
        (sizeof(unsigned char) * len);

#ifdef USB_EVENT_NOTIFY_LINUX_NATIVE_MODE
    memBuf = RawUsbMemCalloc(allocSize);
    if (memBuf == NULL) {
        HDF_LOGE("%{public}s: alloc UsbHostRequest failed", __func__);
        return NULL;
    }
#else
    memBuf = mmap(NULL, allocSize, PROT_READ | PROT_WRITE, MAP_SHARED, handle->fd, 0);
    if (memBuf == MAP_FAILED) {
        HDF_LOGE("%{public}s:%{public}d mmap failed, errno=%{public}d", __func__, __LINE__, errno);
        return NULL;
    }
#endif
    request = (struct UsbHostRequest *)memBuf;
    request->numIsoPackets = isoPackets;
    request->buffer = (unsigned char *)memBuf + allocSize - len;
    request->bufLen = (int32_t)len;
    request->bulkUrb = RawUsbMemCalloc(sizeof(struct UsbAdapterUrb));
    if (request->bulkUrb == NULL) {
        HDF_LOGE("%{public}s RawUsbMemAlloc fail", __func__);
        return NULL;
    }
    request->urbs = request->bulkUrb;
    return request;
}

static struct UsbHostRequest *AdapterAllocRequestByMmap(
    const struct UsbDeviceHandle *handle, int32_t isoPackets, size_t len)
{
    void *memBuf = NULL;
    struct UsbHostRequest *request = NULL;
    if (handle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return NULL;
    }
    size_t allocSize = sizeof(struct UsbHostRequest) + (sizeof(struct UsbIsoPacketDesc) * (size_t)isoPackets);

    request = RawUsbMemCalloc(allocSize);
    if (request == NULL) {
        HDF_LOGE("%{public}s: alloc UsbHostRequest failed", __func__);
        return NULL;
    }

    int32_t fd = handle->isAshmem ? handle->ashmemFd : handle->mmapFd;

    ftruncate(fd, len);
    memBuf = mmap(
        NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (memBuf == MAP_FAILED) {
        HDF_LOGE("%{public}s fd:%{public}d mmap failed, errno=%{public}d, len=%{public}zu",
            __func__, fd, errno, len);
        return NULL;
    }

    request->numIsoPackets = isoPackets;
    request->buffer = memBuf;
    request->bufLen = (int32_t)len;
    request->bulkUrb = RawUsbMemCalloc(sizeof(struct UsbAdapterUrb));
    if (request->bulkUrb == NULL) {
        HDF_LOGE("%{public}s RawUsbMemAlloc fail", __func__);
        return NULL;
    }
    request->urbs = request->bulkUrb;
    return request;
}

static int32_t AdapterFreeRequestByMmap(struct UsbHostRequest *request)
{
    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (request->bulkUrb) {
        RawUsbMemFree(request->bulkUrb);
        request->bulkUrb = NULL;
    }
    request->urbs = NULL;

    if (munmap((void *)request->buffer, request->bufLen) != 0) {
        HDF_LOGE("%{public}s:%{public}d munmap failed, errno=%{public}d", __func__, __LINE__, errno);
        return HDF_ERR_IO;
    }
    RawUsbMemFree(request);
    return HDF_SUCCESS;
}

static int32_t AdapterFreeRequest(struct UsbHostRequest *request)
{
    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid param", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (request->bulkUrb) {
        RawUsbMemFree(request->bulkUrb);
        request->bulkUrb = NULL;
    }
    request->urbs = NULL;
#ifdef USB_EVENT_NOTIFY_LINUX_NATIVE_MODE
    RawUsbMemFree(request);
#else
    size_t allocSize = sizeof(struct UsbHostRequest) +
        (sizeof(struct UsbIsoPacketDesc) * (size_t)(request->numIsoPackets)) + (size_t)request->bufLen;
    if (munmap((void *)request, allocSize) != 0) {
        HDF_LOGE("%{public}s:%{public}d munmap failed, errno=%{public}d", __func__, __LINE__, errno);
        return HDF_ERR_IO;
    }
#endif
    return HDF_SUCCESS;
}

static int32_t AdapterSubmitRequest(struct UsbHostRequest *request)
{
    int32_t ret;

    if (request == NULL) {
        HDF_LOGE("%{public}s:%{public}d request is NULL", __func__, __LINE__);
        return HDF_FAILURE;
    }

    request->actualLength = 0;
    switch (request->requestType) {
        case USB_REQUEST_TYPE_CONTROL:
            ret = OsSubmitControlRequest(request);
            break;
        case USB_REQUEST_TYPE_ISOCHRONOUS:
            ret = OsSubmitIsoRequest(request);
            break;
        case USB_REQUEST_TYPE_BULK:
        case USB_REQUEST_TYPE_INTERRUPT:
            ret = OsSubmitBulkRequest(request);
            break;
        default:
            HDF_LOGE("%{public}s:%{public}d unknown requestType=%{public}u", __func__, __LINE__, request->requestType);
            ret = HDF_ERR_INVALID_PARAM;
            break;
    }

    return ret;
}

static int32_t AdapterCancelRequest(struct UsbHostRequest * const request)
{
    if (!request->urbs) {
        HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
        return HDF_ERR_BAD_FD;
    }

    OsDiscardUrbs(request, 0, request->numUrbs);

    if (!((request->requestType == USB_REQUEST_TYPE_BULK) && (request->reqStatus == USB_REQUEST_ERROR))) {
        request->reqStatus = USB_REQUEST_CANCELLED;
    }

    return HDF_SUCCESS;
}

static int32_t AdapterUrbCompleteHandle(const struct UsbDeviceHandle *devHandle)
{
    struct UsbAdapterUrb *urb = NULL;
    struct UsbHostRequest *request = NULL;
    int32_t ret;

    if (devHandle == NULL) {
        HDF_LOGE("%{public}s:%{public}d invalid parameter", __func__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ioctl(devHandle->fd, USBDEVFS_REAPURB, &urb);
    if (ret < 0) {
        if (errno == EAGAIN) {
            return 1;
        }
        if (errno == ENODEV) {
            return HDF_DEV_ERR_NO_DEVICE;
        }

        return HDF_ERR_IO;
    }

    request = urb->userContext;

    switch (request->requestType) {
        case USB_REQUEST_TYPE_CONTROL:
            ret = OsControlCompletion(request, urb);
            break;
        case USB_REQUEST_TYPE_ISOCHRONOUS:
            ret = OsIsoCompletion(request, urb);
            break;
        case USB_REQUEST_TYPE_BULK:
        case USB_REQUEST_TYPE_INTERRUPT:
            ret = OsBulkCompletion(request, (const struct UsbAdapterUrb *)urb);
            break;
        default:
            HDF_LOGE("%{public}s:%{public}d unrecognised requestType %{public}u",
                __func__, __LINE__, request->requestType);
            ret = HDF_FAILURE;
            break;
    }

    return ret;
}

static bool AdapterGetInterfaceActiveStatus(const struct UsbDeviceHandle *devHandle, uint8_t interfaceNumber)
{
    int32_t ret;
    if (devHandle == NULL) {
        return false;
    }
    struct UsbAdapterGetdriver getDriver = {interfaceNumber, {0}};
    ret = ioctl(devHandle->fd, USBDEVFS_GETDRIVER, &getDriver);
    if (ret < 0 || strcmp(getDriver.driver, "usbfs") == 0) {
        return false;
    }
    return true;
}

static struct UsbOsAdapterOps g_usbAdapter = {
    .init = AdapterInit,
    .exit = AdapterExit,
    .openDevice = AdapterOpenDevice,
    .closeDevice = AdapterCloseDevice,
    .getConfigDescriptor = AdapterGetConfigDescriptor,
    .getConfiguration = AdapterGetConfiguration,
    .setConfiguration = AdapterSetConfiguration,
    .claimInterface = AdapterClaimInterface,
    .releaseInterface = AdapterReleaseInterface,
    .setInterfaceAltsetting = AdapterSetInterface,
    .clearHalt = AdapterClearHalt,
    .resetDevice = AdapterResetDevice,
    .allocRequest = AdapterAllocRequest,
    .allocRequestByMmap = AdapterAllocRequestByMmap,
    .freeRequest = AdapterFreeRequest,
    .freeRequestByMmap = AdapterFreeRequestByMmap,
    .submitRequest = AdapterSubmitRequest,
    .cancelRequest = AdapterCancelRequest,
    .urbCompleteHandle = AdapterUrbCompleteHandle,
    .detachKernelDriverAndClaim = AdapterDetachKernelDriverAndClaim,
    .attachKernelDriver = AdapterAttachKernelDriver,
    .detachKernelDriver = AdapterDetachKernelDriver,
    .usbControlMsg = AdapterUsbControlMsg,
    .getUsbSpeed = AdapterGetUsbSpeed,
    .getInterfaceActiveStatus = AdapterGetInterfaceActiveStatus,
};

static void OsSignalHandler(int32_t signo)
{
    (void)signo;
    return;
}

struct UsbOsAdapterOps *UsbAdapterGetOps(void)
{
    return &g_usbAdapter;
}

UsbRawTidType UsbAdapterGetTid(void)
{
    return gettid();
}

int32_t UsbAdapterRegisterSignal(void)
{
    if (signal(SIGUSR1, OsSignalHandler) == SIG_ERR) {
        HDF_LOGE("%{public}s:%{public}d Can't set AdapterSignalHandler for SIGUSR1", __func__, __LINE__);
        return HDF_ERR_IO;
    }

    return HDF_SUCCESS;
}

int32_t UsbAdapterKillSignal(struct UsbDeviceHandle *devHandle, UsbRawTidType tid)
{
    (void)devHandle;
    return HDF_SUCCESS;
}

int32_t AdapterAtomicInc(OsalAtomic *v)
{
    return OsalAtomicInc(v);
}

int32_t AdapterAtomicDec(OsalAtomic *v)
{
    return OsalAtomicDec(v);
}
