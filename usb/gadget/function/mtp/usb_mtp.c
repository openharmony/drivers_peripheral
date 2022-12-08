/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "usb_mtp.h"

#include "default_config.h"
#include "device_resource_if.h"
#include "hdf_base.h"
#include "hdf_device_object.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "securec.h"
#include "usbfn_device.h"
#include "usbfn_interface.h"
#include "usbfn_request.h"

#define HDF_LOG_TAG hdf_usb_mtp

// MTP interface descriptor
#define USB_MTP_DEVICE_CLASS    USB_DDK_CLASS_VENDOR_SPEC
#define USB_MTP_DEVICE_SUBCLASS USB_DDK_SUBCLASS_VENDOR_SPEC
#define USB_MTP_DEVICE_PROTOCOL 0

// PTP interface descriptor
#define USB_PTP_DEVICE_CLASS       USB_DDK_CLASS_STILL_IMAGE
#define USB_PTP_DEVICE_SUBCLASS    1
#define USB_PTP_DEVICE_PROTOCOL    1
#define MTP_CONTROL_XFER_BYTECOUNT 512

/* req count for control xfer */
#define MTP_CTRL_REQUEST_NUM 2

/* req count for bulk-out xfer */
#define READ_QUEUE_SIZE 8

/* req count for bulk-in xfer */
#define WRITE_QUEUE_SIZE             8
#define BULK_WRITE_BUF_SIZE          8192
#define BULK_READ_BUF_SIZE           8192
#define USB_HS_INTR_PACKET_MAX_BYTES 1024

/* MTP event packet max length */
#define MTP_EVENT_PACKET_MAX_BYTES 28

/* values for UsbMtpDevice.mtpState */
enum UsbMtpDeviceState {
    MTP_STATE_OFFLINE = 0, /* initial state, disconnected */
    MTP_STATE_READY,       /* ready for userspace calls */
    MTP_STATE_BUSY,        /* processing userspace calls */
    MTP_STATE_CANCELED,    /* transaction canceled by host */
    MTP_STATE_ERROR,       /* error from completion routine */
};

/* Compatible: ID for Microsoft MTP OS String */
#define USB_MTP_OS_STRING_ID        0xEE
#define USB_MTP_BMS_VENDORCODE      0x01
#define USB_MTP_EXTENDED_COMPAT_ID  0x0004
#define USB_MTP_EXTENDED_PROPERTIES 0x0005

/* MTP class reqeusts */
#define USB_MTP_REQ_CANCEL             0x64
#define USB_MTP_REQ_GET_EXT_EVENT_DATA 0x65
#define USB_MTP_REQ_RESET              0x66
#define USB_MTP_REQ_GET_DEVICE_STATUS  0x67

/* constants for device status */
#define MTP_RESPONSE_OK          0x2001
#define MTP_RESPONSE_DEVICE_BUSY 0x2019

/* Compatible: Microsoft MTP OS String */
static uint8_t g_mtpOsString[] = {18, /* sizeof(mtp_os_string) */
    USB_DDK_DT_STRING,
    /* Signature field: "MSFT100" (4D00530046005400310030003000) */
    'M', 0, 'S', 0, 'F', 0, 'T', 0, '1', 0, '0', 0, '0', 0,
    /* Vendor code to fetch other OS feature descriptors */
    1,
    /* padding */
    0};

/* Microsoft Extended Configuration Descriptor Header Section */
struct UsbMtpExtConfigDescHeader {
    uint32_t dwLength;
    uint16_t bcdVersion;
    uint16_t wIndex;
    uint8_t bCount;
    uint8_t reserved[7]; /* reserved */
};

/* Microsoft Extended Configuration Descriptor Function Section */
struct UsbMtpExtConfigDescFunction {
    uint8_t bFirstInterfaceNumber;
    uint8_t bInterfaceCount;
    uint8_t compatibleID[8];    /* The function’s compatible ID */
    uint8_t subCompatibleID[8]; /* The function’s subcompatible ID */
    uint8_t reserved[6];        /* reserved */
};

/* Compatible: MTP Extended Configuration Descriptor */
struct {
    struct UsbMtpExtConfigDescHeader header;
    struct UsbMtpExtConfigDescFunction function;
} g_mtpExtConfigDesc = {
    .header = {
        .dwLength = CPU_TO_LE32(sizeof(g_mtpExtConfigDesc)),
        /* The descriptor’s version number in Binary Coded Decimal (for example, version 1.00 is 0100H) */
        .bcdVersion = CPU_TO_LE16(0x0100),
        .wIndex = CPU_TO_LE16(4),
        .bCount = CPU_TO_LE16(1),
    },
    .function = {
        .bFirstInterfaceNumber = 0,
        .bInterfaceCount = 1,
        /* Media Transfer Protocol */
        .compatibleID = {'M', 'T', 'P'},
    },
};

struct UsbMtpDeviceStatus {
    uint16_t wLength;
    uint16_t wCode;
};

static void UsbMtpPortRxPush(struct UsbMtpPort *mtpPort);
static int32_t UsbMtpPortStartTx(struct UsbMtpPort *mtpPort);
static void UsbMtpDeviceFreeNotifyRequest(struct UsbMtpDevice *mtpDev);

static void UsbFnRequestReadComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    struct UsbMtpPort *mtpPort = (struct UsbMtpPort *)req->context;
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    (void)OsalMutexLock(&mtpDev->mutex);

    DListInsertTail(&req->list, &mtpPort->readQueue);
    mtpPort->readStarted--;
    (void)UsbMtpPortRxPush(mtpPort);

    (void)OsalMutexUnlock(&mtpDev->mutex);
}

static void UsbFnRequestWriteComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    struct UsbMtpPort *mtpPort = (struct UsbMtpPort *)req->context;
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    (void)OsalMutexLock(&mtpDev->mutex);

    DListInsertTail(&req->list, &mtpPort->writePool);
    mtpPort->writeStarted--;
    switch (req->status) {
        case USB_REQUEST_COMPLETED:
            (void)UsbMtpPortStartTx(mtpPort);
            break;
        case USB_REQUEST_NO_DEVICE:
            HDF_LOGV("%{public}s: usb mtpDev device was disconnected", __func__);
            mtpDev->mtpState = MTP_STATE_OFFLINE;
            break;
        default:
            HDF_LOGV("%{public}s: unexpected status %{public}d", __func__, req->status);
            mtpDev->mtpState = MTP_STATE_ERROR;
            break;
    }

    (void)OsalMutexUnlock(&mtpDev->mutex);
}

static void UsbFnRequestNotifyComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    struct UsbMtpDevice *mtpDev = (struct UsbMtpDevice *)req->context;
    if (mtpDev == NULL) {
        HDF_LOGE("%{public}s: usb mtpDev is null", __func__);
        return;
    }
    (void)OsalMutexLock(&mtpDev->mutex);

    switch (req->status) {
        case USB_REQUEST_COMPLETED:
            HDF_LOGV("%{public}s: notify req complete", __func__);
            mtpDev->isSendEventDone = true;
            break;
        case USB_REQUEST_NO_DEVICE:
            HDF_LOGV("%{public}s: usb mtpDev device was disconnected", __func__);
            mtpDev->mtpState = MTP_STATE_OFFLINE;
            break;
        default:
            HDF_LOGV("%{public}s unexpected status %{public}d", __func__, req->status);
            mtpDev->mtpState = MTP_STATE_ERROR;
            break;
    }
    mtpDev->notifyReq = req;

    (void)OsalMutexUnlock(&mtpDev->mutex);
}

static int32_t UsbMtpPortStartTx(struct UsbMtpPort *mtpPort)
{
    if (mtpPort == NULL || mtpPort->mtpDev == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    struct DListHead *pool = &mtpPort->writePool;
    int32_t ret = HDF_SUCCESS;
    while (!mtpPort->writeBusy && !DListIsEmpty(pool)) {
        if (mtpPort->writeStarted >= mtpPort->writeAllocated) {
            HDF_LOGE("%{public}s: no idle write req(BULK-IN)", __func__);
            return HDF_FAILURE;
        }
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        /* if mtpDev is disconnect, abort immediately */
        if (mtpPort->mtpDev->mtpState == MTP_STATE_OFFLINE) {
            return HDF_FAILURE;
        }
        uint32_t len = DataFifoRead(&mtpPort->writeFifo, req->buf, mtpPort->mtpDev->dataInPipe.maxPacketSize);
        if (len == 0) {
            return HDF_DEV_ERR_NODATA;
        }
        req->length = len;
        DListRemove(&req->list);
        mtpPort->writeBusy = true;
        ret = UsbFnSubmitRequestAsync(req);
        mtpPort->writeBusy = false;
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: submit bulk-in req error %{public}d", __func__, ret);
            DListInsertTail(&req->list, pool);
            break;
        }
        mtpPort->writeStarted++;
    }
    return ret;
}

static int32_t UsbMtpPortStartRx(struct UsbMtpPort *mtpPort)
{
    struct DListHead *pool = &mtpPort->readPool;
    struct UsbMtpPipe *out = &mtpPort->mtpDev->dataOutPipe;
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    while (!DListIsEmpty(pool)) {
        if (mtpPort->readStarted >= mtpPort->readAllocated) {
            HDF_LOGE("%{public}s no idle read req(BULK-OUT)", __func__);
            break;
        }
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        DListRemove(&req->list);
        req->length = out->maxPacketSize;
        int32_t ret = UsbFnSubmitRequestAsync(req);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: submit bulk-out req error %{public}d", __func__, ret);
            DListInsertTail(&req->list, pool);
            break;
        }
        mtpPort->readStarted++;
        /* if mtpDev is disconnect, abort immediately */
        if (mtpDev->mtpState == MTP_STATE_OFFLINE) {
            break;
        }
    }
    return mtpPort->readStarted;
}

static void UsbMtpPortRxPush(struct UsbMtpPort *mtpPort)
{
    if (mtpPort == NULL) {
        HDF_LOGE("%{public}s: usb mtpPort is null", __func__);
        return;
    }
    uint32_t size = 0;
    struct UsbFnRequest *req;
    uint8_t *data = NULL;
    uint32_t count = 0;
    struct DListHead *queue = &mtpPort->readQueue;
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    while (!DListIsEmpty(queue)) {
        req = DLIST_FIRST_ENTRY(queue, struct UsbFnRequest, list);
        switch (req->status) {
            case USB_REQUEST_NO_DEVICE:
                mtpDev->mtpState = MTP_STATE_OFFLINE;
                HDF_LOGV("%{public}s: usb mtpDev device was disconnected", __func__);
                break;
            case USB_REQUEST_COMPLETED:
                break;
            default:
                HDF_LOGE("%{public}s: unexpected status %{public}d", __func__, req->status);
                mtpDev->mtpState = MTP_STATE_ERROR;
                break;
        }
        if (req->actual != 0) {
            size = req->actual;
            data = req->buf;
            if (req->length < req->actual) {
                HDF_LOGW("%{public}s: recv short packet %{public}u vs %{public}u", __func__, req->length, req->actual);
            }
            if (DataFifoIsFull(&mtpPort->readFifo)) {
                DataFifoSkip(&mtpPort->readFifo, size);
            }
            count = DataFifoWrite(&mtpPort->readFifo, data, size);
            if (count != size) {
                HDF_LOGW("%{public}s: write %{public}u less than expected %{public}u", __func__, count, size);
            }
            HDF_LOGD("%{public}s: rx %{public}d/%{public}d", __func__, req->actual, count);
        }
        DListRemove(&req->list);
        DListInsertTail(&req->list, &mtpPort->readPool);
    }
    if (mtpDev->mtpState != MTP_STATE_OFFLINE && mtpPort->mtpDev) {
        (void)UsbMtpPortStartRx(mtpPort);
    }
}

static void UsbFnRequestCtrlComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    if (req == NULL) {
        return;
    }
    struct CtrlInfo *ctrlInfo = (struct CtrlInfo *)req->context;
    if (ctrlInfo == NULL) {
        return;
    }
    struct UsbMtpDevice *mtpDev = ctrlInfo->mtpDev;
    (void)OsalMutexLock(&mtpDev->mutex);
    switch (req->status) {
        case USB_REQUEST_COMPLETED:
            break;
        case USB_REQUEST_NO_DEVICE:
            HDF_LOGV("%{public}s: usb mtpDev device was disconnected", __func__);
            mtpDev->mtpState = MTP_STATE_OFFLINE;
            break;
        default:
            HDF_LOGV("%{public}s: unexpected status %{public}d", __func__, req->status);
            mtpDev->mtpState = MTP_STATE_ERROR;
            break;
    }
    if (req->status != USB_REQUEST_COMPLETED) {
        HDF_LOGD("%{public}s: ctrl completion error %{public}d", __func__, req->status);
    }
    DListInsertTail(&req->list, &mtpDev->ctrlPool);
    (void)OsalMutexUnlock(&mtpDev->mutex);
}

static int32_t UsbMtpDeviceAllocCtrlRequests(struct UsbMtpDevice *mtpDev, int32_t num)
{
    struct DListHead *head = &mtpDev->ctrlPool;
    struct UsbFnRequest *req = NULL;
    struct CtrlInfo *ctrlInfo = NULL;
    int32_t i;
    DListHeadInit(head);
    mtpDev->ctrlReqNum = 0;
    for (i = 0; i < num; i++) {
        HDF_LOGD("%{public}s: allocate memory for control request", __func__);
        ctrlInfo = (struct CtrlInfo *)OsalMemCalloc(sizeof(*ctrlInfo));
        if (ctrlInfo == NULL) {
            HDF_LOGE("%{public}s: Allocate ctrlInfo failed", __func__);
            goto OUT;
        }
        ctrlInfo->mtpDev = mtpDev;
        req = UsbFnAllocCtrlRequest(mtpDev->ctrlIface.handle, MTP_CONTROL_XFER_BYTECOUNT);
        if (req == NULL) {
            (void)OsalMemFree(ctrlInfo);
            goto OUT;
        }
        req->complete = UsbFnRequestCtrlComplete;
        req->context = ctrlInfo;
        DListInsertTail(&req->list, head);
        mtpDev->ctrlReqNum++;
    }
    return HDF_SUCCESS;
OUT:
    return DListIsEmpty(head) ? HDF_FAILURE : HDF_SUCCESS;
}

static void UsbMtpDeviceFreeCtrlRequests(struct UsbMtpDevice *mtpDev)
{
    struct DListHead *head = &mtpDev->ctrlPool;
    struct UsbFnRequest *req = NULL;
    while (!DListIsEmpty(head)) {
        req = DLIST_FIRST_ENTRY(head, struct UsbFnRequest, list);
        DListRemove(&req->list);
        (void)OsalMemFree(req->context);
        (void)UsbFnFreeRequest(req);
        mtpDev->ctrlReqNum--;
    }
}

static void UsbMtpPortFreeRequests(struct DListHead *head, int32_t *allocated)
{
    struct UsbFnRequest *req = NULL;
    while (!DListIsEmpty(head)) {
        req = DLIST_FIRST_ENTRY(head, struct UsbFnRequest, list);
        DListRemove(&req->list);
        (void)UsbFnFreeRequest(req);
        if (allocated) {
            (*allocated)--;
        }
    }
}

static int32_t UsbMtpPortAllocReadWriteRequests(struct UsbMtpPort *mtpPort, int32_t num, uint8_t isRead)
{
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    struct DListHead *head = (isRead == 1 ? &mtpPort->readPool : &mtpPort->writePool);
    uint8_t pipe = (isRead == 1 ? mtpDev->dataOutPipe.id : mtpDev->dataInPipe.id);
    uint32_t len = (isRead == 1 ? mtpDev->dataOutPipe.maxPacketSize : mtpDev->dataInPipe.maxPacketSize);
    int32_t i;
    for (i = 0; i < num; i++) {
        struct UsbFnRequest *req = UsbFnAllocRequest(mtpDev->dataIface.handle, pipe, len);
        if (req == NULL) {
            return DListIsEmpty(head) ? HDF_FAILURE : HDF_SUCCESS;
        }
        req->complete = isRead == 1 ? UsbFnRequestReadComplete : UsbFnRequestWriteComplete;
        req->context = mtpPort;
        DListInsertTail(&req->list, head);
        if (isRead == 1) {
            mtpPort->readAllocated++;
        } else {
            mtpPort->writeAllocated++;
        }
    }
    return HDF_SUCCESS;
}

static int32_t UsbMtpPortStartIo(struct UsbMtpPort *mtpPort)
{
    struct DListHead *head = &mtpPort->readPool;
    int32_t ret = HDF_SUCCESS;
    uint32_t started;
    /* allocate requests for read/write */
    if (mtpPort->readAllocated == 0) {
        HDF_LOGI("%{public}s: rx req not init, init first time", __func__);
        ret = UsbMtpPortAllocReadWriteRequests(mtpPort, READ_QUEUE_SIZE, 1);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: alloc read requests %{public}d failed: %{public}d", __func__, READ_QUEUE_SIZE, ret);
            return ret;
        }
    }

    if (mtpPort->writeAllocated == 0) {
        HDF_LOGI("%{public}s: tx req not init, init first time", __func__);
        ret = UsbMtpPortAllocReadWriteRequests(mtpPort, WRITE_QUEUE_SIZE, 0);
        if (ret != HDF_SUCCESS) {
            UsbMtpPortFreeRequests(head, &mtpPort->readAllocated);
            HDF_LOGE("%{public}s: alloc write requests %{public}d failed: %{public}d", __func__, WRITE_QUEUE_SIZE, ret);
            return ret;
        }
    }

    started = UsbMtpPortStartRx(mtpPort);
    if (started) {
        (void)UsbMtpPortStartTx(mtpPort);
    } else {
        UsbMtpPortFreeRequests(head, &mtpPort->readAllocated);
        UsbMtpPortFreeRequests(&mtpPort->writePool, &mtpPort->writeAllocated);
        HDF_LOGE("%{public}s: UsbMtpPortStartRx failed", __func__);
        ret = HDF_ERR_IO;
    }
    return ret;
}

static int32_t UsbMtpPortCancelIo(struct UsbMtpPort *mtpPort)
{
    (void)mtpPort;
    return HDF_SUCCESS;
}

static int32_t UsbMtpAllocReadWriteFifo(struct DataFifo *fifo, uint32_t size)
{
    if (!DataFifoIsInitialized(fifo)) {
        void *data = OsalMemAlloc(size);
        if (data == NULL) {
            HDF_LOGE("%{public}s: allocate fifo data buffer failed", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }
        HDF_LOGD("%{public}s: init fifo", __func__);
        DataFifoInit(fifo, size, data);
    }
    return HDF_SUCCESS;
}

static void UsbMtpDeviceFreeReadWriteFifo(struct DataFifo *fifo)
{
    void *buf = fifo->data;
    (void)OsalMemFree(buf);
    DataFifoInit(fifo, 0, NULL);
}

int32_t UsbMtpPortOpen(struct UsbMtpPort *mtpPort)
{
    if (mtpPort == NULL || mtpPort->mtpDev == NULL) {
        HDF_LOGE("%{public}s: mtpPort invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    (void)OsalMutexLock(&mtpDev->mutex);

    int32_t ret = UsbMtpAllocReadWriteFifo(&mtpPort->writeFifo, BULK_WRITE_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: alloc write fifo failed", __func__);
        goto OUT;
    }

    ret = UsbMtpAllocReadWriteFifo(&mtpPort->readFifo, BULK_READ_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: alloc read fifo failed", __func__);
        goto OUT;
    }

    /* the mtpDev is enabled, start the io stream */
    mtpDev->isSendEventDone = true;
    if (!mtpPort->suspended) {
        ret = UsbMtpPortStartIo(mtpPort);
        if (ret != HDF_SUCCESS) {
            goto OUT;
        }
        if (mtpDev->notifyUser != NULL && mtpDev->notifyUser->Connect != NULL) {
            HDF_LOGD("%{public}s: notify connect: open, ready for read", __func__);
            mtpDev->notifyUser->Connect(mtpDev);
        }
    } else {
        mtpPort->startDelayed = true;
    }
OUT:
    (void)OsalMutexUnlock(&mtpDev->mutex);
    return HDF_SUCCESS;
}

int32_t UsbMtpPortClose(struct UsbMtpPort *mtpPort)
{
    if (mtpPort == NULL || mtpPort->mtpDev == NULL) {
        HDF_LOGE("%{public}s: mtpPort invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    (void)OsalMutexLock(&mtpDev->mutex);

    if (!mtpPort->suspended) {
        if (mtpDev->notifyUser != NULL && mtpDev->notifyUser->Disconnect != NULL) {
            mtpDev->notifyUser->Disconnect(mtpDev);
        }
    }
    DataFifoReset(&mtpPort->writeFifo);
    DataFifoReset(&mtpPort->readFifo);
    mtpPort->startDelayed = false;

    (void)OsalMutexUnlock(&mtpDev->mutex);
    return HDF_SUCCESS;
}

static int32_t UsbMtpPortBulkInData(
    struct UsbMtpPort *mtpPort, const uint32_t *dataBuf, uint32_t dataSize, uint32_t *xferSize)
{
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    if (mtpDev->mtpState == MTP_STATE_OFFLINE) {
        HDF_LOGE("%{public}s: mtp device offline", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (mtpDev->mtpState == MTP_STATE_CANCELED) {
        mtpDev->mtpState = MTP_STATE_READY;
        HDF_LOGE("%{public}s: mtp device req cancel", __func__);
        return HDF_ERR_IO;
    }

    uint32_t writeLeft = dataSize;
    int32_t ret = HDF_SUCCESS;
    uint32_t writeTotal = 0;
    mtpDev->mtpState = MTP_STATE_BUSY;
    if ((dataSize & (mtpDev->dataInPipe.maxPacketSize - 1)) == 0) {
        HDF_LOGD("%{public}s: need send Zere Length Packet", __func__);
    }
    while (writeTotal < dataSize) {
        if (mtpDev->mtpState != MTP_STATE_BUSY) {
            HDF_LOGE("%{public}s: mtp device state: %{public}d", __func__, mtpDev->mtpState);
            return HDF_ERR_IO;
        }
        uint32_t singleXfer = (writeLeft > mtpPort->writeFifo.size) ? mtpPort->writeFifo.size : writeLeft;
        uint32_t singleXferActual = DataFifoWrite(&mtpPort->writeFifo, (uint8_t *)&dataBuf[writeTotal], singleXfer);
        ret = UsbMtpPortStartTx(mtpPort);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
        writeTotal += singleXferActual;
        writeLeft -= singleXferActual;
        *xferSize = writeTotal;
    }

    if (mtpDev->mtpState == MTP_STATE_CANCELED) {
        ret = HDF_ERR_IO;
    } else if (mtpDev->mtpState != MTP_STATE_OFFLINE) {
        mtpDev->mtpState = MTP_STATE_READY;
    }
    return ret;
}

static int32_t UsbMtpPortBulkOutData(
    struct UsbMtpPort *mtpPort, const uint32_t *dataBuf, uint32_t dataSize, uint32_t *xferSize)
{
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    if (mtpDev->mtpState == MTP_STATE_OFFLINE) {
        HDF_LOGE("%{public}s: mtp device offline", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (mtpDev->mtpState == MTP_STATE_CANCELED) {
        mtpDev->mtpState = MTP_STATE_READY;
        HDF_LOGE("%{public}s: mtp device req cancel", __func__);
        return HDF_ERR_IO;
    }

    uint32_t readLeft = dataSize;
    mtpDev->mtpState = MTP_STATE_BUSY;
    if ((dataSize & (mtpDev->dataInPipe.maxPacketSize - 1)) == 0) {
        HDF_LOGD("%{public}s: need send Zere Length Packet", __func__);
    }
    if (DataFifoAvailSize(&mtpPort->readFifo) == 0 || DataFifoIsEmpty(&mtpPort->readFifo)) {
        HDF_LOGE("%{public}s: no data read", __func__);
        return HDF_DEV_ERR_NODATA;
    }
    int32_t ret = HDF_SUCCESS;
    uint32_t readTotal = 0;
    while (readTotal < dataSize) {
        if (mtpDev->mtpState != MTP_STATE_BUSY) {
            HDF_LOGD("%{public}s: mtp device state: %{public}d", __func__, mtpDev->mtpState);
            return HDF_ERR_IO;
        }
        uint32_t singleXfer = (readLeft > mtpPort->readFifo.size) ? mtpPort->readFifo.size : readLeft;
        uint32_t singleXferActual = DataFifoRead(&mtpPort->readFifo, (uint8_t *)&dataBuf[readTotal], singleXfer);
        if (singleXferActual == 0) {
            HDF_LOGD("%{public}s: data read done", __func__);
            break;
        }
        (void)UsbMtpPortStartRx(mtpPort);
        readTotal += singleXferActual;
        readLeft -= singleXferActual;
        *xferSize = readTotal;
    }

    if (mtpDev->mtpState == MTP_STATE_CANCELED) {
        ret = HDF_ERR_IO;
    } else if (mtpDev->mtpState != MTP_STATE_OFFLINE) {
        mtpDev->mtpState = MTP_STATE_READY;
    }
    return ret;
}

int32_t UsbMtpPortRead(struct UsbMtpPort *mtpPort, struct HdfSBuf *reply)
{
    uint32_t fifoLen = 0;
    int32_t ret = HDF_SUCCESS;
    void *dataBuf;
    uint32_t xferSize = 0;
    if (mtpPort == NULL || mtpPort->mtpDev == NULL) {
        HDF_LOGE("%{public}s: mtpPort invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    if (DataFifoIsEmpty(&mtpPort->readFifo)) {
        return HDF_DEV_ERR_NODATA;
    }
    (void)OsalMutexLock(&mtpDev->mutex);

    fifoLen = DataFifoLen(&mtpPort->readFifo);
    dataBuf = OsalMemCalloc(fifoLen + sizeof(uint32_t));
    if (dataBuf == NULL) {
        HDF_LOGE("%{public}s: malloc %{public}d error", __func__, fifoLen + sizeof(uint32_t));
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_ERR_MALLOC_FAIL;
    }
    ret = UsbMtpPortBulkOutData(mtpPort, (const uint32_t *)dataBuf, fifoLen, &xferSize);
    if (ret != HDF_SUCCESS) {
        if (ret == HDF_DEV_ERR_NODATA) {
            HDF_LOGE("%{public}s: read-fifo empty", __func__);
        }
        HDF_LOGE("%{public}s: mtp read failed: expect=%{public}d, actual=%{public}d, ret=%{public}d", __func__, fifoLen,
            xferSize, ret);
        goto OUT;
    }
    if (!HdfSbufWriteBuffer(reply, dataBuf, xferSize)) {
        HDF_LOGE("%{public}s: HdfSbufWriteBuffer error", __func__);
        ret = HDF_ERR_IO;
        goto OUT;
    }
OUT:
    (void)OsalMemFree(dataBuf);

    (void)OsalMutexUnlock(&mtpDev->mutex);
    HDF_LOGD("%{public}s: BULK-OUT[%{public}d/%{public}d]: %{public}d", __func__, xferSize, fifoLen, ret);
    return ret;
}

int32_t UsbMtpPortWrite(struct UsbMtpPort *mtpPort, struct HdfSBuf *data)
{
    int32_t ret = HDF_SUCCESS;
    void *dataBuf = NULL;
    uint32_t dataBufSize = 0;
    uint32_t xferActual = 0;
    if (mtpPort == NULL || mtpPort->mtpDev == NULL) {
        HDF_LOGE("%{public}s: mtpPort invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    (void)OsalMutexLock(&mtpDev->mutex);
    if (!HdfSbufReadBuffer(data, (const void **)(&dataBuf), &dataBufSize) || dataBuf == NULL) {
        HDF_LOGE("%{public}s: HdfSbufReadBuffer(data) failed", __func__);
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_FAILURE;
    }

    ret = UsbMtpPortBulkInData(mtpPort, (const uint32_t *)dataBuf, dataBufSize, &xferActual);
    if (ret == HDF_DEV_ERR_NODATA) {
        /* all data send, no data left */
        ret = HDF_SUCCESS;
    }

    (void)OsalMutexUnlock(&mtpDev->mutex);
    HDF_LOGD("%{public}s: BULK-IN[%{public}d/%{public}d]: %{public}d", __func__, xferActual, dataBufSize, ret);
    return ret;
}

int32_t UsbMtpPortSendFileAsync(struct UsbMtpPort *mtpPort, struct HdfSBuf *data)
{
    if (data == NULL || mtpPort == NULL || mtpPort->mtpDev == NULL) {
        HDF_LOGE("%{public}s: income parameter is invald", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    struct UsbMtpDriverFileRange *drvMfr = NULL;
    uint32_t drvMfrSize;

    (void)OsalMutexLock(&mtpDev->mutex);
    if (!HdfSbufReadBuffer(data, (const void **)(&drvMfr), &drvMfrSize) || drvMfr == NULL) {
        HDF_LOGE("%{public}s: HdfSbufReadBuffer(info) failed", __func__);
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s: mfr: cmd=%{public}d, transid=%{public}d, len=%{public}lld offset=%{public}lld", __func__,
        drvMfr->command, drvMfr->transactionId, drvMfr->length, drvMfr->offset);

    void *dataBuf = NULL;
    uint32_t dataBufSize = 0;
    if (!HdfSbufReadBuffer(data, (const void **)(&dataBuf), &dataBufSize) || dataBuf == NULL) {
        HDF_LOGE("%{public}s:  HdfSbufReadBuffer(data) failed", __func__);
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_FAILURE;
    }
    mtpDev->xferFileOffset = drvMfr->offset;
    mtpDev->xferFileLength = drvMfr->length;
    mtpDev->xferSendHeader = (drvMfr->command == 0 && drvMfr->transactionId == 0) ? 0 : 1;

    uint32_t xferActual = 0;
    int32_t ret = UsbMtpPortBulkInData(mtpPort, (const uint32_t *)dataBuf, dataBufSize, &xferActual);
    if (ret == HDF_DEV_ERR_NODATA) {
        /* all data send, no data left */
        ret = HDF_SUCCESS;
    }
    (void)OsalMutexUnlock(&mtpDev->mutex);

    HDF_LOGD("%{public}s: BULK-IN[%{public}d/%{public}d]: %{public}d", __func__, xferActual, dataBufSize, ret);
    return ret;
}

int32_t UsbMtpPortReceiveFileAsync(struct UsbMtpPort *mtpPort, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data == NULL || mtpPort == NULL || mtpPort->mtpDev == NULL) {
        HDF_LOGE("%{public}s: income parameter is invald", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    struct UsbMtpDriverFileRange *drvMfr = NULL;
    uint32_t drvMfrSize;
    if (!HdfSbufReadBuffer(data, (const void **)(&drvMfr), &drvMfrSize) || drvMfr == NULL) {
        HDF_LOGE("%{public}s: HdfSbufReadBuffer(info) failed", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s: mfr: cmd=%{public}d, transid=%{public}d, len=%{public}lld offset=%{public}lld", __func__,
        drvMfr->command, drvMfr->transactionId, drvMfr->length, drvMfr->offset);
    uint32_t dataBufSize =
        (DataFifoLen(&mtpPort->readFifo) < drvMfr->length) ? DataFifoLen(&mtpPort->readFifo) : drvMfr->length;
    mtpDev->xferFileOffset = drvMfr->offset;
    mtpDev->xferFileLength = drvMfr->length;
    if (dataBufSize == 0) {
        HDF_LOGE("%{public}s: readfifi no data", __func__);
        return HDF_DEV_ERR_NODATA;
    }
    void *dataBuf = OsalMemCalloc(dataBufSize);
    if (dataBuf == NULL) {
        HDF_LOGE("%{public}s: malloc %{public}d error", __func__, dataBufSize);
        return HDF_ERR_MALLOC_FAIL;
    }

    (void)OsalMutexLock(&mtpDev->mutex);
    uint32_t xferActual = 0;
    int32_t ret = UsbMtpPortBulkOutData(mtpPort, (const uint32_t *)dataBuf, dataBufSize, &xferActual);
    if (ret == HDF_DEV_ERR_NODATA) {
        HDF_LOGE("%{public}s: no data to read, or receive short packet", __func__);
        ret = HDF_SUCCESS;
    }
    if (ret == HDF_SUCCESS && mtpDev->mtpState == MTP_STATE_READY) {
        if (!HdfSbufWriteBuffer(reply, dataBuf, xferActual)) {
            HDF_LOGE("%{public}s: HdfSbufWriteBuffer(data) error", __func__);
            ret = HDF_ERR_IO;
        }
    }
    (void)OsalMemFree(dataBuf);
    (void)OsalMutexUnlock(&mtpDev->mutex);

    HDF_LOGD("%{public}s: BULK-OUT[%{public}d/%{public}d]: %{public}d", __func__, xferActual, dataBufSize, ret);
    return ret;
}

int32_t UsbMtpPortSendEvent(struct UsbMtpPort *mtpPort, struct HdfSBuf *data)
{
    if (data == NULL || mtpPort == NULL || mtpPort->mtpDev == NULL) {
        HDF_LOGE("%{public}s: income parameter is invald", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    void *tmpBuf = NULL;
    uint32_t tmpBufSize = 0;
    if (!mtpDev->isSendEventDone) {
        return HDF_ERR_DEVICE_BUSY;
    }
    (void)OsalMutexLock(&mtpDev->mutex);
    if (!HdfSbufReadBuffer(data, (const void **)(&tmpBuf), &tmpBufSize) || tmpBuf == NULL) {
        HDF_LOGE("%{public}s:  HdfSbufReadBuffer(data) failed", __func__);
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_FAILURE;
    }
    if (tmpBufSize > MTP_EVENT_PACKET_MAX_BYTES) {
        HDF_LOGE("%{public}s: length is invald: %{public}d", __func__, tmpBufSize);
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_FAILURE;
    }
    if (mtpDev->mtpState == MTP_STATE_OFFLINE) {
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    struct UsbFnRequest *req = mtpDev->notifyReq;
    if (req == NULL || req->buf == NULL) {
        HDF_LOGE("%{public}s: notify req is null", __func__);
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGD("%{public}s: ready to send event", __func__);
    if (memcpy_s((void *)req->buf, tmpBufSize, tmpBuf, tmpBufSize) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        (void)UsbFnFreeRequest(req);
        mtpDev->notifyReq = NULL;
        (void)OsalMutexUnlock(&mtpDev->mutex);
        return HDF_FAILURE;
    }
    mtpDev->isSendEventDone = false;
    mtpDev->notifyReq = NULL;
    int32_t ret = UsbFnSubmitRequestAsync(req);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send notify request failed", __func__);
        mtpDev->notifyReq = req;
    }
    (void)OsalMutexUnlock(&mtpDev->mutex);
    return ret;
}

static struct UsbFnRequest *UsbMtpDeviceGetCtrlReq(struct UsbMtpDevice *mtpDev)
{
    struct UsbFnRequest *req = NULL;
    struct DListHead *pool = &mtpDev->ctrlPool;
    if (!DListIsEmpty(pool)) {
        req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        DListRemove(&req->list);
    }
    return req;
}

static int32_t UsbMtpDeviceBind(struct UsbMtpDevice *mtpDev)
{
    (void)mtpDev;
    return HDF_SUCCESS;
}

static int32_t UsbMtpDeviceEnable(struct UsbMtpDevice *mtpDev)
{
    int32_t ret;
    struct UsbMtpPort *mtpPort = mtpDev->mtpPort;
    if (mtpPort == NULL) {
        HDF_LOGE("%{public}s: mtpPort is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&mtpDev->mutex);

    mtpPort->mtpDev = mtpDev;
    ret = UsbMtpAllocReadWriteFifo(&mtpPort->writeFifo, BULK_WRITE_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpAllocReadWriteFifo failed", __func__);
        return ret;
    }
    ret = UsbMtpAllocReadWriteFifo(&mtpPort->readFifo, BULK_READ_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpAllocReadWriteFifo failed", __func__);
        return ret;
    }
    ret = UsbMtpPortStartIo(mtpPort);
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: UsbMtpPortStartIo failed", __func__);
    }
    if (mtpDev->notifyUser && mtpDev->notifyUser->Connect) {
        HDF_LOGD("%{public}s: try notify user connect: enable, ready for usb xfer", __func__);
        mtpDev->notifyUser->Connect(mtpDev);
    }
    mtpDev->isSendEventDone = true;
    mtpDev->mtpState = MTP_STATE_READY;

    (void)OsalMutexUnlock(&mtpDev->mutex);
    return HDF_SUCCESS;
}

static uint32_t UsbMtpDeviceDisable(struct UsbMtpDevice *mtpDev)
{
    struct UsbMtpPort *mtpPort = mtpDev->mtpPort;
    if (mtpPort == NULL) {
        HDF_LOGE("%{public}s: mtpPort is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&mtpDev->mutex);

    UsbMtpDeviceFreeReadWriteFifo(&mtpPort->writeFifo);
    UsbMtpDeviceFreeReadWriteFifo(&mtpPort->readFifo);
    mtpDev->isSendEventDone = false;
    mtpDev->mtpState = MTP_STATE_OFFLINE;

    (void)OsalMutexUnlock(&mtpDev->mutex);
    return HDF_SUCCESS;
}

static int32_t UsbMtpDeviceStandardRequest(
    struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req)
{
    uint16_t wValue = LE16_TO_CPU(setup->value);
    int32_t responseBytes = 0;
    switch (setup->request) {
        case USB_DDK_REQ_GET_DESCRIPTOR:
            /* wValue specified descriptor type(high 8 bit) and index(low 8 bit) when request is GET_DESCRIPTOR */
            if (setup->reqType == (USB_DDK_DIR_IN | USB_DDK_TYPE_STANDARD | USB_DDK_RECIP_DEVICE) &&
                (wValue >> 8) == USB_DDK_DT_STRING && (wValue & 0xFF) == USB_MTP_OS_STRING_ID) {
                /* Handle MTP OS string */
                HDF_LOGI("%{public}s: Standard Request-Get Descriptor(String)", __func__);
                responseBytes = (wValue < sizeof(g_mtpOsString)) ? wValue : sizeof(g_mtpOsString);
                if (memcpy_s((void *)req->buf, responseBytes, g_mtpOsString, responseBytes) != EOK) {
                    HDF_LOGE("%{public}s: memcpy_s failed: Get Descriptor", __func__);
                    return HDF_FAILURE;
                }
            }
            break;
        default:
            HDF_LOGW("%{public}s: Standard Request-unknown: %{public}d", __func__, setup->request);
            break;
    }
    return responseBytes;
}

static int32_t UsbMtpDeviceClassRequest(
    struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req)
{
    int32_t responseBytes = 0;
    if (setup->request == USB_MTP_REQ_CANCEL && setup->index == 0 && setup->value == 0) {
        HDF_LOGI("%{public}s: Class Request-MTP_REQ_CANCEL", __func__);
        (void)OsalMutexLock(&mtpDev->mutex);
        if (mtpDev->mtpState == MTP_STATE_BUSY) {
            mtpDev->mtpState = MTP_STATE_CANCELED;
            (void)UsbMtpPortCancelIo(mtpDev->mtpPort);
        }
        (void)OsalMutexUnlock(&mtpDev->mutex);
    } else if (setup->request == USB_MTP_REQ_GET_DEVICE_STATUS && setup->index == 0 && setup->value == 0) {
        HDF_LOGI("%{public}s: Class Request-MTP_REQ_GET_DEVICE_STATUS", __func__);
        (void)OsalMutexLock(&mtpDev->mutex);
        struct UsbMtpDeviceStatus mtpStatus;
        mtpStatus.wLength = CPU_TO_LE16(sizeof(mtpStatus));
        if (mtpDev->mtpState == MTP_STATE_CANCELED) {
            mtpStatus.wCode = CPU_TO_LE16(MTP_RESPONSE_DEVICE_BUSY);
        } else {
            mtpStatus.wCode = CPU_TO_LE16(MTP_RESPONSE_OK);
        }
        responseBytes = sizeof(mtpStatus);
        if (memcpy_s((void *)req->buf, responseBytes, &mtpStatus, responseBytes) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed: MTP_REQ_GET_DEVICE_STATUS", __func__);
            return HDF_FAILURE;
        }
        (void)OsalMutexUnlock(&mtpDev->mutex);
    } else {
        HDF_LOGW("%{public}s: Class Request-UNKNOWN: %{public}d", __func__, setup->request);
    }
    return responseBytes;
}

static int32_t UsbMtpDeviceVendorRequest(
    struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req)
{
    uint16_t wIndex = LE16_TO_CPU(setup->index);
    uint16_t wLength = LE16_TO_CPU(setup->length);
    int32_t responseBytes = 0;
    HDF_LOGI("%{public}s: Vendor Request", __func__);
    if (setup->request == USB_MTP_BMS_VENDORCODE && (setup->reqType & USB_DDK_DIR_IN) &&
        (wIndex == USB_MTP_EXTENDED_COMPAT_ID || wIndex == USB_MTP_EXTENDED_PROPERTIES)) {
        /* Handle MTP OS descriptor */
        HDF_LOGI("%{public}s: Vendor Request-Get Descriptor(MTP OS)", __func__);
        responseBytes = (wLength < sizeof(g_mtpExtConfigDesc)) ? wLength : sizeof(g_mtpExtConfigDesc);
        if (memcpy_s((void *)req->buf, responseBytes, &g_mtpExtConfigDesc, responseBytes) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed: Get Descriptor(MTP OS)", __func__);
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGW("%{public}s: Vendor Request-UNKNOWN: %{public}d", __func__, setup->request);
    }
    return responseBytes;
}

static int32_t UsbMtpDeviceSetup(struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup)
{
    if (mtpDev == NULL || mtpDev->mtpPort == NULL || setup == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGV(
        "%{public}s: Setup: reqType=0x%{public}X, req=0x%{public}X, idx=%{public}d, val=%{public}d, len=%{public}d",
        __func__, setup->reqType, setup->request, LE16_TO_CPU(setup->index), LE16_TO_CPU(setup->value),
        LE16_TO_CPU(setup->length));

    struct UsbFnRequest *req = UsbMtpDeviceGetCtrlReq(mtpDev);
    if (req == NULL) {
        HDF_LOGE("%{public}s: control req pool is empty", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t responseBytes = 0;
    switch (setup->reqType & USB_DDK_TYPE_MASK) {
        case USB_DDK_TYPE_STANDARD:
            responseBytes = UsbMtpDeviceStandardRequest(mtpDev, setup, req);
            break;
        case USB_DDK_TYPE_CLASS:
            responseBytes = UsbMtpDeviceClassRequest(mtpDev, setup, req);
            break;
        case USB_DDK_TYPE_VENDOR:
            responseBytes = UsbMtpDeviceVendorRequest(mtpDev, setup, req);
            break;
        default:
            HDF_LOGW("%{public}s: Reserved Request: %{public}d", __func__, (setup->reqType & USB_DDK_TYPE_MASK));
            break;
    }

    struct CtrlInfo *ctrlInfo = (struct CtrlInfo *)req->context;
    ctrlInfo->request = setup->request;
    ctrlInfo->mtpDev = mtpDev;
    if (responseBytes >= 0) {
        req->length = responseBytes;
        HDF_LOGD("%{public}s: submit control in req", __func__);
        int32_t ret = UsbFnSubmitRequestAsync(req);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: mtpDev send setup response error", __func__);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

static void UsbMtpDeviceSuspend(struct UsbMtpDevice *mtpDev)
{
    (void)mtpDev;
}

static void UsbMtpDeviceResume(struct UsbMtpDevice *mtpDev)
{
    (void)mtpDev;
}

static void UsbMtpDeviceEp0EventDispatch(struct UsbFnEvent *event)
{
    struct UsbMtpDevice *mtpDev = NULL;
    if (event == NULL || event->context == NULL) {
        HDF_LOGE("%{public}s: event is null", __func__);
        return;
    }
    mtpDev = (struct UsbMtpDevice *)event->context;
    HDF_LOGD("%{public}s EP0 event: [%{public}d], state=%{public}d", __func__, event->type, mtpDev->mtpState);
    switch (event->type) {
        case USBFN_STATE_BIND:
            HDF_LOGI("%{public}s: receive event: [bind]", __func__);
            (void)UsbMtpDeviceBind(mtpDev);
            break;
        case USBFN_STATE_UNBIND:
            HDF_LOGI("%{public}s: receive event: [unbind]", __func__);
            mtpDev->mtpState = MTP_STATE_OFFLINE;
            break;
        case USBFN_STATE_ENABLE:
            HDF_LOGI("%{public}s: receive event: [enable]", __func__);
            (void)UsbMtpDeviceEnable(mtpDev);
            break;
        case USBFN_STATE_DISABLE:
            HDF_LOGI("%{public}s: receive event: [disable]", __func__);
            (void)UsbMtpDeviceDisable(mtpDev);
            break;
        case USBFN_STATE_SETUP:
            HDF_LOGI("%{public}s: receive event: [setup]", __func__);
            if (event->setup != NULL) {
                (void)UsbMtpDeviceSetup(mtpDev, event->setup);
            }
            break;
        case USBFN_STATE_SUSPEND:
            HDF_LOGI("%{public}s: receive event: [suspend]", __func__);
            UsbMtpDeviceSuspend(mtpDev);
            break;
        case USBFN_STATE_RESUME:
            HDF_LOGI("%{public}s: receive event: [resume]", __func__);
            UsbMtpDeviceResume(mtpDev);
            break;
        default:
            HDF_LOGW("%{public}s: receive event: [unknown]", __func__);
            break;
    }
}

static void UsbMtpDeviceConnectCallback(struct UsbMtpDevice *mtpDev)
{
    (void)mtpDev;
}

static void UsbMtpDeviceDisconnectCallback(struct UsbMtpDevice *mtpDev)
{
    (void)mtpDev;
}

static struct MtpNotifyMethod g_mtpNotifyMethod = {
    .Connect = UsbMtpDeviceConnectCallback,
    .Disconnect = UsbMtpDeviceDisconnectCallback,
};

static int32_t UsbMtpDeviceParseEachPipe(struct UsbMtpDevice *mtpDev, struct UsbMtpInterface *iface)
{
    struct UsbFnInterface *fnIface = iface->fn;
    if (fnIface == NULL || fnIface->info.numPipes == 0) {
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: interface detail: idx=%{public}d numPipes=%{public}d ifClass=%{public}d subclass=%{public}d "
             "prtocol=%{public}d cfgIndex=%{public}d ",
        __func__, fnIface->info.index, fnIface->info.numPipes, fnIface->info.interfaceClass, fnIface->info.subclass,
        fnIface->info.protocol, fnIface->info.configIndex);
    for (uint32_t i = 0; i < fnIface->info.numPipes; i++) {
        struct UsbFnPipeInfo pipeInfo;
        (void)memset_s(&pipeInfo, sizeof(pipeInfo), 0, sizeof(pipeInfo));
        int32_t ret = UsbFnGetInterfacePipeInfo(fnIface, i, &pipeInfo);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: get pipe info error", __func__);
            return ret;
        }
        HDF_LOGI("%{public}s: pipe info detail: id=%{public}d type=%{public}d dir=%{public}d"
                 "maxPacketSize=%{public}d interval=%{public}d",
            __func__, pipeInfo.id, pipeInfo.type, pipeInfo.dir, pipeInfo.maxPacketSize, pipeInfo.interval);
        switch (pipeInfo.type) {
            case USB_PIPE_TYPE_INTERRUPT:
                mtpDev->notifyPipe.id = pipeInfo.id;
                mtpDev->notifyPipe.maxPacketSize = pipeInfo.maxPacketSize;
                mtpDev->ctrlIface = *iface; /* MTP device only have one interface, record here */
                mtpDev->intrIface = *iface;
                break;
            case USB_PIPE_TYPE_BULK:
                if (pipeInfo.dir == USB_PIPE_DIRECTION_IN) {
                    mtpDev->dataInPipe.id = pipeInfo.id;
                    mtpDev->dataInPipe.maxPacketSize = pipeInfo.maxPacketSize;
                    mtpDev->dataIface = *iface;
                } else {
                    mtpDev->dataOutPipe.id = pipeInfo.id;
                    mtpDev->dataOutPipe.maxPacketSize = pipeInfo.maxPacketSize;
                }
                break;
            default:
                HDF_LOGE("%{public}s: pipe type %{public}d don't support", __func__, pipeInfo.type);
                break;
        }
    }
    return HDF_SUCCESS;
}

static int32_t UsbMtpDeviceParseMtpIface(struct UsbMtpDevice *mtpDev, struct UsbFnInterface *fnIface)
{
    UsbFnInterfaceHandle handle = UsbFnOpenInterface(fnIface);
    if (handle == NULL) {
        HDF_LOGE("%{public}s: open interface failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpInterface iface;
    iface.fn = fnIface;
    iface.handle = handle;
    int32_t ret = UsbMtpDeviceParseEachPipe(mtpDev, &iface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: parse each pipe failed", __func__);
    }
    return ret;
}

static bool UsbFnInterfaceIsUsbMtpPtpDevice(struct UsbFnInterface *iface)
{
    HDF_LOGI("%{public}s: iIf=%{public}d ifClass=%{public}d, subclass=%{public}d, protocol=%{public}d", __func__,
        iface->info.configIndex, iface->info.interfaceClass, iface->info.subclass, iface->info.protocol);

    if (iface->info.interfaceClass == USB_MTP_DEVICE_CLASS && iface->info.subclass == USB_MTP_DEVICE_SUBCLASS &&
        iface->info.protocol == USB_MTP_DEVICE_PROTOCOL) {
        HDF_LOGD("%{public}s: this is mtp device", __func__);
    }
    if (iface->info.interfaceClass == USB_PTP_DEVICE_CLASS && iface->info.subclass == USB_PTP_DEVICE_SUBCLASS &&
        iface->info.protocol == USB_PTP_DEVICE_PROTOCOL) {
        HDF_LOGD("%{public}s: this is ptp device", __func__);
    }
    return true;
}

static int32_t UsbMtpDeviceParseEachIface(struct UsbMtpDevice *mtpDev, struct UsbFnDevice *fnDev)
{
    int32_t i;
    for (i = 0; i < fnDev->numInterfaces; i++) {
        struct UsbFnInterface *fnIface = (struct UsbFnInterface *)UsbFnGetInterface(fnDev, i);
        if (fnIface == NULL) {
            HDF_LOGE("%{public}s: get interface failed: %{public}d/%{public}d", __func__, i, fnDev->numInterfaces);
            return HDF_ERR_INVALID_PARAM;
        }
        if (UsbFnInterfaceIsUsbMtpPtpDevice(fnIface)) {
            /* MTP/PTP device only have one interface, only parse once */
            (void)UsbMtpDeviceParseMtpIface(mtpDev, fnIface);
            return HDF_SUCCESS;
        }
    }
    return HDF_FAILURE;
}

static int32_t UsbMtpDeviceCreateFuncDevice(struct UsbMtpDevice *mtpDev)
{
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == NULL || iface->GetUint32 == NULL || mtpDev == NULL) {
        HDF_LOGE("%{public}s: iface is invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (iface->GetString(mtpDev->hdfDevice->property, "udc_name", &mtpDev->udcName, UDC_NAME) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read udc_name failed, use default", __func__);
    }
    HDF_LOGI("%{public}s: udcName=%{public}s", __func__, mtpDev->udcName);
    struct UsbFnDevice *fnDev = (struct UsbFnDevice *)UsbFnGetDevice(mtpDev->udcName);
    if (fnDev == NULL) {
        HDF_LOGE("%{public}s: create usb function device failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: getDevice interface count=%{public}d", __func__, fnDev->numInterfaces);
    int32_t ret = UsbMtpDeviceParseEachIface(mtpDev, fnDev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get pipes failed", __func__);
        return ret;
    }
    mtpDev->fnDev = fnDev;
    return HDF_SUCCESS;
}

static int32_t UsbMtpDeviceReleaseFuncDevice(struct UsbMtpDevice *mtpDev)
{
    int32_t retOk = HDF_SUCCESS;
    if (mtpDev->fnDev == NULL) {
        HDF_LOGE("%{public}s: fnDev is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)UsbMtpDeviceFreeCtrlRequests(mtpDev);
    (void)UsbMtpDeviceFreeNotifyRequest(mtpDev);
    int32_t ret = UsbFnCloseInterface(mtpDev->ctrlIface.handle);
    if (ret != HDF_SUCCESS) {
        retOk = ret;
        HDF_LOGW("%{public}s: close usb control interface failed", __func__);
    }
    ret = UsbFnCloseInterface(mtpDev->intrIface.handle);
    if (ret != HDF_SUCCESS) {
        retOk = ret;
        HDF_LOGW("%{public}s: close usb interrupt interface failed", __func__);
    }
    ret = UsbFnCloseInterface(mtpDev->dataIface.handle);
    if (ret != HDF_SUCCESS) {
        retOk = ret;
        HDF_LOGW("%{public}s: close usb data interface failed", __func__);
    }
    ret = UsbFnStopRecvInterfaceEvent(mtpDev->ctrlIface.fn);
    if (ret != HDF_SUCCESS) {
        retOk = ret;
        HDF_LOGW("%{public}s: stop usb ep0 event handle failed", __func__);
    }
    return retOk;
}

static int32_t UsbMtpDeviceAlloc(struct UsbMtpDevice *mtpDev)
{
    HDF_LOGD("%{public}s: allocate memory for struct UsbMtpPort", __func__);
    struct UsbMtpPort *mtpPort = (struct UsbMtpPort *)OsalMemCalloc(sizeof(struct UsbMtpPort));
    if (mtpPort == NULL) {
        HDF_LOGE("%{public}s: Alloc usb mtpDev mtpPort failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (OsalMutexInit(&mtpPort->lock) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init lock fail", __func__);
        (void)OsalMemFree(mtpPort);
        return HDF_FAILURE;
    }
    DListHeadInit(&mtpPort->readPool);
    DListHeadInit(&mtpPort->readQueue);
    DListHeadInit(&mtpPort->writePool);
    mtpDev->mtpPort = mtpPort;
    mtpPort->mtpDev = mtpDev;
    return HDF_SUCCESS;
}

static int32_t UsbMtpDeviceAllocNotifyRequest(struct UsbMtpDevice *mtpDev)
{
    mtpDev->notifyReq = UsbFnAllocRequest(mtpDev->intrIface.handle, mtpDev->notifyPipe.id, MTP_EVENT_PACKET_MAX_BYTES);
    if (mtpDev->notifyReq == NULL) {
        HDF_LOGE("%{public}s: allocate notify request failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    mtpDev->notifyReq->complete = UsbFnRequestNotifyComplete;
    mtpDev->notifyReq->context = mtpDev;
    mtpDev->isSendEventDone = true;
    return HDF_SUCCESS;
}

static void UsbMtpDeviceFreeNotifyRequest(struct UsbMtpDevice *mtpDev)
{
    int32_t ret = UsbFnFreeRequest(mtpDev->notifyReq);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: free notify request failed", __func__);
        return;
    }
    mtpDev->notifyReq = NULL;
}

static int32_t UsbMtpDeviceFree(struct UsbMtpDevice *mtpDev)
{
    if (mtpDev->mtpPort == NULL) {
        HDF_LOGE("%{public}s: mtpPort is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexDestroy(&(mtpDev->mtpPort->lock));
    HDF_LOGD("%{public}s: release memory for struct UsbMtpPort", __func__);
    (void)OsalMemFree(mtpDev->mtpPort);
    return HDF_SUCCESS;
}

static int32_t UsbMtpDeviceInit(struct UsbMtpDevice *mtpDev)
{
    int32_t ret;
    if (mtpDev == NULL || mtpDev->initFlag) {
        HDF_LOGE("%{public}s: UsbMtpDeviceInit: usb mtpDev is null", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: already init=%{public}s", __func__, mtpDev->initFlag ? "true" : "false");
    ret = UsbMtpDeviceCreateFuncDevice(mtpDev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceCreateFuncDevice failed", __func__);
        return ret;
    }
    ret = UsbMtpDeviceAlloc(mtpDev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceAlloc failed", __func__);
        goto ERR;
    }
    ret = UsbMtpDeviceAllocCtrlRequests(mtpDev, MTP_CTRL_REQUEST_NUM);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceAllocCtrlRequests failed: %{public}d", __func__, MTP_CTRL_REQUEST_NUM);
        goto ERR;
    }
    ret = UsbMtpDeviceAllocNotifyRequest(mtpDev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceAllocNotifyRequest failed", __func__);
        goto ERR;
    }
    ret = UsbFnStartRecvInterfaceEvent(mtpDev->ctrlIface.fn, 0xff, UsbMtpDeviceEp0EventDispatch, mtpDev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: register event callback failed", __func__);
        goto ERR;
    }
    mtpDev->notifyUser = &g_mtpNotifyMethod;
    mtpDev->initFlag = true;
    return HDF_SUCCESS;
ERR:
    (void)UsbMtpDeviceFree(mtpDev);
    (void)UsbMtpDeviceReleaseFuncDevice(mtpDev);
    return ret;
}

static int32_t UsbMtpDeviceRelease(struct UsbMtpDevice *mtpDev)
{
    if (mtpDev == NULL || mtpDev->initFlag == false) {
        HDF_LOGE("%{public}s: UsbMtpDeviceRelease: usb mtpDev is null", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s: release usb mtpDev device", __func__);
    (void)UsbMtpDeviceReleaseFuncDevice(mtpDev);
    HDF_LOGD("%{public}s: release usb mtpDev memory", __func__);
    (void)UsbMtpDeviceFree(mtpDev);
    mtpDev->initFlag = false;
    return HDF_SUCCESS;
}

static int32_t MtpDeviceServiceDispatch(
    struct HdfDeviceIoClient *client, int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGI("%{public}s: recv dispatch cmd: [%{public}d]", __func__, cmd);
    if (client == NULL || client->device == NULL || client->device->service == NULL) {
        HDF_LOGE("%{public}s: client is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = (struct UsbMtpDevice *)client->device->service;
    int32_t ret = HDF_SUCCESS;
    if (HdfDeviceObjectCheckInterfaceDesc(client->device, data) == false) {
        HDF_LOGE("%{public}s: check interface desc fail", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    switch (cmd) {
        case USB_MTP_INIT:
            ret = UsbMtpDeviceInit(mtpDev);
            break;
        case USB_MTP_RELEASE:
            ret = UsbMtpDeviceRelease(mtpDev);
            break;
        case USB_MTP_OPEN:
            ret = UsbMtpPortOpen(mtpDev->mtpPort);
            break;
        case USB_MTP_CLOSE:
            ret = UsbMtpPortClose(mtpDev->mtpPort);
            break;
        case USB_MTP_READ:
            ret = UsbMtpPortRead(mtpDev->mtpPort, reply);
            break;
        case USB_MTP_WRITE:
            ret = UsbMtpPortWrite(mtpDev->mtpPort, data);
            break;
        case USB_MTP_RECEIVE_FILE:
            ret = UsbMtpPortReceiveFileAsync(mtpDev->mtpPort, data, reply);
            break;
        case USB_MTP_SEND_FILE:
            ret = UsbMtpPortSendFileAsync(mtpDev->mtpPort, data);
            break;
        case USB_MTP_SEND_FILE_WITH_HEADER:
            ret = UsbMtpPortSendFileWithHeaderAsync(mtpDev->mtpPort, data);
            break;
        case USB_MTP_SEND_EVENT:
            ret = UsbMtpPortSendEvent(mtpDev->mtpPort, data);
            break;
        default:
            HDF_LOGE("%{public}s: unknown cmd [%{public}d]", __func__, cmd);
            ret = HDF_ERR_NOT_SUPPORT;
            break;
    }
    return ret;
}

static int32_t MtpDriverBind(struct HdfDeviceObject *device)
{
    struct UsbMtpDevice *mtpDev = NULL;
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    HDF_LOGD("%{public}s: allocate memory for struct UsbMtpDevice", __func__);
    mtpDev = (struct UsbMtpDevice *)OsalMemCalloc(sizeof(*mtpDev));
    if (mtpDev == NULL) {
        HDF_LOGE("%{public}s: Alloc usb mtpDev device failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (HdfDeviceObjectSetInterfaceDesc(device, "hdf.usb.usbfn") != HDF_SUCCESS) {
        HDF_LOGE(" Set Desc fail");
        (void)OsalMemFree(mtpDev);
        return HDF_FAILURE;
    }
    mtpDev->hdfDevice = device;
    device->service = &(mtpDev->ioService);
    device->service->Dispatch = MtpDeviceServiceDispatch;
    return HDF_SUCCESS;
}

static int32_t MtpDriverInit(struct HdfDeviceObject *device)
{
    if (device == NULL || device->service == NULL) {
        HDF_LOGE("%{public}s: device or service is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = (struct UsbMtpDevice *)device->service;
    if (OsalMutexInit(&mtpDev->mutex) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init mutex fail", __func__);
        (void)OsalMemFree(mtpDev);
        return HDF_FAILURE;
    }
    mtpDev->initFlag = false;
    mtpDev->mtpState = MTP_STATE_OFFLINE;
    return HDF_SUCCESS;
}

static void MtpDriverRelease(struct HdfDeviceObject *device)
{
    if (device == NULL || device->service == NULL) {
        HDF_LOGE("%{public}s: device or service is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpDevice *mtpDev = (struct UsbMtpDevice *)device->service;
    (void)OsalMutexDestroy(&mtpDev->mutex);
    HDF_LOGD("%{public}s: release memory for struct UsbMtpDevice", __func__);
    (void)OsalMemFree(mtpDev);
}

struct HdfDriverEntry g_mtpDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "usbfn_mtp",
    .Bind = MtpDriverBind,
    .Init = MtpDriverInit,
    .Release = MtpDriverRelease,
};

HDF_INIT(g_mtpDriverEntry);
