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
#define USB_MTP_OS_STRING_ID 0xEE

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
    if (mtpPort == NULL) {
        return HDF_FAILURE;
    }
    struct DListHead *pool = &mtpPort->writePool;
    int32_t ret = HDF_SUCCESS;
    struct UsbFnRequest *req = NULL;
    uint32_t len;
    if (mtpPort->mtpDev == NULL) {
        return HDF_FAILURE;
    }
    while (!mtpPort->writeBusy && !DListIsEmpty(pool)) {
        if (mtpPort->writeStarted >= mtpPort->writeAllocated) {
            HDF_LOGE("%{public}s: no idle write req(BULK-IN)", __func__);
            return HDF_FAILURE;
        }
        req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        /* if mtpDev is disconnect, abort immediately */
        if (mtpPort->mtpDev->mtpState == MTP_STATE_OFFLINE) {
            return HDF_FAILURE;
        }
        len = DataFifoRead(&mtpPort->writeFifo, req->buf, mtpPort->mtpDev->dataInPipe.maxPacketSize);
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
    int32_t ret;
    struct UsbFnRequest *req = NULL;
    struct DListHead *pool = &mtpPort->readPool;
    struct UsbMtpPipe *out = &mtpPort->mtpDev->dataOutPipe;
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    while (!DListIsEmpty(pool)) {
        if (mtpPort->readStarted >= mtpPort->readAllocated) {
            HDF_LOGE("%{public}s no idle read req(BULK-OUT)", __func__);
            break;
        }
        req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        DListRemove(&req->list);
        req->length = out->maxPacketSize;
        ret = UsbFnSubmitRequestAsync(req);
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
    struct UsbFnRequest *req = NULL;
    uint8_t pipe = (isRead == 1 ? mtpDev->dataOutPipe.id : mtpDev->dataInPipe.id);
    uint32_t len = (isRead == 1 ? mtpDev->dataOutPipe.maxPacketSize : mtpDev->dataInPipe.maxPacketSize);
    int32_t i;
    for (i = 0; i < num; i++) {
        req = UsbFnAllocRequest(mtpDev->dataIface.handle, pipe, len);
        if (!req) {
            return DListIsEmpty(head) ? HDF_FAILURE : HDF_SUCCESS;
        }
        req->complete = (isRead == 1 ? UsbFnRequestReadComplete : UsbFnRequestWriteComplete);
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

static int32_t MtpDeviceServiceDispatch(
    struct HdfDeviceIoClient *client, int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGI("%{public}s: recv dispatch cmd: [%{public}d]", __func__, cmd);
    struct UsbMtpDevice *mtpDev = NULL;
    int32_t ret = HDF_SUCCESS;
    if (client == NULL || client->device == NULL || client->device->service == NULL) {
        HDF_LOGE("%{public}s: client is NULL", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    mtpDev = (struct UsbMtpDevice *)client->device->service;
    if (mtpDev == NULL) {
        HDF_LOGE("%{public}s: mtpDev is NULL", __func__);
        return HDF_ERR_IO;
    }
    if (HdfDeviceObjectCheckInterfaceDesc(client->device, data) == false) {
        HDF_LOGE("%{public}s: check interface desc fail", __func__);
        return HDF_ERR_INVALID_PARAM;
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
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s: mtpDev(%{public}p)", __func__, mtpDev);
    if (HdfDeviceObjectSetInterfaceDesc(device, "hdf.usb.usbfn") != HDF_SUCCESS) {
        HDF_LOGE(" Set Desc fail!");
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
    struct UsbMtpDevice *mtpDev = NULL;
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is NULL", __func__);
        return HDF_FAILURE;
    }
    mtpDev = (struct UsbMtpDevice *)device->service;
    if (mtpDev == NULL) {
        HDF_LOGE("%{public}s: MtpDriverInit: usb mtpDev is null", __func__);
        return HDF_FAILURE;
    }
    if (OsalMutexInit(&mtpDev->mutex) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init mutex fail!", __func__);
        (void)OsalMemFree(mtpDev);
        return HDF_FAILURE;
    }
    mtpDev->initFlag = false;
    mtpDev->mtpState = MTP_STATE_OFFLINE;
    return HDF_SUCCESS;
}

static void MtpDriverRelease(struct HdfDeviceObject *device)
{
    struct UsbMtpDevice *mtpDev = NULL;
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is NULL", __func__);
        return;
    }
    mtpDev = (struct UsbMtpDevice *)device->service;
    if (mtpDev == NULL) {
        HDF_LOGE("%{public}s: MtpDriverRelease: usb mtpDev is null", __func__);
        return;
    }
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
