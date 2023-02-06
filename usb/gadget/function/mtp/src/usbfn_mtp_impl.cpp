/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "usbfn_mtp_impl.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "default_config.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "hdf_log.h"

#define HDF_LOG_TAG usbfn_mtp_impl

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
        /* set to 0x04 for extended compat ID descriptors */
        .wIndex = CPU_TO_LE16(4),
        /* Number of function sections */
        .bCount = CPU_TO_LE16(1),
        .reserved = {0},
    },
    .function = {
        .bFirstInterfaceNumber = 0,
        .bInterfaceCount = 1,
        /* Media Transfer Protocol */
        .compatibleID = {'M', 'T', 'P'},
        .subCompatibleID = {0},
        .reserved = {0},
    },
};

struct UsbMtpDeviceStatus {
    uint16_t wLength;
    uint16_t wCode;
};

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Gadget {
namespace Mtp {
namespace V1_0 {
extern "C" IUsbfnMtpInterface *UsbfnMtpInterfaceImplGetInstance(void)
{
    return new (std::nothrow) UsbfnMtpImpl();
}

struct UsbMtpDevice *UsbfnMtpImpl::mtpDev_ = nullptr;
struct UsbMtpPort *UsbfnMtpImpl::mtpPort_ = nullptr;
std::mutex UsbfnMtpImpl::mtpRunning_;
sem_t UsbfnMtpImpl::bulkOutAsyncReq_ {0};
sem_t UsbfnMtpImpl::bulkInAsyncReq_ {0};

constexpr uint32_t BULK_IN_TIMEOUT_MS = 1000;  /* sync timeout */
constexpr uint32_t BULK_OUT_TIMEOUT_MS = 1000; /* sync timeout */
constexpr uint32_t INTR_IN_TIMEOUT_MS = 1000;  /* sync timeout */

enum UsbMtpSendZeroLengthPacket {
    ZLP_NO_NEED = 0, /* no need send ZLP */
    ZLP_NEED_SEND,   /* need send ZLP */
    ZLP_TRY_SEND,    /* try send ZLP */
    ZLP_SEND_DONE,   /* send ZLP done */
};

enum UsbMtpAsyncXferState {
    ASYNC_XFER_FILE_NORMAL = 0,
    ASYNC_XFER_FILE_DONE,
};

UsbfnMtpImpl::UsbfnMtpImpl() : deviceObject_(nullptr) {}

void UsbfnMtpImpl::UsbFnRequestReadComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    if (req == nullptr || req->context == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return;
    }
    struct UsbMtpPort *mtpPort = static_cast<struct UsbMtpPort *>(req->context);

    DListInsertTail(&req->list, &mtpPort->readQueue);
    mtpPort->readStarted--;
    int32_t ret = UsbMtpPortRxPush(mtpPort);
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: rx push failed: %{public}d", __func__, ret);
    }
}

void UsbfnMtpImpl::UsbFnRequestWriteComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    if (req == nullptr || req->context == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return;
    }
    struct UsbMtpPort *mtpPort = static_cast<struct UsbMtpPort *>(req->context);

    while (!DListIsEmpty(&mtpPort->writeQueue)) {
        struct UsbFnRequest *reqTemp = DLIST_FIRST_ENTRY(&mtpPort->writeQueue, struct UsbFnRequest, list);
        DListRemove(&reqTemp->list);
    }

    DListInsertTail(&req->list, &mtpPort->writePool);
    mtpPort->writeStarted--;
    switch (req->status) {
        case USB_REQUEST_COMPLETED:
            mtpPort->mtpDev->asyncSendFileActual += req->actual;
            (void)UsbMtpPortStartTxAsync(mtpPort, true);
            break;
        case USB_REQUEST_NO_DEVICE:
            HDF_LOGV("%{public}s: tx req return disconnected", __func__);
            mtpPort->mtpDev->mtpState = MTP_STATE_OFFLINE;
            break;
        default:
            HDF_LOGV("%{public}s: unexpected status %{public}d", __func__, req->status);
            mtpPort->mtpDev->mtpState = MTP_STATE_ERROR;
            break;
    }
}

void UsbfnMtpImpl::UsbFnRequestNotifyComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    if (req == nullptr || req->context == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return;
    }
}

void UsbfnMtpImpl::UsbFnRequestCtrlComplete(uint8_t pipe, struct UsbFnRequest *req)
{
    (void)pipe;
    if (req == nullptr || req->context == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return;
    }
    struct CtrlInfo *ctrlInfo = static_cast<struct CtrlInfo *>(req->context);
    struct UsbMtpDevice *mtpDev = ctrlInfo->mtpDev;

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
    DListInsertTail(&req->list, &mtpDev->ctrlPool);
}

int32_t UsbfnMtpImpl::UsbMtpPortProcessLastTxPacket(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req)
{
    int32_t ret = HDF_SUCCESS;
    if (req->length == 0 && mtpPort->mtpDev->sendZLP == ZLP_NEED_SEND) {
        mtpPort->mtpDev->sendZLP = ZLP_TRY_SEND;
        req->length = 0;
        int32_t ret = UsbFnSubmitRequestSync(req, BULK_IN_TIMEOUT_MS);
        mtpPort->mtpDev->sendZLP = ZLP_SEND_DONE;
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: submit bulk-in zlp req error: %{public}d", __func__, ret);
        }
        HDF_LOGI("%{public}s: send ZLP done", __func__);
        sem_post(&bulkInAsyncReq_);
    }
    return ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortCheckTxReq(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req)
{
    if (mtpPort->mtpDev->mtpState == MTP_STATE_OFFLINE) {
        HDF_LOGE("%{public}s: device disconnect, stop tx", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (mtpPort->mtpDev->mtpState == MTP_STATE_ERROR) {
        HDF_LOGE("%{public}s: tx failed", __func__);
        return HDF_ERR_IO;
    }
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpPortSubmitAsyncTxReq(
    struct UsbMtpPort *mtpPort, struct UsbFnRequest *req, uint8_t *fileContent)
{
    if (req->length != 0 && memcpy_s(req->buf, req->length, fileContent, req->length) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        DListInsertTail(&req->list, &mtpPort->writePool);
        return HDF_FAILURE;
    }
    DListRemove(&req->list);
    DListInsertTail(&req->list, &mtpPort->writeQueue);
    int32_t ret = UsbFnSubmitRequestAsync(req);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: submit bulk-in req error: %{public}d", __func__, ret);
        DListInsertTail(&req->list, &mtpPort->writePool);
        struct UsbFnRequest *reqTemp = nullptr;
        struct UsbFnRequest *reqPos = nullptr;
        DLIST_FOR_EACH_ENTRY_SAFE(reqPos, reqTemp, &mtpPort->writeQueue, struct UsbFnRequest, list) {
            if (reqTemp == req) {
                DListRemove(&reqTemp->list);
            }
        }
        return ret;
    }
    mtpPort->writeStarted++;
    return ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortStartTxAsync(struct UsbMtpPort *mtpPort, bool callByComplete)
{
    if (mtpPort == nullptr || mtpPort->mtpDev == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);
    if (mtpPort->mtpDev->asyncSendFileActual == mtpPort->mtpDev->xferFileLength && callByComplete) {
        HDF_LOGI(
            "%{public}s: send done: %{public}d/%{public}d", __func__, mtpPort->writeStarted, mtpPort->writeAllocated);
        mtpPort->mtpDev->asyncXferFile = ASYNC_XFER_FILE_DONE;
        return HDF_SUCCESS;
    }
    struct DListHead *pool = &mtpPort->writePool;
    while (!DListIsEmpty(pool)) {
        uint32_t needXfer = mtpPort->mtpDev->xferFileLength - mtpPort->mtpDev->asyncSendFileExpect;
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        int32_t ret = UsbMtpPortCheckTxReq(mtpPort, req);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: tx req error: %{public}d", __func__, ret);
            return ret;
        }
        req->length =
            needXfer < mtpPort->mtpDev->dataInPipe.maxPacketSize ? needXfer : mtpPort->mtpDev->dataInPipe.maxPacketSize;
        if (mtpPort->mtpDev->asyncSendFileExpect == mtpPort->mtpDev->xferFileLength) {
            return UsbMtpPortProcessLastTxPacket(mtpPort, req);
        }
        ret = UsbMtpPortSubmitAsyncTxReq(
            mtpPort, req, mtpPort->mtpDev->asyncSendFileContent + mtpPort->mtpDev->asyncSendFileExpect);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: submit bulk-in req error: %{public}d", __func__, ret);
            return ret;
        }
        if (req->length < mtpPort->mtpDev->dataInPipe.maxPacketSize) {
            HDF_LOGI("%{public}s: last async req", __func__);
            sem_post(&bulkInAsyncReq_);
        }
        mtpPort->mtpDev->asyncSendFileExpect += req->length;
    }
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceAllocCtrlRequests(struct UsbMtpDevice *mtpDev, int32_t num)
{
    struct DListHead *head = &mtpDev->ctrlPool;
    DListHeadInit(head);
    mtpDev->ctrlReqNum = 0;
    for (int32_t i = 0; i < num; ++i) {
        struct CtrlInfo *ctrlInfo = static_cast<struct CtrlInfo *>(OsalMemCalloc(sizeof(struct CtrlInfo)));
        if (ctrlInfo == nullptr) {
            HDF_LOGE("%{public}s: Allocate ctrlInfo failed", __func__);
            return DListIsEmpty(head) ? HDF_FAILURE : HDF_SUCCESS;
        }
        ctrlInfo->mtpDev = mtpDev;
        struct UsbFnRequest *req = UsbFnAllocCtrlRequest(mtpDev->ctrlIface.handle, MTP_CONTROL_XFER_BYTECOUNT);
        if (req == nullptr) {
            HDF_LOGE("%{public}s: Allocate ctrl req failed", __func__);
            (void)OsalMemFree(ctrlInfo);
            return DListIsEmpty(head) ? HDF_FAILURE : HDF_SUCCESS;
        }
        req->complete = UsbFnRequestCtrlComplete;
        req->context = ctrlInfo;
        DListInsertTail(&req->list, head);
        mtpDev->ctrlReqNum++;
    }
    return HDF_SUCCESS;
}

void UsbfnMtpImpl::UsbMtpDeviceFreeCtrlRequests(struct UsbMtpDevice *mtpDev)
{
    struct DListHead *head = &mtpDev->ctrlPool;
    while (!DListIsEmpty(head)) {
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(head, struct UsbFnRequest, list);
        DListRemove(&req->list);
        (void)OsalMemFree(req->context);
        (void)UsbFnFreeRequest(req);
        mtpDev->ctrlReqNum--;
    }
}

void UsbfnMtpImpl::UsbMtpPortFreeRequests(struct DListHead *head, int32_t &allocated)
{
    while (!DListIsEmpty(head)) {
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(head, struct UsbFnRequest, list);
        DListRemove(&req->list);
        (void)UsbFnFreeRequest(req);
        allocated--;
    }
}

int32_t UsbfnMtpImpl::UsbMtpPortAllocReadWriteRequests(struct UsbMtpPort *mtpPort, int32_t readSize, int32_t writeSize)
{
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    struct UsbFnRequest *req = nullptr;
    int32_t i = 0;
    for (i = 0; i < readSize; ++i) {
        req = UsbFnAllocRequest(mtpDev->dataIface.handle, mtpDev->dataOutPipe.id, mtpDev->dataOutPipe.maxPacketSize);
        if (req == nullptr) {
            if (DListIsEmpty(&mtpPort->readPool)) {
                HDF_LOGE("%{public}s: alloc read req failed", __func__);
                return HDF_ERR_MALLOC_FAIL;
            }
            break;
        }
        req->complete = UsbFnRequestReadComplete;
        req->context = mtpPort;
        DListInsertTail(&req->list, &mtpPort->readPool);
        mtpPort->readAllocated++;
    }

    for (i = 0; i < writeSize; ++i) {
        req = UsbFnAllocRequest(mtpDev->dataIface.handle, mtpDev->dataInPipe.id, mtpDev->dataInPipe.maxPacketSize);
        if (req == nullptr) {
            HDF_LOGE("%{public}s: alloc write req failed", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }
        req->complete = UsbFnRequestWriteComplete;
        req->context = mtpPort;
        DListInsertTail(&req->list, &mtpPort->writePool);
        mtpPort->writeAllocated++;
    }
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpPortStartIo(struct UsbMtpPort *mtpPort)
{
    int32_t ret = HDF_SUCCESS;
    if (mtpPort->readAllocated == 0 || mtpPort->writeAllocated == 0) {
        HDF_LOGI("%{public}s: rx_req=%{public}d tx_req=%{public}d, alloc req", __func__, mtpPort->readAllocated,
            mtpPort->writeAllocated);
        ret = UsbMtpPortAllocReadWriteRequests(mtpPort, READ_QUEUE_SIZE, WRITE_QUEUE_SIZE);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: allocate requests for read/write failed: %{public}d", __func__, ret);
            UsbMtpPortFreeRequests(&mtpPort->readPool, mtpPort->readAllocated);
            UsbMtpPortFreeRequests(&mtpPort->writePool, mtpPort->writeAllocated);
            return HDF_ERR_MALLOC_FAIL;
        }
    }
    return ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortCancelAndFreeReq(
    struct DListHead *queueHead, struct DListHead *poolHead, int32_t &allocated)
{
    while (!DListIsEmpty(queueHead)) {
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(queueHead, struct UsbFnRequest, list);
        DListRemove(&req->list);
        DListInsertTail(&req->list, poolHead);
    }
    while (!DListIsEmpty(poolHead)) {
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(poolHead, struct UsbFnRequest, list);
        DListRemove(&req->list);
        (void)UsbFnCancelRequest(req);
        (void)UsbFnFreeRequest(req);
        allocated--;
    }
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpPortCancelIo(struct UsbMtpPort *mtpPort)
{
    HDF_LOGI("%{public}s: cancel and free read req: %{public}d/%{public}d", __func__, mtpPort->readStarted,
        mtpPort->readAllocated);
    (void)UsbMtpPortCancelAndFreeReq(&mtpPort->readQueue, &mtpPort->readPool, mtpPort->readAllocated);
    HDF_LOGI("%{public}s: cancel and free write req: %{public}d/%{public}d", __func__, mtpPort->writeStarted,
        mtpPort->writeAllocated);
    (void)UsbMtpPortCancelAndFreeReq(&mtpPort->writeQueue, &mtpPort->writePool, mtpPort->writeAllocated);
    return HDF_SUCCESS;
}

struct UsbFnRequest *UsbfnMtpImpl::UsbMtpDeviceGetCtrlReq(struct UsbMtpDevice *mtpDev)
{
    struct DListHead *pool = &mtpDev->ctrlPool;
    if (DListIsEmpty(pool)) {
        return nullptr;
    }
    struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
    DListRemove(&req->list);
    return req;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceStandardRequest(
    struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req)
{
    uint16_t wValue = LE16_TO_CPU(setup->value);
    int32_t responseBytes = 0;
    uint8_t mtpOsStringReqType = (USB_DDK_DIR_IN | USB_DDK_TYPE_STANDARD | USB_DDK_RECIP_DEVICE);
    /* wValue specified descriptor type(high 8 bit) and index(low 8 bit) when request is GET_DESCRIPTOR */
    uint16_t mtpOsStringWValue = (USB_DDK_DT_STRING << 8 | USB_MTP_OS_STRING_ID);
    if (setup->request == USB_DDK_REQ_GET_DESCRIPTOR && setup->reqType == mtpOsStringReqType &&
        wValue == mtpOsStringWValue) {
        /* Handle MTP OS string */
        HDF_LOGI("%{public}s: Standard Request-Get Descriptor(String)", __func__);
        responseBytes = (wValue < sizeof(g_mtpOsString)) ? wValue : sizeof(g_mtpOsString);
        if (memcpy_s((void *)req->buf, responseBytes, g_mtpOsString, responseBytes) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed: Get Descriptor", __func__);
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGW("%{public}s: Standard Request-unknown: %{public}d", __func__, setup->request);
    }
    return responseBytes;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceClassRequest(
    struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req)
{
    int32_t responseBytes = 0;
    if (setup->request == USB_MTP_REQ_CANCEL && setup->index == 0 && setup->value == 0) {
        HDF_LOGI("%{public}s: Class Request-MTP_REQ_CANCEL", __func__);
        if (mtpDev->mtpState == MTP_STATE_BUSY) {
            mtpDev->mtpState = MTP_STATE_CANCELED;
            (void)UsbMtpPortCancelIo(mtpDev->mtpPort);
        }
    } else if (setup->request == USB_MTP_REQ_GET_DEVICE_STATUS && setup->index == 0 && setup->value == 0) {
        HDF_LOGI("%{public}s: Class Request-MTP_REQ_GET_DEVICE_STATUS", __func__);
        struct UsbMtpDeviceStatus mtpStatus;
        mtpStatus.wLength = CPU_TO_LE16(sizeof(mtpStatus));
        if (mtpDev->mtpState == MTP_STATE_CANCELED) {
            mtpStatus.wCode = CPU_TO_LE16(MTP_RESPONSE_DEVICE_BUSY);
        } else {
            mtpStatus.wCode = CPU_TO_LE16(MTP_RESPONSE_OK);
        }
        responseBytes = static_cast<int32_t>(sizeof(mtpStatus));
        if (memcpy_s((void *)req->buf, responseBytes, &mtpStatus, responseBytes) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed: MTP_REQ_GET_DEVICE_STATUS", __func__);
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGW("%{public}s: Class Request-UNKNOWN: %{public}d", __func__, setup->request);
    }
    return responseBytes;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceVendorRequest(
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

int32_t UsbfnMtpImpl::UsbMtpDeviceSetup(struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup)
{
    if (mtpDev == nullptr || mtpDev->mtpPort == nullptr || setup == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGV(
        "%{public}s: Setup: reqType=0x%{public}X, req=0x%{public}X, idx=%{public}d, val=%{public}d, len=%{public}d",
        __func__, setup->reqType, setup->request, LE16_TO_CPU(setup->index), LE16_TO_CPU(setup->value),
        LE16_TO_CPU(setup->length));

    struct UsbFnRequest *req = UsbMtpDeviceGetCtrlReq(mtpDev);
    if (req == nullptr) {
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

    struct CtrlInfo *ctrlInfo = static_cast<struct CtrlInfo *>(req->context);
    ctrlInfo->request = setup->request;
    ctrlInfo->mtpDev = mtpDev;
    if (responseBytes >= 0) {
        req->length = responseBytes;
        int32_t ret = UsbFnSubmitRequestAsync(req);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: mtpDev send setup response error", __func__);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

void UsbfnMtpImpl::UsbMtpDeviceSuspend(struct UsbMtpDevice *mtpDev)
{
    struct UsbMtpPort *mtpPort = mtpDev->mtpPort;
    if (mtpPort == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return;
    }

    mtpPort->suspended = true;
    (void)UsbMtpPortCancelIo(mtpPort);
}

void UsbfnMtpImpl::UsbMtpDeviceResume(struct UsbMtpDevice *mtpDev)
{
    struct UsbMtpPort *mtpPort = mtpDev->mtpPort;
    if (mtpPort == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return;
    }
    mtpPort->suspended = false;
    if (!mtpPort->startDelayed) {
        return;
    }
    mtpPort->startDelayed = false;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceEnable(struct UsbMtpDevice *mtpDev)
{
    struct UsbMtpPort *mtpPort = mtpDev->mtpPort;
    if (mtpPort == nullptr || mtpDev == nullptr || mtpDev->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }

    /* the mtpDev is enabled, start the io stream */
    mtpDev->mtpState = MTP_STATE_READY;
    mtpPort->startDelayed = true;
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceDisable(struct UsbMtpDevice *mtpDev)
{
    struct UsbMtpPort *mtpPort = mtpDev->mtpPort;
    if (mtpPort == nullptr || mtpDev == nullptr || mtpDev->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }

    /* The udc has been disabled due to some problem */
    mtpPort->startDelayed = false;
    mtpDev->mtpState = MTP_STATE_OFFLINE;
    return HDF_SUCCESS;
}

void UsbfnMtpImpl::UsbMtpDeviceEp0EventDispatch(struct UsbFnEvent *event)
{
    if (event == nullptr || event->context == nullptr) {
        HDF_LOGE("%{public}s: invalid param event", __func__);
        return;
    }

    struct UsbMtpDevice *mtpDev = static_cast<struct UsbMtpDevice *>(event->context);
    HDF_LOGI("%{public}s EP0 event: [%{public}d], state=%{public}d", __func__, event->type, mtpDev->mtpState);
    switch (event->type) {
        case USBFN_STATE_BIND:
            HDF_LOGI("%{public}s: EP0 [bind] ignore", __func__);
            break;
        case USBFN_STATE_UNBIND:
            HDF_LOGI("%{public}s: EP0 [unbind] ignore", __func__);
            break;
        case USBFN_STATE_ENABLE:
            HDF_LOGI("%{public}s: EP0 [enable]", __func__);
            (void)UsbMtpDeviceEnable(mtpDev);
            break;
        case USBFN_STATE_DISABLE:
            HDF_LOGI("%{public}s: EP0 [disable]", __func__);
            (void)UsbMtpDeviceDisable(mtpDev);
            break;
        case USBFN_STATE_SETUP:
            HDF_LOGI("%{public}s: EP0 [setup]", __func__);
            if (event->setup != nullptr) {
                (void)UsbMtpDeviceSetup(mtpDev, event->setup);
            }
            break;
        case USBFN_STATE_SUSPEND:
            HDF_LOGI("%{public}s: EP0 [suspend]", __func__);
            UsbMtpDeviceSuspend(mtpDev);
            break;
        case USBFN_STATE_RESUME:
            HDF_LOGI("%{public}s: EP0 [resume]", __func__);
            UsbMtpDeviceResume(mtpDev);
            break;
        default:
            HDF_LOGI("%{public}s: EP0 ignore or unknown: %{public}d", __func__, event->type);
            break;
    }
}

int32_t UsbfnMtpImpl::UsbMtpDeviceParseEachPipe(struct UsbMtpDevice *mtpDev, struct UsbMtpInterface &iface)
{
    struct UsbFnInterface *fnIface = iface.fn;
    if (fnIface == nullptr || fnIface->info.numPipes == 0) {
        HDF_LOGE("%{public}s: ifce is invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: interface: idx=%{public}d numPipes=%{public}d ifClass=%{public}d subclass=%{public}d "
             "prtocol=%{public}d cfgIndex=%{public}d ",
        __func__, fnIface->info.index, fnIface->info.numPipes, fnIface->info.interfaceClass, fnIface->info.subclass,
        fnIface->info.protocol, fnIface->info.configIndex);
    for (uint32_t i = 0; i < fnIface->info.numPipes; ++i) {
        struct UsbFnPipeInfo pipeInfo;
        (void)memset_s(&pipeInfo, sizeof(pipeInfo), 0, sizeof(pipeInfo));
        int32_t ret = UsbFnGetInterfacePipeInfo(fnIface, i, &pipeInfo);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: get pipe info error", __func__);
            return ret;
        }
        HDF_LOGI("%{public}s: pipe info detail: id=%{public}d type=%{public}d dir=%{public}d maxPacketSize=%{public}d "
                 "interval=%{public}d",
            __func__, pipeInfo.id, pipeInfo.type, pipeInfo.dir, pipeInfo.maxPacketSize, pipeInfo.interval);
        switch (pipeInfo.type) {
            case USB_PIPE_TYPE_INTERRUPT:
                mtpDev->notifyPipe.id = pipeInfo.id;
                mtpDev->notifyPipe.maxPacketSize = pipeInfo.maxPacketSize;
                mtpDev->ctrlIface = iface; /* MTP device only have one interface, record here */
                mtpDev->intrIface = iface;
                break;
            case USB_PIPE_TYPE_BULK:
                if (pipeInfo.dir == USB_PIPE_DIRECTION_IN) {
                    mtpDev->dataInPipe.id = pipeInfo.id;
                    mtpDev->dataInPipe.maxPacketSize = pipeInfo.maxPacketSize;
                    mtpDev->dataIface = iface;
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

int32_t UsbfnMtpImpl::UsbMtpDeviceParseMtpIface(struct UsbMtpDevice *mtpDev, struct UsbFnInterface *fnIface)
{
    UsbFnInterfaceHandle handle = UsbFnOpenInterface(fnIface);
    if (handle == nullptr) {
        HDF_LOGE("%{public}s: open interface failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct UsbMtpInterface iface;
    iface.fn = fnIface;
    iface.handle = handle;
    int32_t ret = UsbMtpDeviceParseEachPipe(mtpDev, iface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: parse each pipe failed", __func__);
    }
    return ret;
}

bool UsbfnMtpImpl::UsbFnInterfaceIsUsbMtpPtpDevice(struct UsbFnInterface *iface)
{
    HDF_LOGI("%{public}s: iIf=%{public}d ifClass=%{public}d, subclass=%{public}d, protocol=%{public}d", __func__,
        iface->info.configIndex, iface->info.interfaceClass, iface->info.subclass, iface->info.protocol);

    if (iface->info.interfaceClass == USB_MTP_DEVICE_CLASS && iface->info.subclass == USB_MTP_DEVICE_SUBCLASS &&
        iface->info.protocol == USB_MTP_DEVICE_PROTOCOL) {
        HDF_LOGI("%{public}s: this is mtp device", __func__);
        return true;
    }
    if (iface->info.interfaceClass == USB_PTP_DEVICE_CLASS && iface->info.subclass == USB_PTP_DEVICE_SUBCLASS &&
        iface->info.protocol == USB_PTP_DEVICE_PROTOCOL) {
        HDF_LOGI("%{public}s: this is ptp device", __func__);
        return true;
    }
    return false;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceParseEachIface(struct UsbMtpDevice *mtpDev, struct UsbFnDevice *fnDev)
{
    for (int32_t i = 0; i < fnDev->numInterfaces; ++i) {
        struct UsbFnInterface *fnIface = const_cast<struct UsbFnInterface *>(UsbFnGetInterface(fnDev, i));
        if (fnIface == nullptr) {
            HDF_LOGE("%{public}s: get interface failed: %{public}d/%{public}d", __func__, i, fnDev->numInterfaces);
            return HDF_ERR_INVALID_PARAM;
        }
        if (UsbFnInterfaceIsUsbMtpPtpDevice(fnIface)) {
            /* MTP/PTP device only have one interface, only parse once */
            HDF_LOGI("%{public}s: found mtp/ptp interface: %{public}d/%{public}d", __func__, i, fnDev->numInterfaces);
            (void)UsbMtpDeviceParseMtpIface(mtpDev, fnIface);
            return HDF_SUCCESS;
        }
    }
    return HDF_FAILURE;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceCreateFuncDevice(struct UsbMtpDevice *mtpDev)
{
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == NULL) {
        HDF_LOGE("%{public}s: DeviceResourceGetIfaceInstance failed\n", __func__);
    }
    const char *udcName = nullptr;
    if (deviceObject_ != nullptr) {
        if (iface->GetString(deviceObject_->property, "udc_name", &udcName, UDC_NAME) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: read udc_name failed, use default: %{public}s", __func__, UDC_NAME);
        }
    }
    struct UsbFnDevice *fnDev = nullptr;
    if (udcName != nullptr) {
        fnDev = const_cast<struct UsbFnDevice *>(UsbFnGetDevice(udcName));
    } else {
        HDF_LOGE("%{public}s: udcName invalid, use default", __func__);
        fnDev = const_cast<struct UsbFnDevice *>(UsbFnGetDevice(UDC_NAME));
    }
    if (fnDev == NULL) {
        HDF_LOGE("%{public}s: create usb function device failed", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
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

int32_t UsbfnMtpImpl::UsbMtpDeviceReleaseFuncDevice(struct UsbMtpDevice *mtpDev)
{
    if (mtpDev->fnDev == nullptr) {
        HDF_LOGE("%{public}s: fnDev is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)UsbMtpDeviceFreeCtrlRequests(mtpDev);
    (void)UsbMtpDeviceFreeNotifyRequest(mtpDev);
    int32_t finalRet = HDF_SUCCESS;
    int32_t ret = UsbFnCloseInterface(mtpDev->ctrlIface.handle);
    if (ret != HDF_SUCCESS) {
        finalRet = ret;
        HDF_LOGW("%{public}s: close usb control interface failed", __func__);
    }
    ret = UsbFnCloseInterface(mtpDev->intrIface.handle);
    if (ret != HDF_SUCCESS) {
        finalRet = ret;
        HDF_LOGW("%{public}s: close usb interrupt interface failed", __func__);
    }
    ret = UsbFnCloseInterface(mtpDev->dataIface.handle);
    if (ret != HDF_SUCCESS) {
        finalRet = ret;
        HDF_LOGW("%{public}s: close usb data interface failed", __func__);
    }
    ret = UsbFnStopRecvInterfaceEvent(mtpDev->ctrlIface.fn);
    if (ret != HDF_SUCCESS) {
        finalRet = ret;
        HDF_LOGW("%{public}s: stop usb ep0 event handle failed", __func__);
    }
    return finalRet;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceAlloc(struct UsbMtpDevice *mtpDev)
{
    struct UsbMtpPort *mtpPort = static_cast<struct UsbMtpPort *>(OsalMemCalloc(sizeof(struct UsbMtpPort)));
    if (mtpPort == nullptr) {
        HDF_LOGE("%{public}s: Alloc usb mtpDev mtpPort failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    DListHeadInit(&mtpPort->readPool);
    DListHeadInit(&mtpPort->readQueue);
    DListHeadInit(&mtpPort->writePool);
    DListHeadInit(&mtpPort->writeQueue);
    mtpDev->mtpPort = mtpPort;
    mtpPort->mtpDev = mtpDev;
    mtpPort_ = mtpPort;
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceAllocNotifyRequest(struct UsbMtpDevice *mtpDev)
{
    mtpDev->notifyReq = UsbFnAllocRequest(mtpDev->intrIface.handle, mtpDev->notifyPipe.id, MTP_EVENT_PACKET_MAX_BYTES);
    if (mtpDev->notifyReq == nullptr) {
        HDF_LOGE("%{public}s: allocate notify request failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    mtpDev->notifyReq->complete = UsbFnRequestNotifyComplete;
    mtpDev->notifyReq->context = mtpDev;
    return HDF_SUCCESS;
}

void UsbfnMtpImpl::UsbMtpDeviceFreeNotifyRequest(struct UsbMtpDevice *mtpDev)
{
    int32_t ret = UsbFnFreeRequest(mtpDev->notifyReq);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: free notify request failed", __func__);
        return;
    }
    mtpDev->notifyReq = nullptr;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceFree(struct UsbMtpDevice *mtpDev)
{
    if (mtpDev->mtpPort == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMemFree(mtpDev->mtpPort);
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::Init()
{
    HDF_LOGI("%{public}s: Init", __func__);
    mtpDev_ = static_cast<struct UsbMtpDevice *>(OsalMemCalloc(sizeof(struct UsbMtpDevice)));
    if (mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: Alloc usb mtpDev device failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    if (mtpDev_->initFlag) {
        HDF_LOGE("%{public}s: usb mtpDev is already initialized", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = UsbfnMtpImpl::UsbMtpDeviceCreateFuncDevice(mtpDev_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceCreateFuncDevice failed", __func__);
        return ret;
    }
    /* init mtpPort */
    ret = UsbMtpDeviceAlloc(mtpDev_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceAlloc failed", __func__);
        goto ERR;
    }
    ret = UsbMtpDeviceAllocCtrlRequests(mtpDev_, MTP_CTRL_REQUEST_NUM);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceAllocCtrlRequests failed: %{public}d", __func__, MTP_CTRL_REQUEST_NUM);
        goto ERR;
    }
    ret = UsbMtpDeviceAllocNotifyRequest(mtpDev_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbMtpDeviceAllocNotifyRequest failed", __func__);
        goto ERR;
    }
    ret = UsbFnStartRecvInterfaceEvent(mtpDev_->ctrlIface.fn, 0xff, UsbMtpDeviceEp0EventDispatch, mtpDev_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: register event callback failed", __func__);
        goto ERR;
    }
    mtpDev_->initFlag = true;
    HDF_LOGI("%{public}s: Init success", __func__);
    return HDF_SUCCESS;
ERR:
    (void)UsbMtpDeviceReleaseFuncDevice(mtpDev_);
    (void)UsbMtpDeviceFree(mtpDev_);
    (void)OsalMemFree(mtpDev_);
    mtpDev_ = nullptr;
    return ret;
}

int32_t UsbfnMtpImpl::Release()
{
    HDF_LOGI("%{public}s: Release", __func__);
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    int32_t ret = UsbMtpDeviceReleaseFuncDevice(mtpDev_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: release device failed: %{public}d", __func__, ret);
        return ret;
    }
    ret = UsbMtpDeviceFree(mtpDev_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: free device failed: %{public}d", __func__, ret);
        return ret;
    }
    (void)OsalMemFree(mtpDev_);
    mtpDev_ = nullptr;
    HDF_LOGI("%{public}s: Release success", __func__);
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::Start()
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr || mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    mtpDev_->mtpState = MTP_STATE_READY;
    mtpPort_->startDelayed = true;
    return UsbMtpPortStartIo(mtpPort_);
}

int32_t UsbfnMtpImpl::Stop()
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr || mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    (void)UsbMtpPortCancelIo(mtpPort_);
    mtpPort_->startDelayed = false;
    mtpDev_->mtpState = MTP_STATE_OFFLINE;
    return HDF_SUCCESS;
}

uint32_t UsbfnMtpImpl::BufCopyToVector(void *buf, uint32_t bufSize, std::vector<uint8_t> &vectorData)
{
    uint8_t *addr = static_cast<uint8_t *>(buf);
    for (size_t i = 0; i < bufSize; i++) {
        vectorData.push_back(addr[i]);
    }
    return bufSize;
}

uint32_t UsbfnMtpImpl::BufCopyFromVector(
    void *buf, uint32_t bufSize, const std::vector<uint8_t> &vectorData, uint32_t vectorOffset)
{
    uint32_t count = (bufSize + vectorOffset) < vectorData.size() ? bufSize : vectorData.size() - vectorOffset;
    uint8_t *addr = static_cast<uint8_t *>(buf);
    for (size_t i = 0; i < count; i++) {
        addr[i] = vectorData.at(vectorOffset + i);
    }
    return count;
}

uint32_t UsbfnMtpImpl::BufCopyToFile(void *buf, uint32_t bufSize, int32_t fd)
{
    return write(fd, buf, bufSize);
}

uint32_t UsbfnMtpImpl::BufCopyFromFile(void *buf, uint32_t bufSize, int32_t fd)
{
    return read(fd, buf, bufSize);
}

int32_t UsbfnMtpImpl::Read(std::vector<uint8_t> &data)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr || mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }

    std::lock_guard<std::mutex> guard(mtpRunning_);

    struct DListHead *pool = &mtpPort_->readPool;
    struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
    if (req == nullptr) {
        HDF_LOGE("%{public}s: req invalid", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    DListRemove(&req->list);
    uint32_t dataSize = static_cast<uint32_t>(mtpDev_->dataOutPipe.maxPacketSize);
    req->length = dataSize;
    int32_t ret = UsbFnSubmitRequestSync(req, BULK_OUT_TIMEOUT_MS);
    DListInsertTail(&req->list, pool);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send bulk-out sync req failed: %{public}d", __func__, ret);
        return ret;
    }
    switch (req->status) {
        case USB_REQUEST_COMPLETED:
            (void)BufCopyToVector(req->buf, req->actual, data);
            break;
        case USB_REQUEST_NO_DEVICE:
            HDF_LOGV("%{public}s: device disconnected", __func__);
            mtpDev_->mtpState = MTP_STATE_OFFLINE;
            return HDF_DEV_ERR_NO_DEVICE;
        default:
            HDF_LOGV("%{public}s: unexpected status %{public}d", __func__, req->status);
            mtpDev_->mtpState = MTP_STATE_ERROR;
            break;
    }
    return ret == HDF_SUCCESS ? data.size() : ret;
}

int32_t UsbfnMtpImpl::WriteEx(const std::vector<uint8_t> &data, uint8_t sendZLP, uint32_t &xferActual)
{
    uint32_t needXferCount = data.size();
    int32_t ret = HDF_SUCCESS;
    while (needXferCount > 0 || sendZLP == ZLP_NEED_SEND) {
        struct DListHead *pool = &mtpPort_->writePool;
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        if (req == nullptr) {
            HDF_LOGE("%{public}s: req invalid", __func__);
            return HDF_DEV_ERR_DEV_INIT_FAIL;
        }
        DListRemove(&req->list);
        uint32_t reqMax = static_cast<uint32_t>(mtpDev_->dataInPipe.maxPacketSize);
        req->length = reqMax > needXferCount ? needXferCount : reqMax;
        if (needXferCount == 0) {
            sendZLP = ZLP_TRY_SEND;
            req->length = 0;
        }
        (void)BufCopyFromVector(req->buf, req->length, data, xferActual);
        ret = UsbFnSubmitRequestSync(req, BULK_IN_TIMEOUT_MS);
        DListInsertTail(&req->list, pool);
        if (sendZLP == ZLP_TRY_SEND) {
            sendZLP = ZLP_SEND_DONE;
            HDF_LOGI("%{public}s: send zero packet done: %{public}d", __func__, ret);
            return ret;
        }
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: bulk-in req failed: %{public}d", __func__, ret);
            break;
        }
        switch (req->status) {
            case USB_REQUEST_COMPLETED:
                needXferCount -= req->actual;
                xferActual += req->actual;
                break;
            case USB_REQUEST_NO_DEVICE:
                HDF_LOGV("%{public}s: device disconnected", __func__);
                mtpDev_->mtpState = MTP_STATE_OFFLINE;
                return HDF_DEV_ERR_NO_DEVICE;
            default:
                HDF_LOGV("%{public}s: unexpected status %{public}d", __func__, req->status);
                mtpDev_->mtpState = MTP_STATE_ERROR;
                break;
        }
    }
    return ret;
}

int32_t UsbfnMtpImpl::Write(const std::vector<uint8_t> &data)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr || mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    if (mtpDev_->mtpState == MTP_STATE_OFFLINE) {
        HDF_LOGE("%{public}s: device disconnect, stop rx", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (data.size() == 0) {
        HDF_LOGW("%{public}s: no data need to send", __func__);
        return HDF_SUCCESS;
    }
    uint32_t needXferCount = data.size();
    uint32_t xferActual = 0;
    int32_t ret = HDF_SUCCESS;
    uint8_t sendZLP = ZLP_NO_NEED;
    if ((needXferCount & (mtpDev_->dataInPipe.maxPacketSize - 1)) == 0) {
        sendZLP = ZLP_NEED_SEND;
    }
    ret = WriteEx(data, sendZLP, xferActual);
    return ret == HDF_SUCCESS ? data.size() : ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortRxCheckReq(
    struct UsbMtpPort *mtpPort, struct UsbMtpDevice *mtpDev, struct UsbFnRequest *req)
{
    switch (req->status) {
        case USB_REQUEST_NO_DEVICE:
            mtpDev->mtpState = MTP_STATE_OFFLINE;
            HDF_LOGV("%{public}s: rx req return disconnected", __func__);
            return HDF_DEV_ERR_NO_DEVICE;
        case USB_REQUEST_COMPLETED:
            break;
        default:
            HDF_LOGE("%{public}s: unexpected status %{public}d", __func__, req->status);
            mtpDev->mtpState = MTP_STATE_ERROR;
            return HDF_FAILURE;
    }
    if (req->actual < req->length || req->actual == 0) {
        HDF_LOGW("%{public}s: recv short packet, ignore data, end xfer: %{public}u vs %{public}u", __func__,
            req->length, req->actual);
        mtpDev->asyncXferFile = ASYNC_XFER_FILE_DONE;
    }
    if (req->actual == req->length && mtpDev->asyncRecvFileActual + req->actual == mtpDev->xferFileLength) {
        HDF_LOGW("%{public}s: recv last packet %{public}u vs %{public}u", __func__, req->length, req->actual);
        mtpDev->asyncXferFile = ASYNC_XFER_FILE_DONE;
        if (mtpDev->xferFileLength == MTP_MAX_FILE_SIZE) {
            ftruncate(mtpDev->xferFd, mtpDev->xferFileOffset + mtpDev->asyncRecvFileActual + req->actual);
        }
        if (memcpy_s(mtpDev->asyncRecvFileContent + mtpDev->asyncRecvFileActual,
            mtpDev->xferFileLength - mtpDev->asyncRecvFileActual, req->buf, req->actual) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed: last packet", __func__);
            sem_post(&bulkOutAsyncReq_);
            mtpDev->asyncXferFile = ASYNC_XFER_FILE_DONE;
            return HDF_FAILURE;
        }
        mtpDev->asyncRecvFileActual += req->actual;
    }
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpPortRxPush(struct UsbMtpPort *mtpPort)
{
    if (mtpPort == nullptr || mtpPort->mtpDev == nullptr) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = HDF_SUCCESS;
    struct DListHead *queue = &mtpPort->readQueue;
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;

    while (!DListIsEmpty(queue)) {
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(queue, struct UsbFnRequest, list);
        if (UsbMtpPortRxCheckReq(mtpPort, mtpDev, req) != HDF_SUCCESS) {
            sem_post(&bulkOutAsyncReq_);
            return HDF_ERR_IO;
        }
        if (mtpDev->asyncXferFile == ASYNC_XFER_FILE_DONE) {
            HDF_LOGE("%{public}s: recv done, ignore other packet: %{public}d/%{public}d", __func__,
                mtpPort->readStarted, mtpPort->readAllocated);
            sem_post(&bulkOutAsyncReq_);
            return HDF_SUCCESS;
        }
        if (memcpy_s(mtpDev->asyncRecvFileContent + mtpDev->asyncRecvFileActual,
            mtpDev->xferFileLength - mtpDev->asyncRecvFileActual, req->buf, req->actual) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            DListRemove(&req->list);
            DListInsertTail(&req->list, &mtpPort->readPool);
            mtpDev->asyncXferFile = ASYNC_XFER_FILE_DONE;
            sem_post(&bulkOutAsyncReq_);
            return HDF_FAILURE;
        }
        mtpDev->asyncRecvFileActual += req->actual;
        DListRemove(&req->list);
        DListInsertTail(&req->list, &mtpPort->readPool);
    }
    if (mtpDev->mtpState != MTP_STATE_OFFLINE) {
        if (UsbMtpPortStartRxAsync(mtpPort) != HDF_SUCCESS) {
            ret = HDF_ERR_IO;
        }
    }
    return ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortStartRxAsync(struct UsbMtpPort *mtpPort)
{
    struct DListHead *pool = &mtpPort->readPool;
    struct UsbMtpDevice *mtpDev = mtpPort->mtpDev;
    int32_t ret = HDF_SUCCESS;
    while (!DListIsEmpty(pool)) {
        if (mtpPort->readStarted >= mtpPort->readAllocated) {
            HDF_LOGW("%{public}s no idle read req(BULK-OUT)", __func__);
            ret = HDF_ERR_DEVICE_BUSY;
            break;
        }
        if (mtpDev->mtpState == MTP_STATE_OFFLINE) {
            HDF_LOGE("%{public}s: device disconnect, stop rx", __func__);
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
        }
        if (mtpDev->asyncRecvFileExpect >= mtpDev->xferFileLength) {
            HDF_LOGE("%{public}s: no need submit rx req[%{public}d/%{public}d]: %{public}d vs %{public}lld", __func__,
                mtpPort->readStarted, mtpPort->readAllocated, mtpDev->asyncRecvFileExpect, mtpDev->xferFileLength);
            return HDF_SUCCESS;
        }
        struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
        req->length = (mtpDev->asyncRecvFileExpect + mtpDev->dataOutPipe.maxPacketSize < mtpDev->xferFileLength) ?
            mtpDev->dataOutPipe.maxPacketSize :
            mtpDev->xferFileLength - mtpDev->asyncRecvFileExpect;
        if (mtpDev->xferFileLength == MTP_MAX_FILE_SIZE) {
            req->length = mtpDev->dataOutPipe.maxPacketSize;
        }
        DListRemove(&req->list);
        ret = UsbFnSubmitRequestAsync(req);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: submit bulk-out req error %{public}d", __func__, ret);
            DListInsertTail(&req->list, pool);
            break;
        }
        mtpPort->readStarted++;
        mtpDev->asyncRecvFileExpect += req->length;
    }
    return ret;
}

int32_t UsbfnMtpImpl::ReceiveFile(const UsbFnMtpFileSlice &mfs)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr || mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }

    HDF_LOGI("%{public}s: info: cmd=%{public}d, transid=%{public}d, len=%{public}lld offset=%{public}lld fd=%{public}d",
        __func__, mfs.command, mfs.transactionId, mfs.length, mfs.offset, mfs.fd);

    std::lock_guard<std::mutex> guard(mtpRunning_);
    if (mtpDev_->mtpState == MTP_STATE_OFFLINE) {
        HDF_LOGE("%{public}s: device disconnect, stop rx", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (mfs.length == 0) {
        HDF_LOGW("%{public}s: no data need to recv", __func__);
        return HDF_SUCCESS;
    }
    mtpDev_->xferFileOffset = mfs.offset;
    mtpDev_->xferFileLength = mfs.length;
    ftruncate(mfs.fd, mfs.offset + (mfs.length == MTP_MAX_FILE_SIZE ? mtpDev_->dataOutPipe.maxPacketSize : mfs.length));
    void *fileContent = mmap(nullptr, mfs.length, PROT_WRITE, MAP_SHARED, mfs.fd, mfs.offset);
    if (fileContent == nullptr) {
        HDF_LOGE("%{public}s: mmap failed: fd=%{public}d offset=%{public}lld len=%{public}lld", __func__,
            mtpDev_->xferFd, mtpDev_->xferFileOffset, mtpDev_->xferFileLength);
        return HDF_DEV_ERR_NO_MEMORY;
    }
    mtpDev_->asyncRecvFileContent = static_cast<uint8_t *>(fileContent);
    mtpDev_->asyncRecvFileActual = 0;
    mtpDev_->asyncRecvFileExpect = 0;

    sem_init(&bulkOutAsyncReq_, 1, 0);
    mtpDev_->asyncXferFile = ASYNC_XFER_FILE_NORMAL;
    if (UsbMtpPortStartRxAsync(mtpPort_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: start async tx failed", __func__);
        munmap(fileContent, mtpDev_->xferFileLength);
        return HDF_ERR_IO;
    }
    HDF_LOGI("%{public}s: start async rx, wait", __func__);
    sem_wait(&bulkOutAsyncReq_);
    munmap(fileContent, mtpDev_->xferFileLength);
    return (mtpDev_->asyncRecvFileActual == mtpDev_->xferFileLength) ? HDF_SUCCESS : HDF_ERR_IO;
}

int32_t UsbfnMtpImpl::UsbMtpPortSendFileFillFirstReq(
    struct UsbMtpPort *mtpPort, struct UsbFnRequest *req, void *dataBuf, uint32_t dataBufSize, uint32_t &oneReqLeft)
{
    uint32_t hdrSize = (mtpPort->mtpDev->xferSendHeader == 1) ? sizeof(struct UsbMtpDataHeader) : 0;
    uint32_t needXferCount = dataBufSize + hdrSize;
    uint32_t reqMax = static_cast<uint32_t>(mtpPort->mtpDev->dataInPipe.maxPacketSize);
    req->length = (reqMax > needXferCount) ? needXferCount : reqMax;
    if (hdrSize != 0) {
        /* write MTP header first */
        struct UsbMtpDataHeader *header = static_cast<struct UsbMtpDataHeader *>(req->buf);
        /* set file size with header according to MTP Specification v1.0 */
        header->length = needXferCount > MTP_MAX_FILE_SIZE ? MTP_MAX_FILE_SIZE : CPU_TO_LE32(needXferCount);
        /* type value 2 specified data packet */
        header->type = CPU_TO_LE16(2);
        header->cmdCode = CPU_TO_LE16(mtpPort->mtpDev->xferCommand);
        header->transactionId = CPU_TO_LE32(mtpPort->mtpDev->xferTransactionId);
        HDF_LOGI("%{public}s: write header: %{public}d of %{public}d", __func__, hdrSize, req->length);
    }
    uint8_t *bufOffset = static_cast<uint8_t *>(req->buf) + hdrSize;
    oneReqLeft =
        (hdrSize + mtpPort->mtpDev->xferFileLength < reqMax) ? mtpPort->mtpDev->xferFileLength : reqMax - hdrSize;
    if (memcpy_s(bufOffset, oneReqLeft, dataBuf, oneReqLeft) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::UsbMtpPortSendFileEx(void *dataBuf, uint32_t dataBufSize)
{
    struct DListHead *pool = &mtpPort_->writePool;
    struct UsbFnRequest *req = DLIST_FIRST_ENTRY(pool, struct UsbFnRequest, list);
    if (req == nullptr) {
        HDF_LOGE("%{public}s: req invalid", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    DListRemove(&req->list);
    uint32_t oneReqLeft = 0;
    int32_t ret = UsbMtpPortSendFileFillFirstReq(mtpPort_, req, dataBuf, dataBufSize, oneReqLeft);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: fill first sync bulk-in req failed: %{public}d", __func__, ret);
        DListInsertTail(&req->list, pool);
        return ret;
    }
    ret = UsbFnSubmitRequestSync(req, BULK_IN_TIMEOUT_MS);
    DListInsertTail(&req->list, pool);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bulk-in req failed: %{public}d", __func__, ret);
        return ret;
    }
    switch (req->status) {
        case USB_REQUEST_COMPLETED:
            break;
        case USB_REQUEST_NO_DEVICE:
            HDF_LOGV("%{public}s: device disconnected", __func__);
            mtpDev_->mtpState = MTP_STATE_OFFLINE;
            ret = HDF_DEV_ERR_NO_DEVICE;
            break;
        default:
            HDF_LOGV("%{public}s: unexpected status %{public}d", __func__, req->status);
            mtpDev_->mtpState = MTP_STATE_ERROR;
            ret = HDF_ERR_IO;
            break;
    }
    if (oneReqLeft != mtpDev_->xferFileLength) {
        ret = UsbMtpPortSendFileLeftAsync(dataBuf, oneReqLeft);
    }
    return ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortSendFileLeftAsync(void *dataBuf, uint32_t oneReqLeft)
{
    mtpDev_->asyncSendFileContent = static_cast<uint8_t *>(dataBuf) + oneReqLeft;
    mtpDev_->asyncSendFileActual = oneReqLeft;
    mtpDev_->asyncSendFileExpect = oneReqLeft;
    sem_init(&bulkInAsyncReq_, 1, 0);
    mtpDev_->asyncXferFile = ASYNC_XFER_FILE_NORMAL;
    if (UsbMtpPortStartTxAsync(mtpPort_, false) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: start async tx failed", __func__);
        return HDF_ERR_IO;
    }
    HDF_LOGI("%{public}s: wait async tx", __func__);
    sem_wait(&bulkInAsyncReq_);
    return (mtpDev_->mtpState == MTP_STATE_ERROR) ? HDF_ERR_IO : HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::SendFile(const UsbFnMtpFileSlice &mfs)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr || mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }

    mtpDev_->xferFd = mfs.fd;
    mtpDev_->xferFileOffset = mfs.offset;
    mtpDev_->xferFileLength = mfs.length;
    mtpDev_->xferCommand = mfs.command;
    mtpDev_->xferTransactionId = mfs.transactionId;
    mtpDev_->xferSendHeader = (mfs.command == 0 && mfs.transactionId == 0) ? 0 : 1;
    uint32_t hdrSize = (mtpDev_->xferSendHeader == 1) ? sizeof(struct UsbMtpDataHeader) : 0;
    uint32_t needXferCount = static_cast<uint32_t>(mfs.length) + hdrSize;
    HDF_LOGI("%{public}s: info: cmd=%{public}d, transid=%{public}d, len=%{public}lld offset=%{public}lld; "
             "Xfer=%{public}d(header=%{public}u)",
        __func__, mfs.command, mfs.transactionId, mfs.length, mfs.offset, needXferCount, hdrSize);

    if (needXferCount == 0) {
        HDF_LOGW("%{public}s: no data need to send", __func__);
        return HDF_SUCCESS;
    }
    if (mtpDev_->mtpState == MTP_STATE_OFFLINE) {
        HDF_LOGE("%{public}s: device disconnect, stop rx", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    mtpDev_->sendZLP = ZLP_NO_NEED;
    if ((needXferCount & (mtpDev_->dataInPipe.maxPacketSize - 1)) == 0) {
        mtpDev_->sendZLP = ZLP_NEED_SEND;
    }

    void *fileContent = mmap(nullptr, mfs.length, PROT_READ, MAP_SHARED, mfs.fd, mfs.offset);
    if (fileContent == nullptr) {
        HDF_LOGE("%{public}s: mmap failed", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    int32_t ret = UsbMtpPortSendFileEx(fileContent, static_cast<uint32_t>(mfs.length));
    munmap(fileContent, mtpDev_->xferFileLength);
    return ret;
}

int32_t UsbfnMtpImpl::SendEvent(const std::vector<uint8_t> &eventData)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr || mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    if (eventData.size() > MTP_EVENT_PACKET_MAX_BYTES || eventData.size() == 0) {
        HDF_LOGE("%{public}s: length is invald: %{public}d", __func__, eventData.size());
        return HDF_FAILURE;
    }
    if (mtpDev_->mtpState == MTP_STATE_OFFLINE) {
        HDF_LOGE("%{public}s: device offline", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    struct UsbFnRequest *req = mtpDev_->notifyReq;
    if (req == nullptr || req->buf == nullptr) {
        HDF_LOGE("%{public}s: notify req is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (memcpy_s(req->buf, eventData.size(), eventData.data(), eventData.size()) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        (void)UsbFnFreeRequest(req);
        return HDF_FAILURE;
    }
    req->length = static_cast<uint32_t>(eventData.size());
    int32_t ret = UsbFnSubmitRequestSync(req, INTR_IN_TIMEOUT_MS);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send notify sync request failed: %{public}d", __func__, ret);
    }
    return ret;
}
} // namespace V1_0
} // namespace Mtp
} // namespace Gadget
} // namespace Usb
} // namespace HDI
} // namespace OHOS
