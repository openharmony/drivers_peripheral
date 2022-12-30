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

#include "usbfn_mtp_impl.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "default_config.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "hdf_log.h"

#define HDF_LOG_TAG usb_fn_mtp_interface_service

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

UsbfnMtpImpl::UsbfnMtpImpl() : udcName_(nullptr) {}

int32_t UsbfnMtpImpl::UsbMtpDeviceParseEachPipe(struct UsbMtpDevice *mtpDev, struct UsbMtpInterface *iface)
{
    struct UsbFnInterface *fnIface = iface->fn;
    if (fnIface == nullptr || fnIface->info.numPipes == 0) {
        HDF_LOGE("%{public}s: ifce is invalid", __func__);
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
    int32_t ret = UsbMtpDeviceParseEachPipe(mtpDev, &iface);
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
    }
    if (iface->info.interfaceClass == USB_PTP_DEVICE_CLASS && iface->info.subclass == USB_PTP_DEVICE_SUBCLASS &&
        iface->info.protocol == USB_PTP_DEVICE_PROTOCOL) {
        HDF_LOGI("%{public}s: this is ptp device", __func__);
    }
    return true;
}

int32_t UsbfnMtpImpl::UsbMtpDeviceParseEachIface(struct UsbMtpDevice *mtpDev, struct UsbFnDevice *fnDev)
{
    for (int32_t i = 0; i < fnDev->numInterfaces; i++) {
        struct UsbFnInterface *fnIface = (struct UsbFnInterface *)UsbFnGetInterface(fnDev, i);
        if (fnIface == nullptr) {
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

int32_t UsbfnMtpImpl::UsbMtpDeviceCreateFuncDevice(struct UsbMtpDevice *mtpDev)
{
    struct UsbFnDevice *fnDev = nullptr;
    if (udcName_ != nullptr) {
        fnDev = (struct UsbFnDevice *)UsbFnGetDevice(udcName_);
    } else {
        HDF_LOGE("%{public}s: udcName_ invalid, use default", __func__);
        fnDev = (struct UsbFnDevice *)UsbFnGetDevice(UDC_NAME);
    }
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
    struct UsbMtpPort *mtpPort = (struct UsbMtpPort *)OsalMemCalloc(sizeof(struct UsbMtpPort));
    if (mtpPort == nullptr) {
        HDF_LOGE("%{public}s: Alloc usb mtpDev mtpPort failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    DListHeadInit(&mtpPort->readPool);
    DListHeadInit(&mtpPort->readQueue);
    DListHeadInit(&mtpPort->writePool);
    mtpDev->mtpPort = mtpPort;
    mtpPort->mtpDev = mtpDev;
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
    mtpDev->isSendEventDone = true;
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
        HDF_LOGE("%{public}s: mtpPort is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMemFree(mtpDev->mtpPort);
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::Init()
{
    mtpDev_ = (struct UsbMtpDevice *)OsalMemCalloc(sizeof(struct UsbMtpDevice));
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
    return HDF_SUCCESS;
ERR:
    (void)UsbMtpDeviceReleaseFuncDevice(mtpDev_);
    (void)UsbMtpDeviceFree(mtpDev_);
    mtpDev_ = nullptr;
    return ret;
}

int32_t UsbfnMtpImpl::Release()
{
    if (mtpDev_->initFlag == false) {
        HDF_LOGE("%{public}s: usb mtpDev is not initialized", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    (void)UsbMtpDeviceReleaseFuncDevice(mtpDev_);
    (void)UsbMtpDeviceFree(mtpDev_);
    mtpDev_->initFlag = false;
    (void)OsalMemFree(mtpDev_);
    mtpDev_ = nullptr;
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::Start(uint8_t ptp)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    int32_t ret = UsbMtpAllocReadWriteFifo(&mtpPort_->writeFifo, BULK_WRITE_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: alloc write fifo failed", __func__);
        goto OUT;
    }

    ret = UsbMtpAllocReadWriteFifo(&mtpPort_->readFifo, BULK_READ_BUF_SIZE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: alloc read fifo failed", __func__);
        goto OUT;
    }

    /* the mtpDev is enabled, start the io stream */
    mtpDev_->isSendEventDone = true;
    if (!mtpPort_->suspended) {
        ret = UsbMtpPortStartIo(mtpPort_);
        if (ret != HDF_SUCCESS) {
            goto OUT;
        }
    } else {
        mtpPort_->startDelayed = true;
    }
OUT:
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::Close()
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    DataFifoReset(&mtpPort_->writeFifo);
    DataFifoReset(&mtpPort_->readFifo);
    mtpPort_->startDelayed = false;
    return HDF_SUCCESS;
}

int32_t UsbfnMtpImpl::Read(std::vector<uint8_t> &data)
{
    uint32_t xferSize = 0;
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (DataFifoIsEmpty(&mtpPort_->readFifo)) {
        /* no data */
        return HDF_SUCCESS;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    uint32_t dataMaxSize = DataFifoLen(&mtpPort_->readFifo) + sizeof(uint32_t);
    data.reserve(dataMaxSize);
    int32_t ret = UsbMtpPortBulkOutData(mtpPort_, static_cast<const uint8_t*>(data.data()), dataMaxSize, &xferSize);
    if (ret == HDF_DEV_ERR_NODATA) {
        ret = HDF_SUCCESS;
    }
    return ret;
}

int32_t UsbfnMtpImpl::Write(const std::vector<uint8_t> &data)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    uint32_t xferActual = 0;
    int32_t ret = UsbMtpPortBulkInData(mtpPort_, static_cast<const uint8_t*>(data.data()), data.size(), &xferActual);
    if (ret == HDF_DEV_ERR_NODATA) {
        /* all data send, no data left */
        ret = HDF_SUCCESS;
    }
    return ret;
}

int32_t UsbfnMtpImpl::ReceiveFile(const UsbFnMtpFileRange &mfr, sptr<Ashmem> &ashmem, uint8_t zeroPacket)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    (void)zeroPacket;
    int32_t shrMemFd = ashmem->GetAshmemFd();
    int32_t shrMemSize = ashmem->GetAshmemSize();
    lseek(shrMemFd, 0, SEEK_SET);
    uint8_t *shrMemStarAddr =
        static_cast<uint8_t *>(mmap(nullptr, shrMemSize, PROT_READ | PROT_WRITE, MAP_SHARED, shrMemFd, 0));
    close(shrMemFd);
    if (shrMemStarAddr == nullptr) {
        HDF_LOGE("%{public}s: mmap error: %{public}s", __func__, strerror(errno));
        return HDF_ERR_MALLOC_FAIL;
    }

    HDF_LOGI("%{public}s: mfr: cmd=%{public}d, transid=%{public}d, len=%{public}lld offset=%{public}lld", __func__,
        mfr.command, mfr.transactionId, mfr.length, mfr.offset);
    mtpDev_->xferFileOffset = mfr.offset;
    mtpDev_->xferFileLength = mfr.length;
    std::lock_guard<std::mutex> guard(mtpRunning_);

    uint32_t xferActual = 0;
    int32_t ret = UsbMtpPortBulkOutData(mtpPort_, shrMemStarAddr, shrMemSize, &xferActual);
    if (ret == HDF_DEV_ERR_NODATA) {
        HDF_LOGE("%{public}s: no data to read, or receive short packet", __func__);
        ret = HDF_SUCCESS;
    }
    if (ret == HDF_SUCCESS && mtpDev_->mtpState != MTP_STATE_READY) {
        ret = HDF_ERR_IO;
    }
    munmap(shrMemStarAddr, shrMemSize);
    return ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortSendFileNoHeader(
    struct UsbMtpPort *mtpPort, uint8_t *dataBuf, uint32_t dataBufSize, uint32_t *xferActual)
{
    int32_t ret = UsbMtpPortBulkInData(mtpPort, (const uint8_t *)dataBuf, dataBufSize, xferActual);
    if (ret == HDF_DEV_ERR_NODATA) {
        /* all data send, no data left */
        ret = HDF_SUCCESS;
    }
    return ret;
}

int32_t UsbfnMtpImpl::UsbMtpPortSendFileWithHeader(struct UsbMtpPort *mtpPort, uint8_t *dataBuf, uint32_t dataBufSize,
    const UsbFnMtpFileRange &mfr, uint32_t *xferActual)
{
    uint32_t hdrSize = (mtpPort->mtpDev->xferSendHeader == 1) ? sizeof(struct UsbMtpDataHeader) : 0;
    int64_t needXferCount = dataBufSize + hdrSize;
    uint32_t xferedCount = 0;
    uint32_t singleXferActual = 0;
    int32_t ret = HDF_SUCCESS;
    while (needXferCount > 0) {
        if (mtpPort->mtpDev->mtpState == MTP_STATE_OFFLINE) {
            HDF_LOGE("%{public}s: mtp device offline", __func__);
            return HDF_DEV_ERR_NO_DEVICE;
        } else if (mtpPort->mtpDev->mtpState == MTP_STATE_CANCELED) {
            HDF_LOGE("%{public}s: mtp device req cancel", __func__);
            return HDF_ERR_IO;
        }
        uint32_t fifoAvail = DataFifoAvailSize(&mtpPort->writeFifo);
        if (hdrSize == 0) {
            /* send MTP data, header is already xfered */
            singleXferActual = DataFifoWrite(&mtpPort->writeFifo, (uint8_t *)&dataBuf[xferedCount],
                ((needXferCount > fifoAvail) ? fifoAvail : needXferCount));
        } else {
            /* send MTP header + data */
            struct UsbMtpDataHeader *header = (struct UsbMtpDataHeader *)OsalMemCalloc(sizeof(*header));
            /* set file size with header according to MTP Specification v1.0 */
            header->length = needXferCount > MTP_MAX_FILE_SIZE ? MTP_MAX_FILE_SIZE : CPU_TO_LE32(needXferCount);
            /* type value 2 specified data packet */
            header->type = CPU_TO_LE16(2);
            header->cmdCode = CPU_TO_LE16(mfr.command);
            header->transactionId = CPU_TO_LE32(mfr.transactionId);
            singleXferActual =
                DataFifoWrite(&mtpPort->writeFifo, (uint8_t *)&header[xferedCount], hdrSize - xferedCount);
            if (fifoAvail >= hdrSize - xferedCount && singleXferActual >= hdrSize - xferedCount) {
                /* write header complete, availible for write data */
                (void)OsalMemFree(header);
                hdrSize = 0;
                singleXferActual += DataFifoWrite(
                    &mtpPort->writeFifo, (uint8_t *)dataBuf, fifoAvail < dataBufSize ? fifoAvail : dataBufSize);
            }
        }
        ret = UsbMtpPortStartTx(mtpPort);
        if (ret != HDF_SUCCESS) {
            break;
        }
        xferedCount += singleXferActual;
        needXferCount -= singleXferActual;
    }
    *xferActual = xferedCount;
    return ret;
}

int32_t UsbfnMtpImpl::SendFile(const UsbFnMtpFileRange &mfr, const sptr<Ashmem> &ashmem)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }

    int32_t shrMemFd = ashmem->GetAshmemFd();
    int32_t shrMemSize = ashmem->GetAshmemSize();
    lseek(shrMemFd, 0, SEEK_SET);
    uint8_t *shrMemStarAddr =
        static_cast<uint8_t *>(mmap(nullptr, shrMemSize, PROT_READ | PROT_WRITE, MAP_SHARED, shrMemFd, 0));
    close(shrMemFd);
    if (shrMemStarAddr == nullptr) {
        HDF_LOGE("%{public}s: mmap error: %{public}s", __func__, strerror(errno));
        return HDF_ERR_MALLOC_FAIL;
    }

    std::lock_guard<std::mutex> guard(mtpRunning_);

    mtpDev_->xferFileOffset = mfr.offset;
    mtpDev_->xferFileLength = mfr.length;
    mtpDev_->xferSendHeader = (mfr.command == 0 && mfr.transactionId == 0) ? 0 : 1;
    uint32_t hdrSize = (mtpDev_->xferSendHeader == 1) ? sizeof(struct UsbMtpDataHeader) : 0;
    int64_t needXferCount = shrMemSize + hdrSize;
    HDF_LOGI("%{public}s: mfr: cmd=%{public}d, transid=%{public}d, len=%{public}lld offset=%{public}lld; "
             "Xfer=%{public}lld(header=%{public}u)",
        __func__, mfr.command, mfr.transactionId, mfr.length, mfr.offset, needXferCount, hdrSize);

    uint32_t xferActual = 0;
    int32_t ret = mtpDev_->xferSendHeader == 1 ?
        UsbMtpPortSendFileNoHeader(mtpPort_, shrMemStarAddr, needXferCount, &xferActual) :
        UsbMtpPortSendFileWithHeader(mtpPort_, shrMemStarAddr, needXferCount, mfr, &xferActual);

    munmap(shrMemStarAddr, shrMemSize);
    return ret;
}

int32_t UsbfnMtpImpl::SendEvent(const std::vector<uint8_t> &eventData)
{
    if (mtpPort_ == nullptr || mtpDev_ == nullptr) {
        HDF_LOGE("%{public}s: no init", __func__);
        return HDF_DEV_ERR_DEV_INIT_FAIL;
    }
    if (!mtpDev_->isSendEventDone) {
        return HDF_ERR_DEVICE_BUSY;
    }
    std::lock_guard<std::mutex> guard(mtpRunning_);

    if (eventData.size() > MTP_EVENT_PACKET_MAX_BYTES) {
        HDF_LOGE("%{public}s: length is invald: %{public}d", __func__, eventData.size());
        return HDF_FAILURE;
    }
    if (mtpDev_->mtpState == MTP_STATE_OFFLINE) {
        return HDF_DEV_ERR_NO_DEVICE;
    }
    struct UsbFnRequest *req = mtpDev_->notifyReq;
    if (req == nullptr || req->buf == nullptr) {
        HDF_LOGE("%{public}s: notify req is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (memcpy_s((void *)req->buf, eventData.size(), eventData.data(), eventData.size()) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        (void)UsbFnFreeRequest(req);
        mtpDev_->notifyReq = nullptr;
        return HDF_FAILURE;
    }
    mtpDev_->isSendEventDone = false;
    mtpDev_->notifyReq = nullptr;
    int32_t ret = UsbFnSubmitRequestAsync(req);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send notify request failed", __func__);
        mtpDev_->notifyReq = req;
    }
    return ret;
}
} // namespace V1_0
} // namespace Mtp
} // namespace Gadget
} // namespace Usb
} // namespace HDI
} // namespace OHOS
