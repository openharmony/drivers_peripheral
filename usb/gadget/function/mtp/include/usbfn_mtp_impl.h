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

#ifndef OHOS_HDI_USB_GADGET_MTP_V1_0_USBFNMTPIMPL_H
#define OHOS_HDI_USB_GADGET_MTP_V1_0_USBFNMTPIMPL_H

#include <mutex>

#include "data_fifo.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "usbfn_device.h"
#include "usbfn_interface.h"
#include "usbfn_request.h"
#include "v1_0/iusbfn_mtp_interface.h"

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

#define MTP_MAX_FILE_SIZE 0xFFFFFFFFL

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

struct UsbMtpDataHeader {
    uint32_t length;
    uint16_t type;    /* defined mtp data type */
    uint16_t cmdCode; /* Operation, Response or Event Code in mtp */
    uint32_t transactionId;
};

struct UsbMtpPipe {
    uint8_t id;
    uint16_t maxPacketSize;
    struct UsbFnInterface *ctrlIface;
};

struct UsbMtpInterface {
    struct UsbFnInterface *fn;
    UsbFnInterfaceHandle handle;
};

struct UsbMtpPort {
    struct UsbMtpDevice *mtpDev;
    struct DListHead readPool;  /* ready/idle read(bulk-out) req */
    struct DListHead readQueue; /* async read(bulk-out) req complete */
    int32_t readStarted;
    int32_t readAllocated;
    struct DataFifo readFifo;
    struct DListHead writePool;  /* ready/idle write(bulk-in) req */
    struct DListHead writeQueue; /* working async write(bulk-in) req */
    int32_t writeStarted;
    int32_t writeAllocated;
    struct DataFifo writeFifo;
    bool writeBusy;
    bool suspended;
    bool startDelayed;
    int32_t refCount;
};

struct UsbMtpDevice {
    struct UsbFnDevice *fnDev;
    struct UsbMtpInterface ctrlIface;
    struct UsbMtpInterface intrIface;
    struct UsbMtpInterface dataIface;
    struct UsbMtpPipe notifyPipe;  /* intr-in */
    struct UsbMtpPipe dataInPipe;  /* bulk-in */
    struct UsbMtpPipe dataOutPipe; /* bulk-out */
    struct DListHead ctrlPool;
    int32_t ctrlReqNum;
    struct UsbFnRequest *notifyReq;
    struct UsbMtpPort *mtpPort;
    const char *udcName;
    uint8_t *asyncRecvFileContent;
    uint32_t asyncRecvFileActual;
    uint32_t asyncRecvFileExpect;
    uint8_t *asyncSendFileContent;
    uint32_t asyncSendFileActual; /* already send actual */
    uint32_t asyncSendFileExpect; /* already send expect */
    uint8_t asyncXferFile;
    uint8_t sendZLP;
    bool initFlag;
    uint8_t mtpState;           /* record mtp state, example: MTP_STATE_OFFLINE */
    uint8_t xferSendHeader;     /* two value: 0 1 */
    uint16_t xferCommand;       /* refer to struct UsbMtpFileRange.command */
    uint32_t xferTransactionId; /* refer to struct UsbMtpFileRange.transactionId */
    int32_t xferFd;
    int64_t xferFileOffset;
    int64_t xferFileLength;
};

struct CtrlInfo {
    uint8_t request;
    struct UsbMtpDevice *mtpDev;
};

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Gadget {
namespace Mtp {
namespace V1_0 {
class UsbfnMtpImpl : public IUsbfnMtpInterface {
public:
    UsbfnMtpImpl();
    virtual ~UsbfnMtpImpl() = default;

    HdfDeviceObject *deviceObject_;

    /* Return 0 if operation is successful */
    int32_t Start() override;
    /* Return 0 if operation is successful  */
    int32_t Stop() override;
    /* Return number of bytes read/written  */
    int32_t Read(std::vector<uint8_t> &data) override;
    /* Return number of bytes read/written  */
    int32_t Write(const std::vector<uint8_t> &data) override;
    /* Return 0 if send/receive is successful  */
    int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs) override;
    /* Return 0 if send/receive is successful  */
    int32_t SendFile(const UsbFnMtpFileSlice &mfs) override;
    /* Return 0 if send/receive is successful  */
    int32_t SendEvent(const std::vector<uint8_t> &eventData) override;

    int32_t Init() override;
    int32_t Release() override;

private:
    static void UsbFnRequestReadComplete(uint8_t pipe, struct UsbFnRequest *req);
    static void UsbFnRequestWriteComplete(uint8_t pipe, struct UsbFnRequest *req);
    static void UsbFnRequestNotifyComplete(uint8_t pipe, struct UsbFnRequest *req);
    static void UsbFnRequestCtrlComplete(uint8_t pipe, struct UsbFnRequest *req);

    static int32_t UsbMtpPortCheckTxReq(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static int32_t UsbMtpPortProcessLastTxPacket(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static int32_t UsbMtpPortSubmitAsyncTxReq(
        struct UsbMtpPort *mtpPort, struct UsbFnRequest *req, uint8_t *fileContent);
    static int32_t UsbMtpPortStartTxAsync(struct UsbMtpPort *mtpPort, bool callByComplete);
    static int32_t UsbMtpPortRxPush(struct UsbMtpPort *mtpPort);
    static int32_t UsbMtpPortStartRxAsync(struct UsbMtpPort *mtpPort);
    static int32_t UsbMtpPortRxCheckReq(
        struct UsbMtpPort *mtpPort, struct UsbMtpDevice *mtpDev, struct UsbFnRequest *req);

    static int32_t UsbMtpDeviceAllocCtrlRequests(struct UsbMtpDevice *mtpDev, int32_t num);
    static void UsbMtpDeviceFreeCtrlRequests(struct UsbMtpDevice *mtpDev);

    static void UsbMtpPortFreeRequests(struct DListHead *head, int32_t &allocated);

    static int32_t UsbMtpPortAllocReadWriteRequests(struct UsbMtpPort *mtpPort, int32_t readSize, int32_t writeSize);

    static int32_t UsbMtpPortCancelAndFreeReq(
        struct DListHead *queueHead, struct DListHead *poolHead, int32_t &allocated);

    static int32_t UsbMtpPortStartIo(struct UsbMtpPort *mtpPort);
    static int32_t UsbMtpPortCancelIo(struct UsbMtpPort *mtpPort);

    static struct UsbFnRequest *UsbMtpDeviceGetCtrlReq(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceStandardRequest(
        struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req);
    static int32_t UsbMtpDeviceClassRequest(
        struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req);
    static int32_t UsbMtpDeviceVendorRequest(
        struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req);
    static int32_t UsbMtpDeviceSetup(struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup);

    static void UsbMtpDeviceSuspend(struct UsbMtpDevice *mtpDev);
    static void UsbMtpDeviceResume(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceEnable(struct UsbMtpDevice *mtpDev);
    static int32_t UsbMtpDeviceDisable(struct UsbMtpDevice *mtpDev);

    static void UsbMtpDeviceEp0EventDispatch(struct UsbFnEvent *event);

    static int32_t UsbMtpDeviceParseEachPipe(struct UsbMtpDevice *mtpDev, struct UsbMtpInterface &iface);
    static int32_t UsbMtpDeviceParseMtpIface(struct UsbMtpDevice *mtpDev, struct UsbFnInterface *fnIface);
    static bool UsbFnInterfaceIsUsbMtpPtpDevice(struct UsbFnInterface *iface);
    static int32_t UsbMtpDeviceParseEachIface(struct UsbMtpDevice *mtpDev, struct UsbFnDevice *fnDev);

    int32_t UsbMtpDeviceCreateFuncDevice(struct UsbMtpDevice *mtpDev);
    static int32_t UsbMtpDeviceReleaseFuncDevice(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceAlloc(struct UsbMtpDevice *mtpDev);
    static int32_t UsbMtpDeviceFree(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceAllocNotifyRequest(struct UsbMtpDevice *mtpDev);
    static void UsbMtpDeviceFreeNotifyRequest(struct UsbMtpDevice *mtpDev);

    static int32_t WriteEx(const std::vector<uint8_t> &data, uint8_t sendZLP, uint32_t &xferActual);

    static int32_t UsbMtpPortSendFileFillFirstReq(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req, void *dataBuf,
        uint32_t dataBufSize, uint32_t &oneReqLeft);
    static int32_t UsbMtpPortSendFileEx(void *dataBuf, uint32_t dataBufSize);
    static int32_t UsbMtpPortSendFileLeftAsync(void *dataBuf, uint32_t oneReqLeft);

    static uint32_t BufCopyToVector(void *buf, uint32_t bufSize, std::vector<uint8_t> &vectorData);
    static uint32_t BufCopyFromVector(
        void *buf, uint32_t bufSize, const std::vector<uint8_t> &vectorData, uint32_t vectorOffset);
    static uint32_t BufCopyToFile(void *buf, uint32_t bufSize, int32_t fd);
    static uint32_t BufCopyFromFile(void *buf, uint32_t bufSize, int32_t fd);

    static struct UsbMtpDevice *mtpDev_;
    static struct UsbMtpPort *mtpPort_;
    static std::mutex mtpRunning_;
    static sem_t bulkOutAsyncReq_;
    static sem_t bulkInAsyncReq_;
};
} // namespace V1_0
} // namespace Mtp
} // namespace Gadget
} // namespace Usb
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_USB_GADGET_MTP_V1_0_USBFNMTPIMPL_H
