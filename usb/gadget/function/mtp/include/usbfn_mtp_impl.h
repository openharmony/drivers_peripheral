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

#ifndef OHOS_HDI_USB_GADGET_MTP_V1_0_USBFNMTPIMPL_H
#define OHOS_HDI_USB_GADGET_MTP_V1_0_USBFNMTPIMPL_H

#include <mutex>

#include "data_fifo.h"
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
    struct DListHead readPool;
    struct DListHead readQueue;
    int32_t readStarted;
    int32_t readAllocated;
    struct DataFifo readFifo;
    struct DListHead writePool;
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
    struct UsbMtpPipe notifyPipe;
    struct UsbMtpPipe dataInPipe;
    struct UsbMtpPipe dataOutPipe;
    struct DListHead ctrlPool;
    int32_t ctrlReqNum;
    struct UsbFnRequest *notifyReq;
    uint8_t mtpState; /* record mtp state, example: MTP_STATE_OFFLINE */
    const char *udcName;
    bool initFlag;
    bool isSendEventDone;
    struct UsbMtpPort *mtpPort;
    int64_t xferFileOffset;
    int64_t xferFileLength;
    uint8_t xferSendHeader;     /* two value: 0 1 */
    uint16_t xferCommand;       /* refer to struct UsbMtpFileRange.command */
    uint32_t xferTransactionId; /* refer to struct UsbMtpFileRange.transactionId */
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

    const char *udcName_;

    /* Return 0 if operation is successful, or -1 else */
    int32_t Start(uint8_t ptp) override;
    /* Return 0 if operation is successful, or -1 else */
    int32_t Close() override;
    /* Return number of bytes read/written, or -1 and errno is set */
    int32_t Read(std::vector<uint8_t> &data) override;
    /* Return number of bytes read/written, or -1 and errno is set */
    int32_t Write(const std::vector<uint8_t> &data) override;
    /* Return 0 if send/receive is successful, or -1 and errno is set */
    int32_t ReceiveFile(const UsbFnMtpFileRange &mfr, sptr<Ashmem> &ashmem, uint8_t zeroPacket) override;
    /* Return 0 if send/receive is successful, or -1 and errno is set */
    int32_t SendFile(const UsbFnMtpFileRange &mfr, const sptr<Ashmem> &ashmem) override;
    /* Return 0 if send/receive is successful, or -1 and errno is set */
    int32_t SendEvent(const std::vector<uint8_t> &eventData) override;

    int32_t Init() override;
    int32_t Release() override;

private:
    static void UsbFnRequestReadComplete(uint8_t pipe, struct UsbFnRequest *req);

    static void UsbFnRequestWriteComplete(uint8_t pipe, struct UsbFnRequest *req);

    static void UsbFnRequestNotifyComplete(uint8_t pipe, struct UsbFnRequest *req);

    static int32_t UsbMtpPortStartTx(struct UsbMtpPort *mtpPort);

    static int32_t UsbMtpPortStartRx(struct UsbMtpPort *mtpPort);

    static void UsbMtpPortRxPush(struct UsbMtpPort *mtpPort);

    static void UsbFnRequestCtrlComplete(uint8_t pipe, struct UsbFnRequest *req);

    static int32_t UsbMtpDeviceAllocCtrlRequests(struct UsbMtpDevice *mtpDev, int32_t num);

    static void UsbMtpDeviceFreeCtrlRequests(struct UsbMtpDevice *mtpDev);

    static void UsbMtpPortFreeRequests(struct DListHead *head, int32_t *allocated);

    static int32_t UsbMtpPortAllocReadWriteRequests(struct UsbMtpPort *mtpPort, int32_t num, uint8_t isRead);

    static int32_t UsbMtpPortStartIo(struct UsbMtpPort *mtpPort);

    static int32_t UsbMtpPortCancelIo(struct UsbMtpPort *mtpPort);

    static int32_t UsbMtpAllocReadWriteFifo(struct DataFifo *fifo, uint32_t size);

    static void UsbMtpDeviceFreeReadWriteFifo(struct DataFifo *fifo);

    static int32_t UsbMtpPortOpen(struct UsbMtpPort *mtpPort);

    static int32_t UsbMtpPortClose(struct UsbMtpPort *mtpPort);

    static int32_t UsbMtpPortBulkInData(
        struct UsbMtpPort *mtpPort, const uint8_t *dataBuf, uint32_t dataSize, uint32_t *xferSize);

    static int32_t UsbMtpPortBulkOutData(
        struct UsbMtpPort *mtpPort, const uint8_t *dataBuf, uint32_t dataSize, uint32_t *xferSize);

    static struct UsbFnRequest *UsbMtpDeviceGetCtrlReq(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceBind(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceEnable(struct UsbMtpDevice *mtpDev);

    static uint32_t UsbMtpDeviceDisable(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceStandardRequest(
        struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req);

    static int32_t UsbMtpDeviceClassRequest(
        struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req);

    static int32_t UsbMtpDeviceVendorRequest(
        struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup, struct UsbFnRequest *req);

    static int32_t UsbMtpDeviceSetup(struct UsbMtpDevice *mtpDev, struct UsbFnCtrlRequest *setup);

    static void UsbMtpDeviceSuspend(struct UsbMtpDevice *mtpDev);

    static void UsbMtpDeviceResume(struct UsbMtpDevice *mtpDev);

    static void UsbMtpDeviceEp0EventDispatch(struct UsbFnEvent *event);

    static int32_t UsbMtpDeviceParseEachPipe(struct UsbMtpDevice *mtpDev, struct UsbMtpInterface *iface);

    static int32_t UsbMtpDeviceParseMtpIface(struct UsbMtpDevice *mtpDev, struct UsbFnInterface *fnIface);

    static bool UsbFnInterfaceIsUsbMtpPtpDevice(struct UsbFnInterface *iface);

    static int32_t UsbMtpDeviceParseEachIface(struct UsbMtpDevice *mtpDev, struct UsbFnDevice *fnDev);

    int32_t UsbMtpDeviceCreateFuncDevice(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceReleaseFuncDevice(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceAlloc(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceAllocNotifyRequest(struct UsbMtpDevice *mtpDev);

    static void UsbMtpDeviceFreeNotifyRequest(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpDeviceFree(struct UsbMtpDevice *mtpDev);

    static int32_t UsbMtpPortSendFileNoHeader(
        struct UsbMtpPort *mtpPort, uint8_t *dataBuf, uint32_t dataBufSize, uint32_t *xferActual);

    static int32_t UsbMtpPortSendFileWithHeader(struct UsbMtpPort *mtpPort, uint8_t *dataBuf, uint32_t dataBufSize,
        const UsbFnMtpFileRange &mfr, uint32_t *xferActual);

    static struct UsbMtpDevice *mtpDev_;
    static struct UsbMtpPort *mtpPort_;
    static std::mutex mtpRunning_;
};
} // namespace V1_0
} // namespace Mtp
} // namespace Gadget
} // namespace Usb
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_USB_GADGET_MTP_V1_0_USBFNMTPIMPL_H
