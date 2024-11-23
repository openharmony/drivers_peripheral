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

#include <semaphore.h>
#include <mutex>
#include <semaphore.h>
#include <pthread.h>

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
    struct DListHead readQueue; /* working async read(bulk-out) req */
    struct UsbFnRequest *standbyReq;
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
    uint64_t asyncRecvFileActual;
    uint64_t asyncRecvFileExpect;
    uint64_t asyncSendFileActual;   /* already send actual */
    uint64_t asyncSendFileExpect;   /* already send expect */
    uint8_t asyncXferFile;
    uint8_t needZLP;
    uint32_t asyncRecvWriteTempCount;
    uint8_t *asyncRecvWriteTempContent;
    bool initFlag;
    uint8_t mtpState;           /* record mtp state, example: MTP_STATE_OFFLINE */
    uint8_t xferSendHeader;     /* two value: 0 1 */
    uint16_t xferCommand;       /* refer to struct UsbMtpFileRange.command */
    uint32_t xferTransactionId; /* refer to struct UsbMtpFileRange.transactionId */
    int32_t xferFd;
    uint64_t xferFileOffset;
    uint64_t xferFileLength;
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
    /* Return 0 if operation is successful  */
    int32_t Read(std::vector<uint8_t> &data) override;
    /* Return 0 if operation is successful  */
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

    static int32_t UsbMtpPortTxReqCheck(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static int32_t UsbMtpPortProcessLastTxPacket(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static int32_t UsbMtpPortSubmitAsyncTxReq(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static int32_t UsbMtpPortStartTxAsync(struct UsbMtpPort *mtpPort, bool callByComplete);
    static int32_t UsbMtpPortProcessAsyncRxDone(struct UsbMtpPort *mtpPort);
    static int32_t UsbMtpPortRxPush(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static int32_t UsbMtpPortStartSubmitRxReq(struct UsbMtpPort *mtpPort, bool needZLP);
    static int32_t UsbMtpPortStartRxAsync(struct UsbMtpPort *mtpPort);
    static int32_t UsbMtpPortRxCheckReq(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req, bool &writeToFile);
    static void UsbMtpPortReleaseRxReq(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static void UsbMtpPortReleaseTxReq(struct UsbMtpPort *mtpPort, struct UsbFnRequest *req);
    static int32_t UsbMtpPortCancelAndFreeReq(
        struct DListHead *queueHead, struct DListHead *poolHead, int32_t &allocated, bool freeReq);
    static int32_t UsbMtpPortCancelPlusFreeIo(struct UsbMtpPort *mtpPort, bool freeReq);
    static int32_t UsbMtpPortCancelRequest(struct UsbMtpPort *mtpPort);
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
    static void CopyReqToStandbyReqPool(const struct UsbFnRequest *req, struct UsbFnRequest *standbyReq);
    int32_t UsbMtpDeviceAllocCtrlRequests(int32_t num);
    void UsbMtpDeviceFreeCtrlRequests();
    void UsbMtpPortFreeRequests(struct DListHead *head, int32_t &allocated);
    int32_t UsbMtpPortAllocReadWriteRequests(int32_t readSize, int32_t writeSize);
    int32_t UsbMtpPortInitIo();
    int32_t UsbMtpPortReleaseIo();
    int32_t UsbMtpDeviceParseEachPipe(struct UsbMtpInterface &iface);
    int32_t UsbMtpDeviceParseMtpIface(struct UsbFnInterface *fnIface);
    bool UsbFnInterfaceIsUsbMtpPtpDevice(struct UsbFnInterface *iface);
    int32_t UsbMtpDeviceParseEachIface(struct UsbFnDevice *fnDev);
    int32_t UsbMtpDeviceCreateFuncDevice();
    int32_t UsbMtpDeviceReleaseFuncDevice();
    int32_t UsbMtpDeviceAlloc();
    int32_t UsbMtpDeviceFree();
    int32_t UsbMtpDeviceAllocNotifyRequest();
    void UsbMtpDeviceFreeNotifyRequest();
    int32_t InitMtpPort();
    int32_t WriteEx(const std::vector<uint8_t> &data, uint8_t sendZLP, uint32_t &xferActual);
    int32_t WriteSplitPacket(const std::vector<uint8_t> &data);
    int32_t getActualLength(const std::vector<uint8_t> &data);
    int32_t ReadImpl(std::vector<uint8_t> &data);
    int32_t UsbMtpPortSendFileFillFirstReq(struct UsbFnRequest *req, uint64_t &oneReqLeft);
    int32_t UsbMtpPortSendFileEx();
    int32_t UsbMtpPortSendFileLeftAsync(uint64_t oneReqLeft);
    int32_t ReceiveFileEx();

    uint32_t BufCopyToVector(void *buf, uint32_t bufSize, std::vector<uint8_t> &vectorData);
    uint32_t BufCopyFromVector(
        void *buf, uint32_t bufSize, const std::vector<uint8_t> &vectorData, uint32_t vectorOffset);
    void UsbMtpSendFileParamSet(const UsbFnMtpFileSlice &mfs);
    static struct UsbMtpDevice *mtpDev_;
    static struct UsbMtpPort *mtpPort_;
    static std::mutex startMutex_;
    static std::mutex readMutex_;
    static std::mutex writeMutex_;
    static std::mutex eventMutex_;
    static std::mutex asyncMutex_;
    static sem_t asyncReq_;
    static pthread_rwlock_t mtpRunrwLock_;
    std::vector<uint8_t> vectorSplited_;
    size_t writeActualLen_;
};
} // namespace V1_0
} // namespace Mtp
} // namespace Gadget
} // namespace Usb
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_USB_GADGET_MTP_V1_0_USBFNMTPIMPL_H
