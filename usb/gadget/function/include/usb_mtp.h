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

#ifndef HDF_USB_MTP_H
#define HDF_USB_MTP_H

#include "data_fifo.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "osal_atomic.h"
#include "osal_mutex.h"
#include "osal_spinlock.h"
#include "usb_ddk.h"
#include "usb_object.h"
#include "usbfn_request.h"

#define MTP_MAX_FILE_SIZE 0xFFFFFFFFL

enum UsbMtpCmd {
    USB_MTP_OPEN = 0,
    USB_MTP_CLOSE,
    USB_MTP_READ,
    USB_MTP_WRITE,
    USB_MTP_SEND_FILE,
    USB_MTP_RECEIVE_FILE,
    USB_MTP_SEND_EVENT,
    USB_MTP_SEND_FILE_WITH_HEADER,
    USB_MTP_INIT = 100,    /* alloc MTP resource */
    USB_MTP_RELEASE = 101, /* release MTP resource */
};

/* used in hdi interface, application */
struct UsbMtpFileRange {
    /* file descriptor for file to transfer */
    int fd;
    /* offset in file for start of transfer */
    int64_t offset;
    /* number of bytes to transfer */
    int64_t length;
    /* MTP command ID for data header, used only for MTP_SEND_FILE_WITH_HEADER */
    uint16_t command;
    /* MTP transaction ID for data header, used only for MTP_SEND_FILE_WITH_HEADER */
    uint32_t transactionId;
};

/* used in driver, hdi interface, application */
struct UsbMtpEvent {
    /* size of the event */
    size_t length;
    /* event data to send */
    void *data;
};

/* used in driver, hdi interface, subset of struct UsbMtpFileRange */
struct UsbMtpDriverFileRange {
    /* offset in file for start of transfer */
    int64_t offset;
    /* number of bytes to transfer */
    int64_t length;
    /* MTP command ID for data header, used only for MTP_SEND_FILE_WITH_HEADER */
    uint16_t command;
    /* MTP transaction ID for data header, used only for MTP_SEND_FILE_WITH_HEADER */
    uint32_t transactionId;
};

struct UsbMtpDataHeader {
    uint32_t length;
    uint16_t type;    /* defined mtp data type */
    uint16_t cmdCode; /* Operation, Response or Event Code in mtp */
    uint32_t transactionId;
};

struct UsbMtpDataPacket {
    struct UsbMtpDataHeader header;
    void *payload;
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
    struct OsalMutex lock;
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

struct MtpNotifyMethod;
struct UsbMtpDevice {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *hdfDevice;
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
    struct OsalMutex mutex;
    uint8_t mtpState; /* record mtp state, example: MTP_STATE_OFFLINE */
    const char *udcName;
    bool initFlag;
    bool isSendEventDone;
    struct UsbMtpPort *mtpPort;
    struct MtpNotifyMethod *notifyUser;
    void *xferData;
    int64_t xferFileOffset;
    int64_t xferFileLength;
    uint8_t xferSendHeader;     /* two value: 0 1 */
    uint16_t xferCommand;       /* refer to struct UsbMtpFileRange.command */
    uint32_t xferTransactionId; /* refer to struct UsbMtpFileRange.transactionId */
    int xferResult;
};

struct CtrlInfo {
    uint8_t request;
    struct UsbMtpDevice *mtpDev;
};

struct MtpNotifyMethod {
    void (*Connect)(struct UsbMtpDevice *mtpDev);
    void (*Disconnect)(struct UsbMtpDevice *mtpDev);
};

#endif /* HDF_USB_MTP_H */
