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

#ifndef USBD_H
#define USBD_H

#include "data_fifo.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "osal_sem.h"
#include "refbase.h"
#include "iremote_object.h"
#include "usb_ddk.h"
#include "usb_ddk_interface.h"
#include "usb_session.h"
#include "usbd_type.h"
#include "v1_1/iusb_interface.h"
#include "v1_0/iusbd_bulk_callback.h"

#define USB_MAX_INTERFACES 32
#define USB_MAX_DEVICE_NUMBERS 127
#define DIRECTION_MASK         0x1
#define USB_CTRL_SET_TIMEOUT   5000
#define USB_PIPE_DIR_OFFSET    7
#define MAX_SUBSCRIBER         10
#define USBD_BULKASYNCREQ_NUM_MAX 64

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_1 {
struct UsbdBulkASyncReqList;
struct UsbdBulkASyncList;
class UsbImpl;
struct UsbdBufferHandle {
    int32_t fd;   /**< buffer fd, -1 if not supported */
    uint32_t size; /* < size of memory */
    uint8_t *starAddr;
    uint32_t cur;
    uint32_t rcur;
    uint8_t cbflg;
    struct OsalMutex lock;
};

struct UsbdBulkASyncReqNode {
    struct DListHead node;
    struct UsbRequest *request;
    struct UsbdBulkASyncReqList *list;
    int32_t use;
    int32_t id;
};

struct UsbdBulkASyncReqList {
    struct UsbdBulkASyncReqNode node[USBD_BULKASYNCREQ_NUM_MAX];
    struct UsbdBulkASyncList *pList;
    struct DListHead eList;
    struct DListHead uList;
    struct OsalMutex elock;
    struct OsalMutex ulock;
};

struct UsbdBulkASyncList {
    struct HostDevice *instance;
    struct UsbdBulkASyncList *next;
    UsbInterfaceHandle *ifHandle;
    sptr<HDI::Usb::V1_1::IUsbdBulkCallback> cb;
    struct UsbdBulkASyncReqList rList;
    struct UsbPipeInfo pipe;
    struct UsbRequestParams params;
    struct UsbdBufferHandle asmHandle;
    uint8_t ifId;
    uint8_t epId;
};

struct HostDevice {
    struct HdfSListNode node;
    struct DataFifo readFifo;
    struct HdfSList requestQueue;
    struct OsalMutex requestLock;
    struct HdfSList reqSyncList;
    struct OsalMutex reqSyncLock;
    struct HdfSList reqASyncList;
    struct OsalMutex reqASyncLock;
    struct OsalMutex writeLock;
    struct OsalMutex readLock;
    struct OsalMutex lock;
    struct UsbRequest *ctrlReq;
    struct UsbInterface *ctrIface;
    struct UsbPipeInfo *ctrPipe;
    struct UsbdBulkASyncList *bulkASyncList;
    UsbInterfaceHandle *ctrDevHandle;
    UsbImpl *service;
    struct UsbInterface *iface[USB_MAX_INTERFACES];
    UsbInterfaceHandle *devHandle[USB_MAX_INTERFACES];
    uint8_t interfaceIndex[USB_MAX_INTERFACES];
    uint8_t busNum;
    uint8_t devAddr;
    uint8_t interfaceCnt;
    bool initFlag;
};

struct RequestMsg {
    struct UsbRequest *request;
    void *clientData;
    uint32_t clientLength;
    void *buffer;
    uint32_t length;
};

struct UsbControlParams {
    uint8_t request;
    UsbRequestTargetType target;
    uint8_t reqType;
    UsbRequestDirection directon;
    uint16_t value;
    uint16_t index;
    void *data;
    uint16_t size;
};

struct UsbDescriptorParams {
    UsbInterfaceHandle *devHandle;
    struct UsbRequest *request;
    uint8_t type;
    uint8_t index;
    void *buf;
    uint16_t size;
};

struct UsbdService {
    struct IDeviceIoService service;
    struct HdfDeviceObject *device;
    struct UsbdSubscriber *subscriber;
    struct UsbSession *session;
    struct HdfSList devList;
    struct OsalMutex lock;
};

struct UsbdRequestSync {
    struct HdfSListNode node;
    struct UsbRequest *request;
    UsbInterfaceHandle *ifHandle;
    struct OsalMutex lock;
    struct UsbPipeInfo pipe;
    struct UsbRequestParams params;
    uint8_t endPointAddr;
};

struct UsbdRequestASync {
    struct HdfSListNode node;
    struct HdfSListNode qNode;
    UsbInterfaceHandle *ifHandle;
    struct RequestMsg reqMsg;
    struct OsalMutex lock;
    struct UsbPipeInfo pipe;
    struct UsbRequestParams params;
    uint8_t endPointAddr;
    uint8_t status;
};

struct UsbdSubscriber {
    sptr<IUsbdSubscriber> subscriber;
    void *impl;
    struct HdfDevEventlistener usbPnpListener;
    sptr<IRemoteObject> remote;
    void *deathRecipient;
};
} // namespace V1_1
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // USBD_H
