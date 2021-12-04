/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "osal_atomic.h"
#include "osal_sem.h"
#include "usb_ddk.h"
#include "usb_ddk_interface.h"
#include "usb_session.h"
#include "usbd_publisher.h"
#include "usbd_type.h"

#define USB_MAX_INTERFACES 32
#define DIRECTION_MASK 0x1
#define USB_CTRL_SET_TIMEOUT 5000
#define USB_PIPE_DIR_OFFSET 7

struct UsbdService;
struct HostDevice {
    struct HdfSListNode node;
    struct UsbdService *service;
    struct DataFifo readFifo;
    struct HdfSList requestQueue;
    struct OsalMutex requestLock;
    uint8_t interfaceIndex[USB_MAX_INTERFACES];
    uint8_t interfaceCnt;
    struct UsbInterface *iface[USB_MAX_INTERFACES];
    UsbInterfaceHandle *ctrDevHandle;
    UsbInterfaceHandle *devHandle[USB_MAX_INTERFACES];
    struct OsalMutex writeLock;
    struct OsalMutex readLock;
    struct OsalMutex lock;
    struct UsbRequest *ctrlReq;
    struct UsbInterface *ctrIface;
    struct UsbPipeInfo *ctrPipe;
    uint8_t busNum;
    uint8_t devAddr;
    bool initFlag;
};

struct RequestMsg {
    struct HdfSListNode node;
    struct UsbRequest *request;
    void *clientData;
    uint32_t clientLength;
};

struct UsbControlParams {
    uint8_t request;
    UsbRequestTargetType target;
    UsbControlRequestType reqType;
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

struct UsbdSubscriber;
int32_t BindUsbSubscriber(struct UsbdService *service, struct UsbdSubscriber *subscriber);
int32_t UnbindUsbSubscriber(struct UsbdService *service);

#endif // USBD_H
