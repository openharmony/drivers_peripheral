/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#ifndef USB_NET_HOST_H
#define USB_NET_HOST_H

#include "hdf_log.h"
#include "hdf_usb_net_manager.h"
#include "hdf_device_desc.h"

#include "data_fifo.h"
#include "usb_raw_api.h"
#include "usb_net_net.h"

#define USBNET_NW                  16
#define USBNET_NR                  44
#define USB_CTRL_REQ_SIZE          256
#define IFF_NOARP                  1 << 7

#define USB_IO_THREAD_STACK_SIZE      8192
#define USB_RAW_IO_SLEEP_MS_TIME      100
#define USB_RAW_IO_STOP_WAIT_MAX_TIME 3
#define HARCH_LOG_TAG                 "[-harch-hdf-]"

#define HARCH_INFO_PRINT(fmt, ...) \
do { \
    if (0){ \
        HDF_LOGI(HARCH_LOG_TAG"[%{public}s][%{public}d]:" fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);} \
}while (0)

enum UsbnetHostDeviceSpeed {
    USB_SPEED_UNKNOWN = 0,        /* enumerating */
    USB_SPEED_LOW,                /* usb 1.1  1.5M */
    USB_SPEED_FULL,               /* usb 1.1  12M */
    USB_SPEED_HIGH,               /* usb 2.0  480M */
    USB_SPEED_WIRELESS,
    USB_SPEED_SUPER,              /* usb 3.0 "5G" */
    USB_SPEED_SUPER_PLUS,         /* usb 3.0 "10G" */
};

//usb process
struct UsbnetHost;
struct UsbHostWb {
    struct UsbRawRequest *request;
    struct UsbnetHost *nNet;
    uint8_t *buf;
    uint32_t len;
    int32_t use;
};

struct UsbHostRb {
    uint8_t *base;
    int32_t size;
    int32_t index;
    int32_t use;
    struct UsbnetHost *nNet;
};

struct UsbEndpoint {
    uint8_t addr;
    uint8_t interval;
    uint16_t maxPacketSize;
};

typedef enum {
    USB_RAW_IO_PROCESS_RUNNING,
    USB_RAW_IO_PROCESS_STOP,
    USB_RAW_IO_PROCESS_STOPED
} UsbRawIoProcessStatusType;

/* interface from UsbnetHost core to each USB networking link we handle */
struct UsbnetHost {
    //usb info
    struct IDeviceIoService service;
    struct HdfDeviceObject *deviceObject;

    uint8_t curInterfaceNumber;
    uint8_t busNum;
    uint8_t devAddr;
    struct UsbSession *session;
    UsbRawHandle *devHandle;
    struct UsbRawConfigDescriptor *config;
    struct UsbRawInterfaceDescriptor *intf;
    struct UsbRawEndpointDescriptor *status;
    bool initFlag;
    int32_t flags;
    uint8_t ctrlIface;
    uint8_t dataIface;
    struct UsbEndpoint *statusEp;
    struct UsbEndpoint *dataInEp;
    struct UsbEndpoint *dataOutEp;
    uint32_t xid;
    //data process
    uint16_t rxQlen, txQlen;
    uint32_t canDmaSg : 1;
    uint8_t  *paddingPkt;
    struct DListHead  readPool;
    struct DListHead  readQueue;
    struct DListHead  writePool;
    struct DListHead  writeQueue;

    struct UsbHostWb wb[USBNET_NW];
    struct OsalMutex writeLock;
    struct OsalMutex readLock;
    struct UsbRawRequest *readReq[USBNET_NR];
    struct UsbRawRequest *statusReq;
    bool allocFlag;

    struct DataFifo readFifo;

    uint32_t nbIndex;
    uint32_t nbSize;
    int32_t transmitting;

    uint8_t *notificationBuffer;
    uint8_t readReqNum;

    struct UsbRawRequest *ctrlWriteReqSync;
    struct UsbRawRequest *ctrlReadReqSync;
    struct UsbRawRequest *ctrlWriteReqAsync;

    struct OsalMutex usbIoLock;
    UsbRawIoProcessStatusType usbIoStatus;
    struct OsalThread ioThread;
    //net info
    struct HdfIoService *hdfNetIoServ;
    struct HdfDevEventlistener *hdfNetListener;
    struct UsbnetTransInfo net;
    struct OsalMutex sendNetLock;
    //device info
    struct UsbnetHostDriverInfo *driverInfo;
};

/* interface from the device/framing level "minidriver" to core */
struct UsbnetHostDriverInfo {
    char    *description;
    int32_t flags;
    /* init device ... can sleep, or cause probe() failure */
    int32_t (*bind)(struct UsbnetHost *);
    void    (*unbind)(struct UsbnetHost *);
};

/* write or read command need param */
struct UsbnetHostCmdParam {
    uint8_t cmd;
    uint8_t reqtype;
    uint16_t value;
    uint16_t index;
    const void *data;
    uint16_t size;
};

void UsbnetWriteLog(char *buff, int size, int tag);

//net process
int32_t UsbnetHostProbe(struct UsbnetHost *uNet);

void UsbnetHostRelease(struct UsbnetHost *uNet);

//usb process
int32_t UsbnetHostWriteCmdSync(struct UsbnetHost *usbNet, struct UsbnetHostCmdParam cmdParm);

#endif
