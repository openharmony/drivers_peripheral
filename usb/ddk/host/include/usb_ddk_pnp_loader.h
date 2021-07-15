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

#ifndef USB_DDK_PNP_LOADER_H
#define USB_DDK_PNP_LOADER_H

#include "devmgr_service_if.h"
#include "hdf_usb_pnp_manage.h"

#define USB_PNP_NOTIFY_SERVICE_NAME "hdf_usb_pnp_notify_service"

typedef enum {
    USB_PNP_NORMAL_STATUS,
    USB_PNP_ADD_STATUS,
    USB_PNP_REMOVE_STATUS
} UsbPnpDriverStatus;

struct UsbPnpMatchIdTable {
    const char *moduleName;
    const char *serviceName;
    const char *deviceMatchAttr;

    int32_t interfaceClassLength;
    int32_t interfaceClassMask;
    int32_t interfaceSubClassLength;
    int32_t interfaceSubClassMask;
    int32_t interfaceProtocolLength;
    int32_t interfaceProtocolMask;
    int32_t interfaceLength;
    int32_t interfaceMask;

    uint8_t pnpMatchFlag;

    uint8_t length;

    uint16_t matchFlag;

    uint16_t vendorId;
    uint16_t productId;

    uint16_t bcdDeviceLow;
    uint16_t bcdDeviceHigh;

    uint8_t deviceClass;
    uint8_t deviceSubClass;
    uint8_t deviceProtocol;

    uint8_t interfaceClass[USB_PNP_INFO_MAX_INTERFACES];
    uint8_t interfaceSubClass[USB_PNP_INFO_MAX_INTERFACES];
    uint8_t interfaceProtocol[USB_PNP_INFO_MAX_INTERFACES];

    uint8_t interfaceNumber[USB_PNP_INFO_MAX_INTERFACES];
};

struct UsbPnpDeviceListTable {
    struct DListHead list;
    const char *moduleName;
    const char *serviceName;
    const char *deviceMatchAttr;
    UsbPnpDriverStatus status;
    uint32_t usbDevAddr;
    int32_t devNum;
    int32_t busNum;
    int32_t interfaceLength;
    uint8_t interfaceNumber[USB_PNP_INFO_MAX_INTERFACES];
};

struct UsbPnpRemoveInfo {
    uint8_t removeType;
    uint32_t usbDevAddr;
    int32_t devNum;
    int32_t busNum;
    uint8_t interfaceNum;
};

int UsbDdkPnpLoaderEventReceived(void *priv, uint32_t id, struct HdfSBuf *data);
int UsbDdkPnpLoaderEventHandle(void);

#endif /* USB_DDK_PNP_LOADER_H */
