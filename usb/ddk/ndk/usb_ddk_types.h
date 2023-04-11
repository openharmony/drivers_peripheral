/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef USBDDKTYPES_H
#define USBDDKTYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define USB_MAXINTERFACES 32

typedef enum NotificationType {
    USB_DEVICE_ATTACH,
    USB_DEVICE_DETACH,
    USB_NOTIFICATION_UNKNOW,
} NotificationType;

typedef enum UsbClaimMode {
    USB_CLAIM_UNFORCE,
    USB_CLAIM_FORCE,
} UsbClaimMode;

typedef struct UsbControlRequestSetup {
    uint8_t requestType;
    uint8_t requestCmd;
    uint16_t value;
    uint16_t index;
    uint16_t length;
    uint32_t timeout;
} __attribute__((packed)) UsbControlRequestSetup;

typedef struct UsbDeviceDescriptor {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t bcdUSB;
    uint8_t bDeviceClass;
    uint8_t bDeviceSubClass;
    uint8_t bDeviceProtocol;
    uint8_t bMaxPacketSize0;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t iManufacturer;
    uint8_t iProduct;
    uint8_t iSerialNumber;
    uint8_t bNumConfigurations;
} __attribute__((packed)) UsbDeviceDescriptor;

typedef struct UsbConfigDescriptor {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t wTotalLength;
    uint8_t bNumInterfaces;
    uint8_t bConfigurationValue;
    uint8_t iConfiguration;
    uint8_t bmAttributes;
    uint8_t bMaxPower;
} __attribute__((packed)) UsbConfigDescriptor;

typedef struct UsbInterfaceDescriptor {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bInterfaceNumber;
    uint8_t bAlternateSetting;
    uint8_t bNumEndpoints;
    uint8_t bInterfaceClass;
    uint8_t bInterfaceSubClass;
    uint8_t bInterfaceProtocol;
    uint8_t iInterface;
} __attribute__((packed)) UsbInterfaceDescriptor;

typedef struct UsbEndpointDescriptor {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bEndpointAddress;
    uint8_t bmAttributes;
    uint16_t wMaxPacketSize;
    uint8_t bInterval;
    uint8_t bRefresh;
    uint8_t bSynchAddress;
} __attribute__((packed)) UsbEndpointDescriptor;

typedef struct UsbDdkEndpointDescriptor {
    struct UsbEndpointDescriptor endpointDescriptor;
    uint8_t *extra;
    uint32_t extraLength;
} UsbDdkEndpointDescriptor;

typedef struct UsbDdkInterfaceDescriptor {
    struct UsbInterfaceDescriptor interfaceDescriptor;
    struct UsbDdkEndpointDescriptor *endPoint;
    uint8_t *extra;
    uint32_t extraLength;
} UsbDdkInterfaceDescriptor;

typedef struct UsbDdkInterface {
    uint8_t numAltsetting;
    struct UsbDdkInterfaceDescriptor altsetting[];
} UsbDdkInterface;

typedef struct UsbDdkConfigDescriptor {
    struct UsbConfigDescriptor configDescriptor;
    struct UsbDdkInterface *interface[USB_MAXINTERFACES];
    uint8_t *extra;
    uint32_t extraLength;
} UsbDdkConfigDescriptor;

typedef struct UsbRequestPipe {
    uint64_t interfaceHandle;
    uint8_t endpoint;
    uint32_t timeout;
} __attribute__((packed)) UsbRequestPipe;

struct HdfRemoteService;
typedef struct INotificationCallback {
    int32_t (*OnNotificationCallback)(
        struct INotificationCallback *self, enum NotificationType type, uint64_t devHandle);

    int32_t (*getVersion)(struct INotificationCallback *self, uint32_t *majorVer, uint32_t *minorVer);

    struct HdfRemoteService *(*asObject)(struct INotificationCallback *self);
} INotificationCallback;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // USBDDKTYPES_H