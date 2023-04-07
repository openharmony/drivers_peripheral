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

#ifndef OHOS_HDI_USB_DDK_V1_0_IUSBDDK_H
#define OHOS_HDI_USB_DDK_V1_0_IUSBDDK_H

#include <stdbool.h>
#include <stdint.h>
#include <hdf_base.h>

#include "inotification_callback.h"
#include "usb_ddk_inner_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HdfRemoteService;

#define IUSBDDK_INTERFACE_DESC "ohos.hdi.usb.ddk.v1_0.IUsbDdk"

#define IUSB_DDK_MAJOR_VERSION 1
#define IUSB_DDK_MINOR_VERSION 0

#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

#ifndef HDI_CHECK_VALUE_RET_GOTO
#define HDI_CHECK_VALUE_RET_GOTO(lv, compare, rv, ret, value, table) \
    do {                                                             \
        if ((lv)compare(rv)) {                                       \
            ret = value;                                             \
            goto table;                                              \
        }                                                            \
    } while (false)
#endif

enum {
    CMD_USB_DDK_INIT,
    CMD_USB_DDK_RELEASE,
    CMD_USB_DDK_REGISTER_NOTIFICATION,
    CMD_USB_DDK_UN_REGISTER_NOTIFICATION,
    CMD_USB_DDK_GET_DEVICE_DESCRIPTOR,
    CMD_USB_DDK_GET_CONFIG_DESCRIPTOR,
    CMD_USB_DDK_CLAIM_INTERFACE,
    CMD_USB_DDK_RELEASE_INTERFACE,
    CMD_USB_DDK_SELECT_INTERFACE_SETTING,
    CMD_USB_DDK_GET_CURRENT_INTERFACE_SETTING,
    CMD_USB_DDK_SEND_CONTROL_READ_REQUEST,
    CMD_USB_DDK_SEND_CONTROL_WRITE_REQUEST,
    CMD_USB_DDK_SEND_PIPE_READ_REQUEST,
    CMD_USB_DDK_SEND_PIPE_WRITE_REQUEST,
    CMD_USB_DDK_GET_VERSION,
};

struct IUsbDdk {
    int32_t (*init)(struct IUsbDdk *self);

    int32_t (*release)(struct IUsbDdk *self);

    int32_t (*registerNotification)(struct IUsbDdk *self, struct INotificationCallback *cb);

    int32_t (*unRegisterNotification)(struct IUsbDdk *self, struct INotificationCallback *cb);

    int32_t (*getDeviceDescriptor)(struct IUsbDdk *self, uint64_t devHandle, struct UsbDeviceDescriptor *desc);

    int32_t (*getConfigDescriptor)(
        struct IUsbDdk *self, uint64_t devHandle, uint8_t configIndex, uint8_t *configDesc, uint32_t *configDescLen);

    int32_t (*claimInterface)(struct IUsbDdk *self, uint64_t devHandle, uint8_t interfaceIndex,
        enum UsbClaimMode claimMode, uint64_t *interfaceHandle);

    int32_t (*releaseInterface)(struct IUsbDdk *self, uint64_t interfaceHandle);

    int32_t (*selectInterfaceSetting)(struct IUsbDdk *self, uint64_t interfaceHandle, uint8_t settingIndex);

    int32_t (*getCurrentInterfaceSetting)(struct IUsbDdk *self, uint64_t interfaceHandle, uint8_t *settingIndex);

    int32_t (*sendControlReadRequest)(struct IUsbDdk *self, uint64_t interfaceHandle,
        const struct UsbControlRequestSetup *setup, uint8_t *data, uint32_t *dataLen);

    int32_t (*sendControlWriteRequest)(struct IUsbDdk *self, uint64_t interfaceHandle,
        const struct UsbControlRequestSetup *setup, const uint8_t *data, uint32_t dataLen);

    int32_t (*sendPipeReadRequest)(
        struct IUsbDdk *self, const struct UsbRequestPipe *pipe, uint8_t *buffer, uint32_t *bufferLen);

    int32_t (*sendPipeWriteRequest)(struct IUsbDdk *self, const struct UsbRequestPipe *pipe, const uint8_t *buffer,
        uint32_t bufferLen, uint32_t *transferredLength);

    int32_t (*getVersion)(struct IUsbDdk *self, uint32_t *majorVer, uint32_t *minorVer);

    struct HdfRemoteService *(*asObject)(struct IUsbDdk *self);
};

// external method used to create client object, it support ipc and passthrought mode
struct IUsbDdk *IUsbDdkGet(bool isStub);
struct IUsbDdk *IUsbDdkGetInstance(const char *serviceName, bool isStub);

// external method used to create release object, it support ipc and passthrought mode
void IUsbDdkRelease(struct IUsbDdk *instance, bool isStub);
void IUsbDdkReleaseInstance(const char *serviceName, struct IUsbDdk *instance, bool isStub);
int32_t UsbDdkWapperGetConfigDescriptor(
    struct IUsbDdk *self, uint64_t devHandle, uint8_t configIndex, struct UsbDdkConfigDescriptor ** const config);
void UsbDdkFreeConfigDescriptor(const struct UsbDdkConfigDescriptor * const config);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_USB_DDK_V1_0_IUSBDDK_H