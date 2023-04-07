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
#ifndef USB_DDK_API_H
#define USB_DDK_API_H
#include <stdint.h>

#include "usb_ddk_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t OH_Usb_Init();

void OH_Usb_Release();

int32_t OH_Usb_RegisterNotification(struct INotificationCallback *cb);

int32_t OH_Usb_UnRegisterNotification(struct INotificationCallback *cb);

int32_t OH_Usb_GetDeviceDescriptor(uint64_t devHandle, struct UsbDeviceDescriptor *desc);

int32_t OH_Usb_GetConfigDescriptor(
    uint64_t devHandle, uint8_t configIndex, struct UsbDdkConfigDescriptor ** const config);
void OH_Usb_FreeConfigDescriptor(const struct UsbDdkConfigDescriptor * const config);

int32_t OH_Usb_ClaimInterface(
    uint64_t devHandle, uint8_t interfaceIndex, enum UsbClaimMode claimMode, uint64_t *interfaceHandle);

int32_t OH_Usb_ReleaseInterface(uint64_t interfaceHandle);

int32_t OH_Usb_SelectInterfaceSetting(uint64_t interfaceHandle, uint8_t settingIndex);

int32_t OH_Usb_GetCurrentInterfaceSetting(uint64_t interfaceHandle, uint8_t *settingIndex);

int32_t OH_Usb_SendControlReadRequest(
    uint64_t interfaceHandle, const struct UsbControlRequestSetup *setup, uint8_t *data, uint32_t *dataLen);

int32_t OH_Usb_SendControlWriteRequest(
    uint64_t interfaceHandle, const struct UsbControlRequestSetup *setup, const uint8_t *data, uint32_t dataLen);

int32_t OH_Usb_SendPipeReadRequest(const struct UsbRequestPipe *pipe, uint8_t *buffer, uint32_t *bufferLen);

int32_t OH_Usb_SendPipeWriteRequest(
    const struct UsbRequestPipe *pipe, const uint8_t *buffer, uint32_t bufferLen, uint32_t *transferredLength);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // USB_DDK_API_H