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

#ifndef OHOS_HDI_USB_DDK_V1_0_INOTIFICATIONCALLBACK_H
#define OHOS_HDI_USB_DDK_V1_0_INOTIFICATIONCALLBACK_H

#include <stdbool.h>
#include <stdint.h>
#include <hdf_base.h>

#include "usb_ddk_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define INOTIFICATIONCALLBACK_INTERFACE_DESC "ohos.hdi.usb.ddk.v1_0.INotificationCallback"

#define INOTIFICATION_CALLBACK_MAJOR_VERSION 1
#define INOTIFICATION_CALLBACK_MINOR_VERSION 0

#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

enum {
    CMD_NOTIFICATION_CALLBACK_ON_NOTIFICATION_CALLBACK,
    CMD_NOTIFICATION_CALLBACK_GET_VERSION,
};

// no external method used to create client object, it only support ipc mode
struct INotificationCallback *INotificationCallbackGet(struct HdfRemoteService *remote);

// external method used to release client object, it support ipc and passthrought mode
void INotificationCallbackRelease(struct INotificationCallback *instance);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_USB_DDK_V1_0_INOTIFICATIONCALLBACK_H