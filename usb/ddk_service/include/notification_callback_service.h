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

#ifndef OHOS_HDI_USB_DDK_V1_0_NOTIFICATIONCALLBACKSERVICE_H
#define OHOS_HDI_USB_DDK_V1_0_NOTIFICATIONCALLBACKSERVICE_H

#include "inotification_callback.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct NotificationCallbackService {
    struct INotificationCallback interface;
};

struct INotificationCallback *NotificationCallbackServiceGet(void);

void NotificationCallbackServiceRelease(struct INotificationCallback *instance);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_USB_DDK_V1_0_NOTIFICATIONCALLBACKSERVICE_H