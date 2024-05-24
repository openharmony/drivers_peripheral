/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_WLAN_V1_2_WLANCALLBACKSERVICE_H
#define OHOS_HDI_WLAN_V1_2_WLANCALLBACKSERVICE_H

#include "v1_1/iwpa_callback.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

struct WpaCallbackService {
    struct IWpaCallback interface;
};

struct IWpaCallback *WpaCallbackServiceGet(void);
void WpaCallbackServiceRelease(struct IWpaCallback *instance);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_WLAN_V1_2_WLANCALLBACKSERVICE_H