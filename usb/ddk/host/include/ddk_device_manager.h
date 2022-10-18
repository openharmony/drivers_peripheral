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

#ifndef DDK_DEVICE_MANAGER_H
#include <stdint.h>

#include "hdf_usb_pnp_manage.h"
#ifdef __cplusplus
extern "C" {
#endif
#define USB_PNP_NOTIFY_SERVICE_NAME "hdf_usb_pnp_notify_service"
typedef int32_t (*DdkDevMgrHandleDev)(const struct UsbPnpNotifyMatchInfoTable *device, void *priv);
typedef int32_t (*DdkDevMgrHandleGadget)(void *priv);
/*
 * Init methed must be called before all other metheds
 * Success return 0, otherwise return non-zero
 */
int32_t DdkDevMgrInit(void);
const struct UsbPnpNotifyMatchInfoTable *DdkDevMgrCreateDevice(const char *deviceDir);
int32_t DdkDevMgrRemoveDevice(int32_t busNum, int32_t devNum, struct UsbPnpNotifyMatchInfoTable *info);
int32_t DdkDevMgrForEachDeviceSafe(DdkDevMgrHandleDev handle, void *priv);
int32_t DdkDevMgrGetGadgetLinkStatusSafe(DdkDevMgrHandleGadget handle, void *priv);
#ifdef __cplusplus
}
#endif
#define DDK_DEVICE_MANAGER_H
#endif // DDK_DEVICE_MANAGER_H
