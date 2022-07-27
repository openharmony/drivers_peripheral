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

#ifndef DDK_PNP_LISTENER_MGR_H
#include "hdf_io_service_if.h"
#include "hdf_usb_pnp_manage.h"
#ifdef __cplusplus
extern "C" {
#endif

int32_t DdkListenerMgrInit();
int32_t DdkListenerMgrRemove(struct HdfDevEventlistener *listener);
int32_t DdkListenerMgrAdd(struct HdfDevEventlistener *listener);
void DdkListenerMgrNotifyAll(const struct UsbPnpNotifyMatchInfoTable *device, enum UsbPnpNotifyServiceCmd cmd);
#ifdef __cplusplus
}
#endif
#define DDK_PNP_LISTENER_MGR_H
#endif // DDK_PNP_LISTENER_MGR_H