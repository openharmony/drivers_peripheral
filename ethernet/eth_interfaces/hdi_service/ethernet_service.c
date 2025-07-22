/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
 
#include "v1_0/iethernet_callback.h"
#include "v1_0/iethernet.h"
#include "wpa_common_cmd.h"
#include "ethernet_impl.h"
 
struct EthernetService {
    struct IEthernet interface;
};
 
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "EthernetService"
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD0015b0
 
struct IEthernet *EthernetImplGetInstance(void)
{
    HDF_LOGI("%{public}s enter", __func__);
    struct EthernetService *service = (struct EthernetService *)OsalMemCalloc(sizeof(struct EthernetService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc failed!", __func__);
        return NULL;
    }
    service->interface.StartEap = EthStartEap;
    service->interface.StopEap = EthStopEap;
    service->interface.RegisterEapEventCallback = EthRegisterEapEventCallback;
    service->interface.UnregisterEapEventCallback = EthUnregisterEapEventCallback;
    service->interface.EapShellCmd = EthEapShellCmd;
    return &service->interface;
}
 
void EthernetImplRelease(struct IEthernet *instance)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (instance == NULL) {
        return;
    }
    OsalMemFree(instance);
}
