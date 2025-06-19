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
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include "v1_0/ihostapd_callback.h"
#include "v1_0/ihostapd_callback.h"
#include "hostapd_common_cmd.h"
#include "hostapd_impl.h"

struct HostapdInterfaceService {
    struct IHostapdInterface interface;
};

struct IHostapdInterface *HostapdInterfaceImplGetInstance(void)
{
    struct HostapdInterfaceService *service = (struct HostapdInterfaceService *)OsalMemCalloc(
        sizeof(struct HostapdInterfaceService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc HostapdInterfaceService obj failed!", __func__);
        return NULL;
    }
    service->interface.StartAp = HostapdInterfaceStartAp;
    service->interface.StartApWithCmd = HostapdInterfaceStartApWithCmd;
    service->interface.StopAp = HostapdInterfaceStopAp;
    service->interface.EnableAp = HostapdInterfaceEnableAp;
    service->interface.DisableAp = HostapdInterfaceDisableAp;
    service->interface.SetApPasswd = HostapdInterfaceSetApPasswd;
    service->interface.SetApName = HostapdInterfaceSetApName;
    service->interface.SetApWpaValue = HostapdInterfaceSetApWpaValue;
    service->interface.SetApBand = HostapdInterfaceSetApBand;
    service->interface.SetAp80211n = HostapdInterfaceSetAp80211n;
    service->interface.SetApWmm = HostapdInterfaceSetApWmm;
    service->interface.SetApChannel = HostapdInterfaceSetApChannel;
    service->interface.SetApMaxConn = HostapdInterfaceSetApMaxConn;
    service->interface.SetMacFilter = HostapdInterfaceSetMacFilter;
    service->interface.DelMacFilter = HostapdInterfaceDelMacFilter;
    service->interface.ReloadApConfigInfo = HostapdInterfaceReloadApConfigInfo;
    service->interface.GetStaInfos = HostapdInterfaceGetStaInfos;
    service->interface.DisassociateSta = HostapdInterfaceDisassociateSta;
    service->interface.RegisterEventCallback = HostapdInterfaceRegisterEventCallback;
    service->interface.UnregisterEventCallback = HostapdInterfaceUnregisterEventCallback;
    service->interface.HostApdShellCmd = HostApdInterfaceShellCmd;
    service->interface.GetVersion = HostapdGetVersion;
    return &service->interface;
}

void HostapdInterfaceImplRelease(struct IHostapdInterface *instance)
{
    if (instance == NULL) {
        return;
    }
    OsalMemFree(instance);
}
