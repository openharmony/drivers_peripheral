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
#include "v1_0/iwpa_callback.h"
#include "v1_0/iwpa_interface.h"
#include "wpa_common_cmd.h"
#include "wpa_impl.h"

struct WpaInterfaceService {
    struct IWpaInterface interface;
};

struct IWpaInterface *WpaInterfaceImplGetInstance(void)
{
    struct WpaInterfaceService *service = (struct WpaInterfaceService *)OsalMemCalloc(
        sizeof(struct WpaInterfaceService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc WpaInterfaceService obj failed!", __func__);
        return NULL;
    }

    service->interface.Start = WpaInterfaceStart;
    service->interface.Stop = WpaInterfaceStop;
    service->interface.AddWpaIface = WpaInterfaceAddWpaIface;
    service->interface.RemoveWpaIface = WpaInterfaceRemoveWpaIface;
    service->interface.Scan = WpaInterfaceScan;
    service->interface.ScanResult= WpaInterfaceScanResult;
    service->interface.AddNetwork = WpaInterfaceAddNetwork;
    service->interface.RemoveNetwork = WpaInterfaceRemoveNetwork;
    service->interface.DisableNetwork = WpaInterfaceDisableNetwork;
    service->interface.SetNetwork = WpaInterfaceSetNetwork;
    service->interface.ListNetworks = WpaInterfaceListNetworks;
    service->interface.SelectNetwork = WpaInterfaceSelectNetwork;
    service->interface.EnableNetwork = WpaInterfaceEnableNetwork;
    service->interface.Reconnect = WpaInterfaceReconnect;
    service->interface.Disconnect = WpaInterfaceDisconnect;
    service->interface.SetPowerSave = WpaInterfaceSetPowerSave;
    service->interface.AutoConnect = WpaInterfaceAutoConnect;
    service->interface.WifiStatus  = WpaInterfaceWifiStatus;
    service->interface.SaveConfig = WpaInterfaceSaveConfig;
    service->interface.WpsPbcMode = WpaInterfaceWpsPbcMode;
    service->interface.WpsPinMode = WpaInterfaceWpsPinMode;
    service->interface.WpsCancel = WpaInterfaceWpsCancel;
    service->interface.GetCountryCode = WpaInterfaceGetCountryCode;
    service->interface.GetNetwork = WpaInterfaceGetNetwork;
    service->interface.BlocklistClear = WpaInterfaceBlocklistClear;
    service->interface.SetSuspendMode = WpaInterfaceSetSuspendMode;
    service->interface.RegisterEventCallback = WpaInterfaceRegisterEventCallback;
    service->interface.UnregisterEventCallback = WpaInterfaceUnregisterEventCallback;
    service->interface.GetConnectionCapabilities = WpaInterfaceGetConnectionCapabilities;
    service->interface.GetScanSsid = WpaInterfaceGetScanSsid;
    service->interface.GetPskPassphrase = WpaInterfaceGetPskPassphrase;
    service->interface.GetPsk = WpaInterfaceGetPsk;
    service->interface.GetWepKey = WpaInterfaceGetWepKey;
    service->interface.GetWepTxKeyIdx = WpaInterfaceGetWepTxKeyIdx;
    service->interface.GetRequirePmf = WpaInterfaceGetRequirePmf;
    service->interface.SetCountryCode = WpaInterfaceSetCountryCode;
    return &service->interface;
}

void WpaInterfaceImplRelease(struct IWpaInterface *instance)
{
    if (instance == NULL) {
        return;
    }
    OsalMemFree(instance);
}
