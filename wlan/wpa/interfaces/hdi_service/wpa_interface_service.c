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
#include "v2_0/iwpa_callback.h"
#include "v2_0/iwpa_interface.h"
#include "wpa_common_cmd.h"
#include "wpa_p2p_cmd.h"
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
    service->interface.RegisterWpaEventCallback = WpaInterfaceRegisterEventCallback;
    service->interface.UnregisterWpaEventCallback = WpaInterfaceUnregisterEventCallback;
    service->interface.GetConnectionCapabilities = WpaInterfaceGetConnectionCapabilities;
    service->interface.GetScanSsid = WpaInterfaceGetScanSsid;
    service->interface.GetPskPassphrase = WpaInterfaceGetPskPassphrase;
    service->interface.GetPsk = WpaInterfaceGetPsk;
    service->interface.GetWepKey = WpaInterfaceGetWepKey;
    service->interface.GetWepTxKeyIdx = WpaInterfaceGetWepTxKeyIdx;
    service->interface.GetRequirePmf = WpaInterfaceGetRequirePmf;
    service->interface.SetCountryCode = WpaInterfaceSetCountryCode;
    service->interface.Reassociate = WpaInterfaceReassociate;
    service->interface.StaShellCmd = WpaInterfaceStaShellCmd;

    service->interface.P2pSetSsidPostfixName = WpaInterfaceP2pSetSsidPostfixName;
    service->interface.P2pSetWpsDeviceType = WpaInterfaceP2pSetWpsDeviceType;
    service->interface.P2pSetWpsConfigMethods = WpaInterfaceP2pSetWpsConfigMethods;
    service->interface.P2pSetGroupMaxIdle = WpaInterfaceP2pSetGroupMaxIdle;
    service->interface.P2pSetWfdEnable = WpaInterfaceP2pSetWfdEnable;
    service->interface.P2pSetPersistentReconnect = WpaInterfaceP2pSetPersistentReconnect;
    service->interface.P2pSetWpsSecondaryDeviceType = WpaInterfaceP2pSetWpsSecondaryDeviceType;
    service->interface.P2pSetupWpsPbc = WpaInterfaceP2pSetupWpsPbc;
    service->interface.P2pSetupWpsPin = WpaInterfaceP2pSetupWpsPin;
    service->interface.P2pSetPowerSave = WpaInterfaceP2pSetPowerSave;
    service->interface.P2pSetDeviceName = WpaInterfaceP2pSetDeviceName;
    service->interface.P2pSetWfdDeviceConfig = WpaInterfaceP2pSetWfdDeviceConfig;
    service->interface.P2pSetRandomMac = WpaInterfaceP2pSetRandomMac;
    service->interface.P2pStartFind = WpaInterfaceP2pStartFind;
    service->interface.P2pSetExtListen = WpaInterfaceP2pSetExtListen;
    service->interface.P2pSetListenChannel = WpaInterfaceP2pSetListenChannel;
    service->interface.P2pProvisionDiscovery = WpaInterfaceP2pProvisionDiscovery;
    service->interface.P2pAddGroup = WpaInterfaceP2pAddGroup;
    service->interface.P2pAddService = WpaInterfaceP2pAddService;
    service->interface.P2pRemoveService = WpaInterfaceP2pRemoveService;
    service->interface.P2pStopFind = WpaInterfaceP2pStopFind;
    service->interface.P2pFlush = WpaInterfaceP2pFlush;
    service->interface.P2pFlushService = WpaInterfaceP2pFlushService;
    service->interface.P2pRemoveNetwork = WpaInterfaceP2pRemoveNetwork;
    service->interface.P2pSetGroupConfig = WpaInterfaceP2pSetGroupConfig;
    service->interface.P2pInvite = WpaInterfaceP2pInvite;
    service->interface.P2pReinvoke = WpaInterfaceP2pReinvoke;
    service->interface.P2pGetDeviceAddress = WpaInterfaceP2pGetDeviceAddress;
    service->interface.P2pReqServiceDiscovery = WpaInterfaceP2pReqServiceDiscovery;
    service->interface.P2pCancelServiceDiscovery = WpaInterfaceP2pCancelServiceDiscovery;
    service->interface.P2pRespServerDiscovery = WpaInterfaceP2pRespServerDiscovery;
    service->interface.P2pConnect = WpaInterfaceP2pConnect;
    service->interface.P2pHid2dConnect = WpaInterfaceP2pHid2dConnect;
    service->interface.P2pSetServDiscExternal = WpaInterfaceP2pSetServDiscExternal;
    service->interface.P2pRemoveGroup = WpaInterfaceP2pRemoveGroup;
    service->interface.P2pCancelConnect = WpaInterfaceP2pCancelConnect;
    service->interface.P2pGetGroupConfig = WpaInterfaceP2pGetGroupConfig;
    service->interface.P2pAddNetwork = WpaInterfaceP2pAddNetwork;
    service->interface.P2pGetPeer = WpaInterfaceP2pGetPeer;
    service->interface.P2pGetGroupCapability = WpaInterfaceP2pGetGroupCapability;
    service->interface.P2pListNetworks = WpaInterfaceP2pListNetworks;
    service->interface.DeliverP2pData = WpaInterfaceDeliverP2pData;
    service->interface.P2pSaveConfig = WpaInterfaceP2pSaveConfig;

    service->interface.VendorProcessCmd = WpaInterfaceVendorExtProcessCmd;
    service->interface.GetWpaStaData = WpaInterfaceGetWpaStaData;

    return &service->interface;
}

void WpaInterfaceImplRelease(struct IWpaInterface *instance)
{
    if (instance == NULL) {
        return;
    }
    OsalMemFree(instance);
}
