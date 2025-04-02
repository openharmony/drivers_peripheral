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

#include <cerrno>
#include <cstdlib>
#include "securec.h"
#include "v2_0/iwpa_interface.h"
#include "wpa_fuzzer.h"
#include "wpa_common_fuzzer.h"
#include "servmgr_hdi.h"
#include "devmgr_hdi.h"
#include "hdf_remote_service.h"

namespace OHOS {
namespace WIFI {
constexpr size_t THRESHOLD = 10;
const char *g_wpaServiceName = "wpa_interface_service";
struct IWpaInterface *g_wpaObj = nullptr;
static struct HDIDeviceManager *g_devMgr = nullptr;

void FuzzWpaStart(struct IWpaInterface *gWpaObj, uint8_t *tmpRawData)
{
    FuzzWpaInterfaceStart(gWpaObj, tmpRawData);
    FuzzWpaInterfaceStop(gWpaObj, tmpRawData);
    FuzzWpaInterfaceScan(gWpaObj, tmpRawData);
    FuzzWpaInterfaceScanResult(gWpaObj, tmpRawData);
    FuzzWpaInterfaceAddNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceRemoveNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceDisableNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceSetNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceReconnect(gWpaObj, tmpRawData);
    FuzzWpaInterfaceDisconnect(gWpaObj, tmpRawData);
    FuzzWpaInterfaceSelectNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceEnableNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceSetPowerSave(gWpaObj, tmpRawData);
    FuzzWpaInterfaceAutoConnect(gWpaObj, tmpRawData);
    FuzzWpaInterfaceSaveConfig(gWpaObj, tmpRawData);
    FuzzWpaInterfaceWpsCancel(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetCountryCode(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceBlocklistClear(gWpaObj, tmpRawData);
    FuzzWpaInterfaceSetSuspendMode(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetScanSsid(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetPskPassphrase(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetPsk(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetWepKey(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetWepTxKeyIdx(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetRequirePmf(gWpaObj, tmpRawData);
    FuzzWpaInterfaceSetCountryCode(gWpaObj, tmpRawData);
    FuzzWpaInterfaceListNetworks(gWpaObj, tmpRawData);
    FuzzWpaInterfaceWifiStatus(gWpaObj, tmpRawData);
    FuzzWpaInterfaceWpsPbcMode(gWpaObj, tmpRawData);
    FuzzWpaInterfaceWpsPinMode(gWpaObj, tmpRawData);
    FuzzWpaInterfaceRegisterEventCallback(gWpaObj, tmpRawData);
    FuzzWpaInterfaceUnregisterEventCallback(gWpaObj, tmpRawData);
    FuzzWpaInterfaceGetConnectionCapabilities(gWpaObj, tmpRawData);
    FuzzWpaInterfaceAddWpaIface(gWpaObj, tmpRawData);
    FuzzWpaInterfaceRemoveWpaIface(gWpaObj, tmpRawData);
    FuzzWpaInterfaceReassociate(gWpaObj, tmpRawData);
    FuzzWpaInterfaceStaShellCmd(gWpaObj, tmpRawData);
}

void FuzzP2pStart(struct IWpaInterface *gWpaObj, uint8_t *tmpRawData)
{
    FuzzWpaInterfaceP2pSetSsidPostfixName(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWpsDeviceType(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWpsConfigMethods(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetGroupMaxIdle(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWfdEnable(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetPersistentReconnect(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWpsSecondaryDeviceType(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetupWpsPbc(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetupWpsPin(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetPowerSave(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetDeviceName(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWfdDeviceConfig(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetRandomMac(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pStartFind(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetExtListen(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetListenChannel(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pProvisionDiscovery(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pAddGroup(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pAddService(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRemoveService(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pStopFind(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pFlush(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pFlushService(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRemoveNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetGroupConfig(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pInvite(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pReinvoke(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetDeviceAddress(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pReqServiceDiscovery(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pCancelServiceDiscovery(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRespServerDiscovery(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pConnect(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pHid2dConnect(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetServDiscExternal(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRemoveGroup(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pCancelConnect(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetGroupConfig(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pAddNetwork(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetPeer(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetGroupCapability(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pListNetworks(gWpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSaveConfig(gWpaObj, tmpRawData);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    bool result = false;

    if (rawData == nullptr || size == 0) {
        return false;
    }
    g_devMgr = HDIDeviceManagerGet();
    if (g_devMgr == nullptr) {
        HDF_LOGE("%{public}s : g_wpaObj is null", __FUNCTION__);
        return result;
    }
    int32_t rc = g_devMgr->LoadDevice(g_devMgr, g_wpaServiceName);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : g_wpaObj is null", __FUNCTION__);
        return result;
    }
    g_wpaObj = IWpaInterfaceGetInstance(g_wpaServiceName, true);
    if (g_wpaObj == nullptr) {
        HDF_LOGE("%{public}s : g_wpaObj is null", __FUNCTION__);
        return result;
    }
    uint32_t dataSize = size - OFFSET;
    uint8_t *tmpRawData = reinterpret_cast<uint8_t *>(OsalMemCalloc(dataSize + 1));
    if (tmpRawData == nullptr) {
        HDF_LOGE("%{public}s : OsalMemCalloc failed!", __FUNCTION__);
        return result;
    }
    if (PreProcessRawData(rawData, size, tmpRawData, dataSize + 1) != true) {
        return result;
    }
    int32_t ret = g_wpaObj->Start(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : Start failed!", __FUNCTION__);
        OsalMemFree(tmpRawData);
        return result;
    }
    FuzzWpaStart(g_wpaObj, tmpRawData);
    FuzzP2pStart(g_wpaObj, tmpRawData);
    ret = g_wpaObj->Stop(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : Stop failed!", __FUNCTION__);
        result = false;
    }
    IWpaInterfaceReleaseInstance(g_wpaServiceName, g_wpaObj, true);
    OsalMemFree(tmpRawData);
    g_devMgr->UnloadDevice(g_devMgr, g_wpaServiceName);
    g_devMgr = nullptr;
    return result;
}
} // namespace WIFI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::WIFI::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::WIFI::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}