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
#include "drivers/peripheral/wlan/wpa/interfaces/hdi_service/service_common/wpa_common_cmd.h"
#include "v1_0/iwpa_interface.h"
#include "wpa_fuzzer.h"
#include "wpa_common_fuzzer.h"

namespace OHOS {
namespace WIFI {
constexpr size_t THRESHOLD = 10;
const char *g_wpaServiceName = "wpa_interface_service";
struct IWpaInterface *g_wpaObj = nullptr;

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    bool result = false;

    if (rawData == nullptr || size == 0) {
        return false;
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
    int32_t ret = g_wpaObj->Start(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : Start failed!", __FUNCTION__);
        OsalMemFree(tmpRawData);
        return result;
    }
    FuzzWpaInterfaceStart(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceStop(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceScan(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceScanResult(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceAddNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceRemoveNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceDisableNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceSetNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceReconnect(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceDisconnect(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceSelectNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceEnableNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceSetPowerSave(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceAutoConnect(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceSaveConfig(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceWpsCancel(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetCountryCode(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceBlocklistClear(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceSetSuspendMode(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetScanSsid(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetPskPassphrase(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetPsk(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetWepKey(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetWepTxKeyIdx(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetRequirePmf(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceSetCountryCode(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceListNetworks(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceWifiStatus(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceWpsPbcMode(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceWpsPinMode(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceRegisterEventCallback(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceUnregisterEventCallback(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceGetConnectionCapabilities(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceAddWpaIface(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceRemoveWpaIface(g_wpaObj, tmpRawData);

    FuzzWpaInterfaceP2pSetSsidPostfixName(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWpsDeviceType(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWpsConfigMethods(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetGroupMaxIdle(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWfdEnable(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetPersistentReconnect(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWpsSecondaryDeviceType(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetupWpsPbc(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetupWpsPin(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetPowerSave(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetDeviceName(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetWfdDeviceConfig(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetRandomMac(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pStartFind(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetExtListen(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetListenChannel(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pProvisionDiscovery(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pAddGroup(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pAddService(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRemoveService(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pStopFind(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pFlush(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pFlushService(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRemoveNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetGroupConfig(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pInvite(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pReinvoke(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetDeviceAddress(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pReqServiceDiscovery(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pCancelServiceDiscovery(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRespServerDiscovery(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pConnect(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pHid2dConnect(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSetServDiscExternal(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pRemoveGroup(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pCancelConnect(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetGroupConfig(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pAddNetwork(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetPeer(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pGetGroupCapability(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pListNetworks(g_wpaObj, tmpRawData);
    FuzzWpaInterfaceP2pSaveConfig(g_wpaObj, tmpRawData);

    ret = g_wpaObj->Stop(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : Stop failed!", __FUNCTION__);
        result = false;
    }
    IWpaInterfaceReleaseInstance(g_wpaServiceName, g_wpaObj, false);
    OsalMemFree(tmpRawData);
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
