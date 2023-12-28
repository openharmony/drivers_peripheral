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
#include "v1_0/iwpa_interface.h"
#include "wpa_fuzzer.h"
#include "wpa_common_fuzzer.h"

namespace OHOS {
namespace WIFI {
constexpr size_t THRESHOLD = 10;
const char *g_wpaServiceName = "wpa_interface_service";
#define IFNAME "wlan0"
#define CONFNAME "/data/service/el1/public/wifi/wpa_supplicant/wpa_supplicant.conf"
struct IWpaInterface *g_wpaObj = nullptr;

static FuzzWpaFuncs g_fuzzWpaFuncs[] = {
    FuzzWpaInterfaceScan,
    FuzzWpaInterfaceScanResult,
    FuzzWpaInterfaceAddNetwork,
    FuzzWpaInterfaceRemoveNetwork,
    FuzzWpaInterfaceDisableNetwork,
    FuzzWpaInterfaceSetNetwork,
    FuzzWpaInterfaceReconnect,
    FuzzWpaInterfaceDisconnect,
    FuzzWpaInterfaceSelectNetwork,
    FuzzWpaInterfaceEnableNetwork,
    FuzzWpaInterfaceSetPowerSave,
    FuzzWpaInterfaceAutoConnect,
    FuzzWpaInterfaceSaveConfig,
    FuzzWpaInterfaceWpsCancel,
    FuzzWpaInterfaceGetCountryCode,
    FuzzWpaInterfaceGetNetwork,
    FuzzWpaInterfaceBlocklistClear,
    FuzzWpaInterfaceSetSuspendMode,
    FuzzWpaInterfaceGetScanSsid,
    FuzzWpaInterfaceGetPskPassphrase,
    FuzzWpaInterfaceGetPsk,
    FuzzWpaInterfaceGetWepKey,
    FuzzWpaInterfaceGetWepTxKeyIdx,
    FuzzWpaInterfaceGetRequirePmf,
    FuzzWpaInterfaceSetCountryCode,
    FuzzWpaInterfaceListNetworks,
    FuzzWpaInterfaceWifiStatus,
    FuzzWpaInterfaceWpsPbcMode,
    FuzzWpaInterfaceWpsPinMode,
    FuzzWpaInterfaceRegisterEventCallback,
    FuzzWpaInterfaceUnregisterEventCallback,
    FuzzWpaInterfaceGetConnectionCapabilities,
};

static void FuncToOptimal(struct IWpaInterface *interface, uint32_t cmdId, const uint8_t *data)
{
    FuzzWpaFuncs fuzzWpaFunc = g_fuzzWpaFuncs[cmdId];
    if (fuzzWpaFunc != nullptr) {
        fuzzWpaFunc(interface, data);
    }
    return;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    bool result = false;

    if (rawData == nullptr || size == 0) {
        return false;
    }
    uint32_t cmdId = Convert2Uint32(rawData) % ((sizeof(g_fuzzWpaFuncs) / sizeof(g_fuzzWpaFuncs[0])));
    g_wpaObj = IWpaInterfaceGetInstance(g_wpaServiceName, false);
    if (g_wpaObj == nullptr) {
        HDF_LOGE("%{public}s: g_wpaObj is null", __FUNCTION__);
        return result;
    }
    uint32_t dataSize = size - OFFSET;
    uint8_t *tmpRawData = reinterpret_cast<uint8_t *>(OsalMemCalloc(dataSize + 1));
    if (tmpRawData == nullptr) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed!", __FUNCTION__);
        return result;
    }
    int32_t ret = g_wpaObj->Start(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Start failed! ret=%{public}d", __FUNCTION__, ret);
        OsalMemFree(tmpRawData);
        return result;
    }
    do {
        if (PreProcessRawData(rawData, size, tmpRawData, dataSize + 1) != true) {
            break;
        }
        ret = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: CreateFeature failed! ret=%{public}d", __FUNCTION__, ret);
            break;
        }
        FuncToOptimal(g_wpaObj, cmdId, tmpRawData);
        ret = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DestroyFeature failed! ret=%{public}d", __FUNCTION__, ret);
            break;
        }
        result = true;
    } while (false);
    ret = g_wpaObj->Stop(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Stop failed! ret=%{public}d", __FUNCTION__, ret);
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
