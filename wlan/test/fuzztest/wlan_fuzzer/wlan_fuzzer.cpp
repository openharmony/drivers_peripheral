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

#include "wlan_fuzzer.h"

#include "hdf_log.h"
#include "v1_0/iwlan_interface.h"
#include "v1_0/wlan_types.h"
#include "wifi_hal_base_feature.h"
#include "wlan_callback_impl.h"

#define HDF_LOG_TAG HDF_WIFI_CORE

namespace OHOS {
namespace WIFI {
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
const char *g_wlanServiceName = "wlan_interface_service";
const uint32_t ETH_ADDR_LEN = 6;
const int32_t WLAN_MAX_NUM_STA_WITH_AP = 4;
const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
struct HdfFeatureInfo ifeature;
struct IWlanInterface *g_wlanObj = nullptr;
uint32_t num = 0;

enum  WlanCmdId {
    CMD_WLAN_INTERFACE_GET_ASSCOCIATED_STAS,
    CMD_WLAN_INTERFACE_GET_DEVICE_MAC_ADDRESS,
};

uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

static void WlanFucSwitch(struct IWlanInterface *interface, uint32_t cmd, const uint8_t *rawData)
{
    switch (cmd) {
        case CMD_WLAN_INTERFACE_GET_ASSCOCIATED_STAS: {
            struct HdfStaInfo staInfo[WLAN_MAX_NUM_STA_WITH_AP] = {{0}};
            uint32_t staInfoLen = WLAN_MAX_NUM_STA_WITH_AP;
            ifeature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
            ifeature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
            interface->GetAssociatedStas(interface, &ifeature, staInfo, &staInfoLen, &num);
            break;
        }
        case CMD_WLAN_INTERFACE_GET_DEVICE_MAC_ADDRESS: {
            uint8_t mac[ETH_ADDR_LEN] = {0};
            uint32_t macLen = ETH_ADDR_LEN;
            ifeature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
            ifeature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
            interface->GetDeviceMacAddress(interface, &ifeature, mac, &macLen,
                *const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(rawData)));
            break;
        }
        default:
            break;
    }
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    (void)size;

    if (rawData == nullptr) {
        return false;
    }
    bool result = false;
    uint32_t cmd = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;

    g_wlanObj = IWlanInterfaceGetInstance(g_wlanServiceName, false);
    if (g_wlanObj == nullptr) {
        HDF_LOGE("%{public}s: g_wlanObj is null", __FUNCTION__);
        return result;
    }

    int32_t ret = g_wlanObj->Start(g_wlanObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Start failed! ret=%{public}d", __FUNCTION__, ret);
        IWlanInterfaceReleaseInstance(g_wlanServiceName, g_wlanObj, false);
        return result;
    }

    ret = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CreateFeature failed! ret=%{public}d", __FUNCTION__, ret);
        ret = g_wlanObj->Stop(g_wlanObj);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Stop failed! ret=%{public}d", __FUNCTION__, ret);
        }
        IWlanInterfaceReleaseInstance(g_wlanServiceName, g_wlanObj, false);
        return false;
    }

    WlanFucSwitch(g_wlanObj, cmd, rawData);

    ret = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DestroyFeature failed! ret=%{public}d", __FUNCTION__, ret);
        result = false;
    }

    ret = g_wlanObj->Stop(g_wlanObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Stop failed! ret=%{public}d", __FUNCTION__, ret);
        result = false;
    }

    IWlanInterfaceReleaseInstance(g_wlanServiceName, g_wlanObj, false);
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
