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

#include "ap_fuzzer.h"
#include "wlan_common_fuzzer.h"

namespace OHOS {
namespace WIFI {
constexpr size_t THRESHOLD = 10;
const char *g_wlanServiceName = "wlan_interface_service";
const int32_t WLAN_MAX_NUM_STA_WITH_AP = 4;
const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
struct IWlanInterface *g_wlanObj = nullptr;
uint32_t num = 0;

void FuzzGetAssociatedStas(struct IWlanInterface *interface, const uint8_t *rawData)
{
    struct HdfFeatureInfo feature;
    struct HdfStaInfo staInfo[WLAN_MAX_NUM_STA_WITH_AP] = {{0}};
    uint32_t staInfoLen = WLAN_MAX_NUM_STA_WITH_AP;
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));

    interface->GetAssociatedStas(interface, &feature, staInfo, &staInfoLen, &num);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzSetCountryCode(struct IWlanInterface *interface, const uint8_t *rawData)
{
    const char *mac = reinterpret_cast<const char *>(rawData);
    uint32_t macLen = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<uint32_t *>(reinterpret_cast<const uint32_t *>(rawData));

    interface->SetCountryCode(interface, &feature, mac, macLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetApBandwidth(struct IWlanInterface *interface, const uint8_t *rawData)
{
    const char *ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    uint8_t bandwidth;
    interface->GetApBandwidth(interface, ifName, &bandwidth);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

static FuzzWlanFuncs g_fuzzWlanFuncs[] = {
    FuzzGetAssociatedStas,
    FuzzSetCountryCode,
    FuzzGetApBandwidth,
    FuzzGetChipId,
    FuzzGetDeviceMacAddress,
    FuzzGetFeatureType,
    FuzzGetFreqsWithBand,
    FuzzGetNetworkIfaceName,
    FuzzSetMacAddress,
    FuzzSetTxPower,
    FuzzGetPowerMode,
    FuzzSetPowerMode,
    FuzzGetIfNamesByChipId,
    FuzzResetDriver,
    FuzzStartChannelMeas,
    FuzzSetProjectionScreenParam,
    FuzzWifiSendCmdIoctl,
    FuzzGetFeatureByIfName,
    FuzzGetStaInfo,
    FuzzGetChannelMeasResult,
    FuzzResetToFactoryMacAddress,
};

static void FuncToOptimal(struct IWlanInterface *interface, uint32_t cmdId, const uint8_t *data)
{
    FuzzWlanFuncs fuzzWlanFunc = g_fuzzWlanFuncs[cmdId];
    if (fuzzWlanFunc != nullptr) {
        fuzzWlanFunc(interface, data);
    }
    return;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    struct HdfFeatureInfo ifeature;
    bool result = false;

    if (rawData == nullptr || size == 0) {
        return false;
    }
    uint32_t cmdId = Convert2Uint32(rawData) % ((sizeof(g_fuzzWlanFuncs) / sizeof(g_fuzzWlanFuncs[0])));
    g_wlanObj = IWlanInterfaceGetInstance(g_wlanServiceName, false);
    if (g_wlanObj == nullptr) {
        HDF_LOGE("%{public}s: g_wlanObj is null", __FUNCTION__);
        return result;
    }
    uint32_t dataSize = size - OFFSET;
    uint8_t *tmpRawData = reinterpret_cast<uint8_t *>(OsalMemCalloc(dataSize + 1));
    if (tmpRawData == nullptr) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed!", __FUNCTION__);
        return result;
    }
    int32_t ret = g_wlanObj->Start(g_wlanObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Start failed! ret=%{public}d", __FUNCTION__, ret);
        OsalMemFree(tmpRawData);
        return result;
    }
    do {
        if (PreProcessRawData(rawData, size, tmpRawData, dataSize + 1) != true) {
            break;
        }
        ret = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: CreateFeature failed! ret=%{public}d", __FUNCTION__, ret);
            break;
        }
        FuncToOptimal(g_wlanObj, cmdId, tmpRawData);
        ret = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DestroyFeature failed! ret=%{public}d", __FUNCTION__, ret);
            break;
        }
        result = true;
    } while (false);
    ret = g_wlanObj->Stop(g_wlanObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Stop failed! ret=%{public}d", __FUNCTION__, ret);
        result = false;
    }
    IWlanInterfaceReleaseInstance(g_wlanServiceName, g_wlanObj, false);
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
