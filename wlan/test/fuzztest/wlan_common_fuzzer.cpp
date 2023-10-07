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
#include "wlan_common_fuzzer.h"

#define WLAN_FREQ_MAX_NUM 35
#define ETH_ADDR_LEN 6
#define BITS_NUM_24 24
#define BITS_NUM_16 16
#define BITS_NUM_8 8

static uint32_t g_wlanTestSize = 0;

uint32_t SetWlanDataSize(const uint32_t *dataSize)
{
    if (dataSize != nullptr) {
        g_wlanTestSize = *dataSize;
        return HDF_SUCCESS;
    }
    HDF_LOGE("%{public}s: set data size failed!", __FUNCTION__);
    return HDF_FAILURE;
}

uint32_t GetWlanDataSize(uint32_t *dataSize)
{
    if (dataSize != nullptr) {
        *dataSize = g_wlanTestSize;
        return HDF_SUCCESS;
    }
    HDF_LOGE("%{public}s: get data size failed!", __FUNCTION__);
    return HDF_FAILURE;
}

uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[0] << BITS_NUM_24) | (ptr[1] << BITS_NUM_16) | (ptr[2] << BITS_NUM_8) | (ptr[3]);
}

bool PreProcessRawData(const uint8_t *rawData, size_t size, uint8_t *tmpRawData, size_t tmpRawDataSize)
{
    if (rawData == nullptr || tmpRawData == nullptr) {
        HDF_LOGE("%{public}s: rawData or tmpRawData is nullptr!", __FUNCTION__);
        return false;
    }
    uint32_t dataSize = size - OFFSET;
    if (memcpy_s(tmpRawData, tmpRawDataSize, rawData + OFFSET, dataSize) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed!", __FUNCTION__);
        return false;
    }
    if (SetWlanDataSize(&dataSize) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: set data size failed!", __FUNCTION__);
        return false;
    }
    return true;
}

void FuzzGetChipId(struct IWlanInterface *interface, const uint8_t *rawData)
{
    uint8_t chipId = 0;
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->GetChipId(interface, &feature, &chipId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetDeviceMacAddress(struct IWlanInterface *interface, const uint8_t *rawData)
{
    uint8_t mac[ETH_ADDR_LEN] = {0};
    uint32_t macLen = ETH_ADDR_LEN;
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->GetDeviceMacAddress(interface, &feature, mac, &macLen,
        *const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(rawData)));
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetFeatureType(struct IWlanInterface *interface, const uint8_t *rawData)
{
    int32_t featureType;
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->GetFeatureType(interface, &feature, &featureType);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetFreqsWithBand(struct IWlanInterface *interface, const uint8_t *rawData)
{
    struct HdfFeatureInfo feature;
    struct HdfWifiInfo wifiInfo;
    int32_t freq[WLAN_FREQ_MAX_NUM] = {0};
    uint32_t freqLen = WLAN_FREQ_MAX_NUM;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    wifiInfo.band = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    wifiInfo.size = *const_cast<uint32_t *>(reinterpret_cast<const uint32_t *>(rawData));

    interface->GetFreqsWithBand(interface, &feature, &wifiInfo, freq, &freqLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetNetworkIfaceName(struct IWlanInterface *interface, const uint8_t *rawData)
{
    char ifNames[IFNAMSIZ] = {0};
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->GetNetworkIfaceName(interface, &feature, ifNames, IFNAMSIZ);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzSetMacAddress(struct IWlanInterface *interface, const uint8_t *rawData)
{
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    const uint8_t *mac = rawData;
    uint32_t macLen = ETH_ADDR_LEN;

    interface->SetMacAddress(interface, &feature, mac, macLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzSetTxPower(struct IWlanInterface *interface, const uint8_t *rawData)
{
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t power = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetTxPower(interface, &feature, power);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetPowerMode(struct IWlanInterface *interface, const uint8_t *rawData)
{
    uint8_t mode = 0;
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->GetPowerMode(interface, &feature, &mode);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzSetPowerMode(struct IWlanInterface *interface, const uint8_t *rawData)
{
    struct HdfFeatureInfo feature;
    feature.ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    feature.type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    uint8_t mode = *const_cast<uint8_t *>(rawData);

    interface->SetPowerMode(interface, &feature, mode);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetIfNamesByChipId(struct IWlanInterface *interface, const uint8_t *rawData)
{
    uint32_t num = 0;
    char ifNames[IFNAMSIZ] = {0};
    uint8_t chipId = *const_cast<uint8_t *>(rawData);

    interface->GetIfNamesByChipId(interface, chipId, ifNames, IFNAMSIZ, &num);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzResetDriver(struct IWlanInterface *interface, const uint8_t *rawData)
{
    uint8_t chipId = *const_cast<uint8_t *>(rawData);
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->ResetDriver(interface, chipId, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzStartChannelMeas(struct IWlanInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct MeasChannelParam measChannelParam;
    measChannelParam.channelId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    measChannelParam.measTime = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->StartChannelMeas(interface, ifName, &measChannelParam);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzSetProjectionScreenParam(struct IWlanInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct ProjectionScreenCmdParam param;
    param.buf = const_cast<int8_t *>(reinterpret_cast<const int8_t *>(rawData));
    param.bufLen = g_wlanTestSize;
    param.cmdId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetProjectionScreenParam(interface, ifName, &param);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWifiSendCmdIoctl(struct IWlanInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t cmdId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int8_t *paramBuf = const_cast<int8_t *>(reinterpret_cast<const int8_t *>(rawData));

    interface->WifiSendCmdIoctl(interface, ifName, cmdId, paramBuf, g_wlanTestSize);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetFeatureByIfName(struct IWlanInterface *interface, const uint8_t *rawData)
{
    struct HdfFeatureInfo featureInfo;
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->GetFeatureByIfName(interface, ifName, &featureInfo);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetStaInfo(struct IWlanInterface *interface, const uint8_t *rawData)
{
    struct WifiStationInfo info;
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const uint8_t *mac = rawData;
    uint32_t macLen = ETH_ADDR_LEN;

    interface->GetStaInfo(interface, ifName, &info, mac, macLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzResetToFactoryMacAddress(struct IWlanInterface *interface, const uint8_t *rawData)
{
    const char *ifName = const_cast<char *>(reinterpret_cast<const char *>(rawData));
    interface->ResetToFactoryMacAddress(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzGetChannelMeasResult(struct IWlanInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct MeasChannelResult measChannelResult = {0};

    interface->GetChannelMeasResult(interface, ifName, &measChannelResult);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}
