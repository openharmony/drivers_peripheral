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
#include "wpa_common_fuzzer.h"

#define WLAN_FREQ_MAX_NUM 35
#define ETH_ADDR_LEN 6
#define BITS_NUM_24 24
#define BITS_NUM_16 16
#define BITS_NUM_8 8

static uint32_t g_wpaTestSize = 0;
struct IWpaCallback *g_wpaCallbackObj = nullptr;

uint32_t SetWpaDataSize(const uint32_t *dataSize)
{
    if (dataSize != nullptr) {
        g_wpaTestSize = *dataSize;
        return HDF_SUCCESS;
    }
    HDF_LOGE("%{public}s: set data size failed!", __FUNCTION__);
    return HDF_FAILURE;
}

uint32_t GetWpaDataSize(uint32_t *dataSize)
{
    if (dataSize != nullptr) {
        *dataSize = g_wpaTestSize;
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
    if (SetWpaDataSize(&dataSize) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: set data size failed!", __FUNCTION__);
        return false;
    }
    return true;
}

void FuzzWpaInterfaceScan(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->Scan(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceScanResult(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    unsigned char buf[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    uint32_t bufLen = ETH_ADDR_LEN;
    interface->ScanResult(interface, ifName, buf, &bufLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceAddNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->AddNetwork(interface, ifName, &networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceRemoveNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    
    interface->RemoveNetwork(interface, ifName, networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceDisableNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->DisableNetwork(interface, ifName, networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceSetNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *name = reinterpret_cast<const char *>(rawData);
    const char *value = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetNetwork(interface, ifName, networkId, name, value);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceReconnect(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->Reconnect(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceDisconnect(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->Disconnect(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceSelectNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SelectNetwork(interface, ifName, networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceEnableNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->EnableNetwork(interface, ifName, networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceSetPowerSave(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t enable = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetPowerSave(interface, ifName, enable);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceAutoConnect(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t enable = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->AutoConnect(interface, ifName, enable);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceSaveConfig(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->SaveConfig(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceWpsCancel(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->WpsCancel(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetCountryCode(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    char countryCode[3] = {0};

    interface->GetCountryCode(interface, ifName, countryCode, 3);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int networkId = 0;
    char value[32] = {0};

    interface->GetNetwork(interface, ifName, networkId, "ssid", value, 32);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceBlocklistClear(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->BlocklistClear(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceSetSuspendMode(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t mode = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetSuspendMode(interface, ifName, mode);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetScanSsid(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t enable = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->GetScanSsid(interface, ifName, &enable);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetPskPassphrase(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    char psk[32] = {0};

    interface->GetPskPassphrase(interface, ifName, psk, 32);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetPsk(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    uint8_t psk[32] = {0};
    uint32_t pskLen = 32;

    interface->GetPsk(interface, ifName, psk, &pskLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetWepKey(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    uint8_t wepKey[16] = {0};
    uint32_t wepKeyLen = 16;

    interface->GetWepKey(interface, ifName, 1, wepKey, &wepKeyLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetWepTxKeyIdx(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int keyIdx = *const_cast<int *>(reinterpret_cast<const int *>(rawData));

    interface->GetWepTxKeyIdx(interface, ifName, &keyIdx);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetRequirePmf(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int enable = *const_cast<int *>(reinterpret_cast<const int *>(rawData));

    interface->GetRequirePmf(interface, ifName, &enable);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceSetCountryCode(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char countryCode[3] = {0};

    interface->SetCountryCode(interface, ifName, countryCode);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceListNetworks(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiWifiWpaNetworkInfo networkInfo;
    (void)memset_s(&networkInfo, sizeof(struct HdiWifiWpaNetworkInfo), 0, sizeof(struct HdiWifiWpaNetworkInfo));
    uint32_t networkInfoLen = 0;

    interface->ListNetworks(interface, ifName, (struct HdiWifiWpaNetworkInfo *)&networkInfo, &networkInfoLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceWifiStatus(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiWpaCmdStatus wifiStatus;
    (void)memset_s(&wifiStatus, sizeof(struct HdiWpaCmdStatus), 0, sizeof(struct HdiWpaCmdStatus));

    interface->WifiStatus(interface, ifName, &wifiStatus);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceWpsPbcMode(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiWifiWpsParam wpsParam;
    (void)memset_s(&wpsParam, sizeof(struct HdiWifiWpsParam), 0, sizeof(struct HdiWifiWpsParam));
    wpsParam.anyFlag = 1;
    wpsParam.multiAp = 1;
    wpsParam.bssidLen = 6;
    wpsParam.bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (wpsParam.bssidLen));
    wpsParam.bssid[0] = 0x12;
    wpsParam.bssid[1] = 0x34;
    wpsParam.bssid[2] = 0x56;
    wpsParam.bssid[3] = 0x78;
    wpsParam.bssid[4] = 0xab;
    wpsParam.bssid[5] = 0xcd;

    interface->WpsPbcMode(interface, ifName, &wpsParam);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceWpsPinMode(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiWifiWpsParam wpsParam;
    (void)memset_s(&wpsParam, sizeof(struct HdiWifiWpsParam), 0, sizeof(struct HdiWifiWpsParam));
    wpsParam.anyFlag = 1;
    wpsParam.multiAp = 1;
    wpsParam.bssidLen = 6;
    wpsParam.bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (wpsParam.bssidLen));
    wpsParam.bssid[0] = 0x12;
    wpsParam.bssid[1] = 0x34;
    wpsParam.bssid[2] = 0x56;
    wpsParam.bssid[3] = 0x78;
    wpsParam.bssid[4] = 0xab;
    wpsParam.bssid[5] = 0xcd;
    int pinCode = 0;

    interface->WpsPinMode(interface, ifName, &wpsParam, &pinCode);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceRegisterEventCallback(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->RegisterEventCallback(interface, g_wpaCallbackObj, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceUnregisterEventCallback(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->UnregisterEventCallback(interface, g_wpaCallbackObj, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceGetConnectionCapabilities(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct ConnectionCapabilities connectionCap;
    (void)memset_s(&connectionCap, sizeof(struct ConnectionCapabilities), 0, sizeof(struct ConnectionCapabilities));

    interface->GetConnectionCapabilities(interface, ifName, &connectionCap);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}