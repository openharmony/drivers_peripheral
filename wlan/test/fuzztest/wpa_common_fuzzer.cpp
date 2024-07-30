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
#include "wpa_common_fuzzer.h"

#define WLAN_FREQ_MAX_NUM 35
#define ETH_ADDR_LEN 6
#define BITS_NUM_24 24
#define BITS_NUM_16 16
#define BITS_NUM_8 8
#define REPLY_SIZE 1024

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

/* **********Wpa Interface********** */
void FuzzWpaInterfaceStart(struct IWpaInterface *interface, const uint8_t *rawData)
{
    interface->Start(interface);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceStop(struct IWpaInterface *interface, const uint8_t *rawData)
{
    interface->Stop(interface);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
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
    wpsParam.bssid = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * (wpsParam.bssidLen)));
    if (wpsParam.bssid == nullptr) {
        return;
    }
    wpsParam.bssid[0] = 0x12;
    wpsParam.bssid[1] = 0x34;
    wpsParam.bssid[2] = 0x56;
    wpsParam.bssid[3] = 0x78;
    wpsParam.bssid[4] = 0xab;
    wpsParam.bssid[5] = 0xcd;

    interface->WpsPbcMode(interface, ifName, &wpsParam);
    OsalMemFree(wpsParam.bssid);
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
    wpsParam.bssid = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * (wpsParam.bssidLen)));
    if (wpsParam.bssid == nullptr) {
        return;
    }
    wpsParam.bssid[0] = 0x12;
    wpsParam.bssid[1] = 0x34;
    wpsParam.bssid[2] = 0x56;
    wpsParam.bssid[3] = 0x78;
    wpsParam.bssid[4] = 0xab;
    wpsParam.bssid[5] = 0xcd;
    int pinCode = 0;

    interface->WpsPinMode(interface, ifName, &wpsParam, &pinCode);
    OsalMemFree(wpsParam.bssid);
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

void FuzzWpaInterfaceAddWpaIface(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *configname = "/data/service/el1/public/wifi/wpa_supplicant/wpa_supplicant.conf";
    interface->AddWpaIface(interface, ifName, configname);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceRemoveWpaIface(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->RemoveWpaIface(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceReassociate(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->Reassociate(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceStaShellCmd(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *cmd = reinterpret_cast<const char *>(rawData);
    
    interface->StaShellCmd(interface, ifName, cmd);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}


/* **********P2p Interface********** */
void FuzzWpaInterfaceP2pSetSsidPostfixName(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *name = reinterpret_cast<const char *>(rawData);

    interface->P2pSetSsidPostfixName(interface, ifName, name);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetWpsDeviceType(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *type = reinterpret_cast<const char *>(rawData);

    interface->P2pSetWpsDeviceType(interface, ifName, type);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetWpsConfigMethods(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *methods = reinterpret_cast<const char *>(rawData);

    interface->P2pSetWpsConfigMethods(interface, ifName, methods);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetGroupMaxIdle(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t time = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetGroupMaxIdle(interface, ifName, time);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetWfdEnable(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t enable = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetWfdEnable(interface, ifName, enable);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetPersistentReconnect(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t status = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetPersistentReconnect(interface, ifName, status);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetWpsSecondaryDeviceType(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *type = reinterpret_cast<const char *>(rawData);

    interface->P2pSetWpsSecondaryDeviceType(interface, ifName, type);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetupWpsPbc(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *address = reinterpret_cast<const char *>(rawData);

    interface->P2pSetupWpsPbc(interface, ifName, address);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetupWpsPin(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *address = reinterpret_cast<const char *>(rawData);
    const char *pin = reinterpret_cast<const char *>(rawData);
    char result[32] = {0};
    uint32_t resultLen = *const_cast<uint32_t *>(reinterpret_cast<const uint32_t *>(rawData));


    interface->P2pSetupWpsPin(interface, ifName, address, pin, result, resultLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetPowerSave(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t enable = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetPowerSave(interface, ifName, enable);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetDeviceName(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *name = reinterpret_cast<const char *>(rawData);

    interface->P2pSetDeviceName(interface, ifName, name);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetWfdDeviceConfig(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *config = reinterpret_cast<const char *>(rawData);

    interface->P2pSetWfdDeviceConfig(interface, ifName, config);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetRandomMac(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetRandomMac(interface, ifName, networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pStartFind(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t timeout = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pStartFind(interface, ifName, timeout);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetExtListen(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t enable = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t period = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t interval = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetExtListen(interface, ifName, enable, period, interval);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetListenChannel(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t channel = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t regClass = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetListenChannel(interface, ifName, channel, regClass);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pProvisionDiscovery(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *peerBssid = reinterpret_cast<const char *>(rawData);
    int32_t mode = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pProvisionDiscovery(interface, ifName, peerBssid, mode);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pAddGroup(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t isPersistent = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t freq = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pAddGroup(interface, ifName, isPersistent, networkId, freq);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pAddService(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiP2pServiceInfo info = {0};
    (void)memset_s(&info, sizeof(struct HdiP2pServiceInfo), 0, sizeof(struct HdiP2pServiceInfo));
    info.mode = 0;
    info.version = 0;
    const int nameLen = 32;
    const int paramLen = 1;
    info.nameLen = nameLen;
    info.queryLen = paramLen;
    info.respLen = paramLen;
    info.name = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * nameLen));
    info.query = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * paramLen));
    info.resp = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * paramLen));
    if (info.name == nullptr || info.query == nullptr || info.resp == nullptr) {
        HDF_LOGI("%{public}s: OsalMemCalloc fail", __FUNCTION__);
        return;
    }
    strcpy_s((char *)info.name, sizeof(info.name), "p2p0");

    interface->P2pAddService(interface, ifName, &info);
    OsalMemFree(info.name);
    OsalMemFree(info.query);
    OsalMemFree(info.resp);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pRemoveService(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiP2pServiceInfo info = {0};
    (void)memset_s(&info, sizeof(struct HdiP2pServiceInfo), 0, sizeof(struct HdiP2pServiceInfo));
    info.mode = 0;
    info.version = 0;
    const int nameLen = 32;
    const int paramLen = 1;
    info.nameLen = nameLen;
    info.queryLen = paramLen;
    info.respLen = paramLen;
    info.name = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * nameLen));
    info.query = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * paramLen));
    info.resp = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * paramLen));
    if (info.name == nullptr || info.query == nullptr || info.resp == nullptr) {
        HDF_LOGI("%{public}s: OsalMemCalloc fail", __FUNCTION__);
        return;
    }
    strcpy_s((char *)info.name, sizeof(info.name), "p2p0");

    interface->P2pRemoveService(interface, ifName, &info);
    OsalMemFree(info.name);
    OsalMemFree(info.query);
    OsalMemFree(info.resp);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pStopFind(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->P2pStopFind(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pFlush(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->P2pFlush(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pFlushService(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->P2pFlushService(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pRemoveNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pRemoveNetwork(interface, ifName, networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetGroupConfig(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    const char *name = reinterpret_cast<const char *>(rawData);
    const char *value = reinterpret_cast<const char *>(rawData);

    interface->P2pSetGroupConfig(interface, ifName, networkId, name, value);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pInvite(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *peerBssid = reinterpret_cast<const char *>(rawData);
    const char *goBssid = reinterpret_cast<const char *>(rawData);

    interface->P2pInvite(interface, ifName, peerBssid, goBssid);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pReinvoke(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *bssid = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pReinvoke(interface, ifName, networkId, bssid);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pGetDeviceAddress(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    char deviceAddress[32] = {0};
    uint32_t deviceAddressLen = *const_cast<uint32_t *>(reinterpret_cast<const uint32_t *>(rawData));

    interface->P2pGetDeviceAddress(interface, ifName, deviceAddress, deviceAddressLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pReqServiceDiscovery(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    char *replyDisc = static_cast<char *>(calloc(REPLY_SIZE, sizeof(char)));
    if (replyDisc == nullptr) {
        return;
    }
    uint32_t replyDiscLen = REPLY_SIZE;
    struct HdiP2pReqService reqService;
    (void)memset_s(&reqService, sizeof(struct HdiP2pReqService), 0, sizeof(struct HdiP2pReqService));
    reqService.bssidLen = ETH_ADDR_LEN;
    reqService.bssid = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * (reqService.bssidLen)));
    if (reqService.bssid == nullptr) {
        free(replyDisc);
        return;
    }
    reqService.bssid[0] = 0x12;
    reqService.bssid[1] = 0x34;
    reqService.bssid[2] = 0x56;
    reqService.bssid[3] = 0x78;
    reqService.bssid[4] = 0xab;
    reqService.bssid[5] = 0xcd;

    interface->P2pReqServiceDiscovery(interface, ifName, &reqService, replyDisc, replyDiscLen);
    free(replyDisc);
    OsalMemFree(reqService.bssid);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pCancelServiceDiscovery(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *id = reinterpret_cast<const char *>(rawData);

    interface->P2pCancelServiceDiscovery(interface, ifName, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pRespServerDiscovery(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiP2pServDiscReqInfo info;
    (void)memset_s(&info, sizeof(struct HdiP2pServDiscReqInfo), 0, sizeof(struct HdiP2pServDiscReqInfo));

    interface->P2pRespServerDiscovery(interface, ifName, &info);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pConnect(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiP2pConnectInfo info;
    (void)memset_s(&info, sizeof(struct HdiP2pConnectInfo), 0, sizeof(struct HdiP2pConnectInfo));
    char *replyPin = static_cast<char *>(calloc(REPLY_SIZE, sizeof(char)));
    if (replyPin == nullptr) {
        return;
    }
    uint32_t replyPinLen = REPLY_SIZE;

    interface->P2pConnect(interface, ifName, &info, replyPin, replyPinLen);
    free(replyPin);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pHid2dConnect(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const int macAddrIndexOne = 0;
    const int macAddrIndexTwo = 1;
    const int macAddrIndexThree = 2;
    const int macAddrIndexFour = 3;
    const int macAddrIndexFive = 4;
    const int macAddrIndexSix = 5;
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiHid2dConnectInfo info;
    (void)memset_s(&info, sizeof(struct HdiHid2dConnectInfo), 0, sizeof(struct HdiHid2dConnectInfo));
    info.bssidLen = ETH_ADDR_LEN;
    info.bssid = static_cast<uint8_t *>(OsalMemCalloc(sizeof(uint8_t) * (info.bssidLen)));
    if (info.bssid == nullptr) {
        return;
    }
    info.bssid[macAddrIndexOne] = 0x00;
    info.bssid[macAddrIndexTwo] = 0x00;
    info.bssid[macAddrIndexThree] = 0x00;
    info.bssid[macAddrIndexFour] = 0x00;
    info.bssid[macAddrIndexFive] = 0x00;
    info.bssid[macAddrIndexSix] = 0x00;
    interface->P2pHid2dConnect(interface, ifName, &info);
    OsalMemFree(info.bssid);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSetServDiscExternal(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t mode = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pSetServDiscExternal(interface, ifName, mode);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pRemoveGroup(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *groupName = reinterpret_cast<const char *>(rawData);

    interface->P2pRemoveGroup(interface, ifName, groupName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pCancelConnect(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->P2pCancelConnect(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pGetGroupConfig(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    const char *param = reinterpret_cast<const char *>(rawData);
    char value[32] = {0};
    uint32_t valueLen = *const_cast<uint32_t *>(reinterpret_cast<const uint32_t *>(rawData));

    interface->P2pGetGroupConfig(interface, ifName, networkId, param, value, valueLen);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pAddNetwork(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t networkId = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pAddNetwork(interface, ifName, &networkId);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pGetPeer(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *bssid = reinterpret_cast<const char *>(rawData);
    struct HdiP2pDeviceInfo info;
    (void)memset_s(&info, sizeof(struct HdiP2pDeviceInfo), 0, sizeof(struct HdiP2pDeviceInfo));

    interface->P2pGetPeer(interface, ifName, bssid, &info);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pGetGroupCapability(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *bssid = reinterpret_cast<const char *>(rawData);
    int32_t cap = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->P2pGetGroupCapability(interface, ifName, bssid, &cap);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pListNetworks(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    struct HdiP2pNetworkList infoList;
    (void)memset_s(&infoList, sizeof(struct HdiP2pNetworkList), 0, sizeof(struct HdiP2pNetworkList));

    interface->P2pListNetworks(interface, ifName, &infoList);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzWpaInterfaceP2pSaveConfig(struct IWpaInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->P2pSaveConfig(interface, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}
