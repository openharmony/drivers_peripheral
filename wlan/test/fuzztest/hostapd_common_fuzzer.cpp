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
#include "hostapd_common_fuzzer.h"

#define WLAN_FREQ_MAX_NUM 35
#define ETH_ADDR_LEN 6
#define BITS_NUM_24 24
#define BITS_NUM_16 16
#define BITS_NUM_8 8
#define BUFFSIZE_REQUEST 4096

static uint32_t g_wpaTestSize = 0;
struct IHostapdCallback *g_hostapdCallbackObj = nullptr;

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

void FuzzHostapdInterfaceStartAp(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    interface->StartAp(interface);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceStopAp(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    interface->StopAp(interface);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceEnableAp(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->EnableAp(interface, ifName, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceDisableAp(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->DisableAp(interface, ifName, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetApPasswd(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *pass = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetApPasswd(interface, ifName, pass, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetApName(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *name = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetApName(interface, ifName, name, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetApBand(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t band = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetApBand(interface, ifName, band, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetAp80211n(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t value = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetAp80211n(interface, ifName, value, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetApWmm(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t value = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetApWmm(interface, ifName, value, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetApChannel(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t channel = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetApChannel(interface, ifName, channel, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetApMaxConn(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t maxConn = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetApMaxConn(interface, ifName, maxConn, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceSetMacFilter(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *mac = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->SetMacFilter(interface, ifName, mac, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceDelMacFilter(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *mac = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->DelMacFilter(interface, ifName, mac, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceGetStaInfos(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    char buf[BUFFSIZE_REQUEST] = {0};
    uint32_t bufLen = *const_cast<uint32_t *>(reinterpret_cast<const uint32_t *>(rawData));
    int32_t size = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->GetStaInfos(interface, ifName, buf, bufLen, size, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceDisassociateSta(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    const char *mac = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    
    interface->DisassociateSta(interface, ifName, mac, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceRegisterEventCallback(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->RegisterEventCallback(interface, g_hostapdCallbackObj, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceUnregisterEventCallback(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);

    interface->UnregisterEventCallback(interface, g_hostapdCallbackObj, ifName);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}

void FuzzHostapdInterfaceReloadApConfigInfo(struct IHostapdInterface *interface, const uint8_t *rawData)
{
    const char *ifName = reinterpret_cast<const char *>(rawData);
    int32_t id = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));

    interface->ReloadApConfigInfo(interface, ifName, id);
    HDF_LOGI("%{public}s: success", __FUNCTION__);
}
