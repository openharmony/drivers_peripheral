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
#include "v1_0/ihostapd_interface.h"
#include "hostapd_fuzzer.h"
#include "hostapd_common_fuzzer.h"
#include "servmgr_hdi.h"
#include "devmgr_hdi.h"
#include "hdf_remote_service.h"

namespace OHOS {
namespace WIFI {
constexpr size_t THRESHOLD = 10;
const char *g_wpaServiceName = "hostapd_interface_service";
struct IHostapdInterface *g_wpaObj = nullptr;
static struct HDIDeviceManager *g_devMgr = nullptr;

void FuzzHostapdStart(struct IHostapdInterface *gWpaObj, uint8_t *tmpRawData)
{
    HDF_LOGI("%{public}s : is starting", __FUNCTION__);
    FuzzHostapdInterfaceSetApPasswd(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApName(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApBand(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApChannel(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApMaxConn(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceSetAp80211n(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApWmm(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceReloadApConfigInfo(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceDisableAp(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceEnableAp(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceSetMacFilter(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceDelMacFilter(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceGetStaInfos(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceDisassociateSta(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceRegisterEventCallback(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceUnregisterEventCallback(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceStartAp(gWpaObj, tmpRawData);
    FuzzHostapdInterfaceStopAp(gWpaObj, tmpRawData);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    HDF_LOGI("%{public}s: enter", __FUNCTION__);
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
    g_wpaObj = IHostapdInterfaceGetInstance(g_wpaServiceName, true);
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
        HDF_LOGE("%{public}s : PreProcessRawData failed!", __FUNCTION__);
        OsalMemFree(tmpRawData);
        return result;
    }
    int32_t ret = g_wpaObj->StartApWithCmd(g_wpaObj, "wlan1", 0);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : StartApWithCmd failed!", __FUNCTION__);
        OsalMemFree(tmpRawData);
        return result;
    }
    HDF_LOGE("%{public}s :StartApWithCmd sucess", __FUNCTION__);
    FuzzHostapdStart(g_wpaObj, tmpRawData);
    IHostapdInterfaceReleaseInstance(g_wpaServiceName, g_wpaObj, true);
    OsalMemFree(tmpRawData);
    g_devMgr->UnloadDevice(g_devMgr, g_wpaServiceName);
    g_devMgr = nullptr;
    g_wpaObj = nullptr;
    return result;
}
} // namespace WIFI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    HDF_LOGI("%{public}s : size = %lu ,THRESHOLD = %lu", __FUNCTION__, size, OHOS::WIFI::THRESHOLD);
    if (size < OHOS::WIFI::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::WIFI::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}