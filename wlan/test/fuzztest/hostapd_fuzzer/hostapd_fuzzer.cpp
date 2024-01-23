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

namespace OHOS {
namespace WIFI {
constexpr size_t THRESHOLD = 10;
const char *g_wpaServiceName = "hostapd_interface_service";
struct IHostapdInterface *g_wpaObj = nullptr;

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    bool result = false;

    if (rawData == nullptr || size == 0) {
        return false;
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
    int32_t ret = g_wpaObj->StartAp(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : StartAp failed!", __FUNCTION__);
        OsalMemFree(tmpRawData);
        return result;
    }

    FuzzHostapdInterfaceStartAp(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceStopAp(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceEnableAp(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceDisableAp(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApPasswd(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApName(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApBand(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetAp80211n(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApWmm(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApChannel(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetApMaxConn(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceSetMacFilter(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceDelMacFilter(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceGetStaInfos(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceDisassociateSta(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceRegisterEventCallback(g_wpaObj, tmpRawData);
    FuzzHostapdInterfaceUnregisterEventCallback(g_wpaObj, tmpRawData);

    ret = g_wpaObj->StopAp(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s : StopAp failed!", __FUNCTION__);
        result = false;
    }
    IHostapdInterfaceReleaseInstance(g_wpaServiceName, g_wpaObj, true);
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
