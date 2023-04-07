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
#include "usb_ddk_hash.h"
#include <functional>
#include <unordered_map>
#include <mutex>

#include "hdf_base.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

std::unordered_map<uint64_t, uint64_t> g_hashMap;
std::mutex g_mapMutex;

constexpr size_t MAX_HASH_RECORD = 1000;

int32_t UsbDdkHash(uint64_t param, uint64_t *hashVal)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);

    if (g_hashMap.size() > MAX_HASH_RECORD) {
        return HDF_ERR_OUT_OF_RANGE;
    }

    *hashVal = static_cast<uint64_t>(std::hash<uint64_t> {}(param));
    g_hashMap.emplace(*hashVal, param);
    return HDF_SUCCESS;
}

int32_t UsbDdkUnHash(uint64_t hashVal, uint64_t *param)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto mappedVal = g_hashMap[hashVal];
    if (mappedVal == 0) {
        g_hashMap.erase(hashVal);
        return HDF_ERR_INVALID_PARAM;
    }
    *param = mappedVal;
    return HDF_SUCCESS;
}

void UsbDdkDelHashRecord(uint64_t hashVal)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);
    g_hashMap.erase(hashVal);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
