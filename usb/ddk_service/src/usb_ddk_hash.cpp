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
#include <mutex>
#include <unordered_map>
#include <iostream>

#include "hdf_base.h"
#include "usbd_wrapper.h"

static std::unordered_map<uint64_t, InterfaceInfo> g_hashMap;
std::mutex g_mapMutex;

constexpr size_t MAX_HASH_RECORD = 1000;

int32_t UsbDdkHash(const InterfaceInfo &info, uint64_t &hashVal)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);
    if (g_hashMap.size() > MAX_HASH_RECORD) {
        return HDF_ERR_OUT_OF_RANGE;
    }

    hashVal = static_cast<uint64_t>(std::hash<uint64_t> {}(info.addr));
    g_hashMap.emplace(hashVal, info);
    return HDF_SUCCESS;
}

int32_t UsbDdkUnHash(uint64_t hashVal, uint64_t &addr)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);
    if (auto ret = g_hashMap.find(hashVal); ret == g_hashMap.end()) {
        return HDF_ERR_INVALID_PARAM;
    }
    auto mappedVal = g_hashMap[hashVal];
    addr = mappedVal.addr;
    return HDF_SUCCESS;
}

void UsbDdkDelHashRecord(uint64_t hashVal)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);
    g_hashMap.erase(hashVal);
}

bool UsbDdkGetRecordByVal(const InterfaceInfo &info, uint64_t &hashVal)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);
    for (auto it = g_hashMap.begin(); it != g_hashMap.end(); it++) {
        if (it->second.busNum == info.busNum && it->second.devNum == info.devNum) {
            hashVal = it->first;
            return true;
        }
    }
    return false;
}

int32_t GetInterfaceInfoByVal(const uint64_t hashVal, InterfaceInfo &Info)
{
    std::lock_guard<std::mutex> lock(g_mapMutex);
    auto it = g_hashMap.find(hashVal);
    if (it == g_hashMap.end()) {
        return HDF_ERR_INVALID_PARAM;
    }
    Info = it->second;
    return HDF_SUCCESS;
}