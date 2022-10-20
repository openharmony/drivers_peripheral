/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_instance_manager.h"
#include <map>
#include <mutex>

#ifdef __cplusplus
extern "C"
{
#endif

std::map<uintptr_t, uintptr_t> g_codecInstances;
std::mutex g_codecInstanceLock;

bool AddToCodecInstanceManager(CODEC_HANDLETYPE codecHandle, struct CodecInstance *codecInstance)
{
    uintptr_t handle = reinterpret_cast<uintptr_t>(codecHandle);
    uintptr_t instance = reinterpret_cast<uintptr_t>(codecInstance);
    std::unique_lock<std::mutex> autoLock(g_codecInstanceLock);
    std::pair<std::map<uintptr_t, uintptr_t>::iterator, bool> ret =
        g_codecInstances.insert(std::pair<uintptr_t, uintptr_t>(handle, instance));
    bool result = ret.second;
    return result;
}

struct CodecInstance* FindInCodecInstanceManager(CODEC_HANDLETYPE codecHandle)
{
    uintptr_t handle = reinterpret_cast<uintptr_t>(codecHandle);
    std::unique_lock<std::mutex> autoLock(g_codecInstanceLock);
    std::map<uintptr_t, uintptr_t>::iterator it = g_codecInstances.find(handle);
    if (it == g_codecInstances.end()) {
        return nullptr;
    }
    uintptr_t ret = it->second;
    return reinterpret_cast<struct CodecInstance *>(ret);
}

void RemoveFromCodecInstanceManager(CODEC_HANDLETYPE codecHandle)
{
    uintptr_t handle = reinterpret_cast<uintptr_t>(codecHandle);
    std::unique_lock<std::mutex> autoLock(g_codecInstanceLock);
    g_codecInstances.erase(handle);
}

#ifdef __cplusplus
}
#endif
