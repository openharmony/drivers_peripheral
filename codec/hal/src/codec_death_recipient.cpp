/*
 * Copyright (c) 2023 Shenzhen Kaihong DID Co., Ltd.
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

#include "codec_death_recipient.h"
#include <hdf_remote_service.h>
#include <map>
#include <mutex>
#include <securec.h>
#include <set>
#include <unistd.h>
#include "codec_log_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

static std::map<uint64_t *, uint32_t> g_addrPidMap;
static std::map<uint32_t, std::set<uint32_t>> g_pidCompsMap;
static std::mutex g_mutex;

bool RegisterService(struct CodecCallbackType *callbacks, uint32_t componentId,
                     struct CodecComponentNode *codecNode)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    if (callbacks == nullptr) {
        CODEC_LOGE("invalid parameter");
        return false;
    }
    uint32_t remotePid =  static_cast<uint32_t>(HdfRemoteGetCallingPid());
    auto comps = g_pidCompsMap.find(remotePid);
    if (comps != g_pidCompsMap.end()) {
        CODEC_LOGE("RemoteService had been added deathRecipient!");
        comps->second.insert(componentId);
        return false;
    }

    uint64_t *addr = reinterpret_cast<uint64_t *>(callbacks->remote);
    std::set<uint32_t> compIds;
    compIds.insert(componentId);
    g_pidCompsMap.emplace(std::make_pair(remotePid, compIds));
    g_addrPidMap.emplace(std::make_pair(addr, remotePid));
    return true;
}

int32_t CleanMapperOfDiedService(struct HdfRemoteService *remote, uint32_t *compIds, uint32_t *size)
{
    std::lock_guard<std::mutex> lk(g_mutex);

    uint64_t *addr = reinterpret_cast<uint64_t *>(remote);
    auto addrPid = g_addrPidMap.find(addr);
    if (addrPid == g_addrPidMap.end()) {
        CODEC_LOGE("RemoteService no mapper in g_addrPidMap!");
        return HDF_FAILURE;
    }

    uint32_t remotePid = addrPid->second;
    auto comps = g_pidCompsMap.find(remotePid);
    if (comps == g_pidCompsMap.end()) {
        CODEC_LOGE("RemoteService no mapper in g_pidCompsMap!");
        return HDF_FAILURE;
    }
    
    std::set<uint32_t> ids = comps->second;
    uint32_t index = 0;
    *size = ids.size();
    for (auto id = ids.begin(); id != ids.end(); id++) {
        compIds[index++] = *id;
    }

    g_addrPidMap.erase(addrPid);
    g_pidCompsMap.erase(comps);
    CODEC_LOGE("clean service mapper success!");
    return HDF_SUCCESS;
}

void RemoveDestoryedComponent(uint32_t componentId)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    
    uint32_t remotePid =  static_cast<uint32_t>(HdfRemoteGetCallingPid());
    auto comps = g_pidCompsMap.find(remotePid);
    if (comps != g_pidCompsMap.end()) {
        comps->second.erase(componentId);
    }
}
#ifdef __cplusplus
};
#endif
