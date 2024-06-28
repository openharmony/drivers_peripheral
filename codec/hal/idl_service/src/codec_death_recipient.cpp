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
#include <map>
#include <set>
#include <mutex>
#include <iproxy_broker.h>
#include <codec_death_recipient.h>
#include "codec_log_wrapper.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V3_0 {

static std::map<IRemoteObject *, std::set<uint32_t>> g_remoteCompsMap;
static std::map<IRemoteObject *, sptr<CodecDeathRecipient>> g_deathReciMap;
static std::map<uint32_t, IRemoteObject *> g_compRemoteMap;
static std::mutex g_mutex;

void CleanResourceOfDiedService(sptr<IRemoteObject> object, wptr<CodecComponentManagerService> managerService)
{
    std::set<uint32_t> compIds {};
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        auto remoteComps = g_remoteCompsMap.find(object.GetRefPtr());
        if (remoteComps == g_remoteCompsMap.end()) {
            CODEC_LOGE("can not find remote service in g_remoteCompsMap!");
            return;
        }
        compIds = remoteComps->second;
        g_remoteCompsMap.erase(remoteComps);
    }

    for (auto id = compIds.begin(); id != compIds.end(); id++) {
        managerService->DestroyComponent(*id);
    }
    CODEC_LOGI("Clean died remoteService resource success!");
}

void RegisterDeathRecipientService(const sptr<ICodecCallback> callbacks, uint32_t componentId,
                                   wptr<CodecComponentManagerService> service)
{
    std::unique_lock<std::mutex> lk(g_mutex);

    const sptr<OHOS::IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ICodecCallback>(callbacks);
    g_compRemoteMap.emplace(std::make_pair(componentId, remote.GetRefPtr()));

    auto remoteComps = g_remoteCompsMap.find(remote.GetRefPtr());
    if (remoteComps != g_remoteCompsMap.end()) {
        CODEC_LOGI("RemoteService had been added deathRecipient!");
        remoteComps->second.insert(componentId);
        return;
    }

    const sptr<CodecDeathRecipient> deathCallBack(new CodecDeathRecipient(service));
    bool ret = remote->AddDeathRecipient(deathCallBack);
    if (!ret) {
        CODEC_LOGE("RemoteService add deathRecipient fail!");
        return ;
    }

    std::set<uint32_t> compIds;
    compIds.insert(componentId);
    g_remoteCompsMap.emplace(std::make_pair(remote.GetRefPtr(), compIds));
    g_deathReciMap[remote.GetRefPtr()] = deathCallBack;
    CODEC_LOGI("Add deathRecipient success!");
}

void RemoveMapperOfDestoryedComponent(uint32_t componentId)
{
    std::unique_lock<std::mutex> lk(g_mutex);

    auto compRemote = g_compRemoteMap.find(componentId);
    if (compRemote == g_compRemoteMap.end()) {
        return;
    }

    IRemoteObject *remote = compRemote->second;
    auto remoteComps = g_remoteCompsMap.find(remote);
    if (remoteComps == g_remoteCompsMap.end()) {
        return;
    }
    remoteComps->second.erase(componentId);
    if (remoteComps->second.empty()) {
        g_remoteCompsMap.erase(remoteComps);
    }
    g_compRemoteMap.erase(compRemote);

    auto deathReci = g_deathReciMap.find(remote);
    if (deathReci == g_deathReciMap.end()) {
        CODEC_LOGE("%{public}s: not find recipient", __func__);
        return;
    }
    bool result = remote->RemoveDeathRecipient(deathReci->second);
    g_deathReciMap.erase(deathReci);
    if (!result) {
        CODEC_LOGE("%{public}s: removeDeathRecipient fail", __func__);
        return;
    }
    CODEC_LOGI("Remove mapper destoryedComponent success!");
}
}  // namespace V3_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
