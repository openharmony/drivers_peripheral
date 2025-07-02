/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "low_power_player_factory.h"
#include "lpp_sync_manager_adapter.h"

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

extern "C" ILowPowerPlayerFactory* LowPowerPlayerFactoryImplGetInstance(void)
{
    return new (std::nothrow) LowPowerPlayerFactory();
}

extern "C" void LowPowerPlayerFactoryImplRelease(void* ptr)
{
    delete (LowPowerPlayerFactory*)ptr;
}

int32_t LowPowerPlayerFactory::CreateSyncMgr(sptr<ILppSyncManagerAdapter> &lppAdapter, uint32_t &instanceId)
{
    uint32_t componentId = GetNextMgrId();
    sptr<ILppSyncManagerAdapter> lppInstance(new LppSyncManagerAdapter(componentId));
    syncMgrMap_.emplace(std::make_pair(componentId, lppInstance));
    lppAdapter = lppInstance;
    instanceId = componentId;
    return HDF_SUCCESS;
}

int32_t LowPowerPlayerFactory::DestroySyncMgr(uint32_t instanceId)
{
    auto it = syncMgrMap_.find(instanceId);
    if (it != syncMgrMap_.end()) {
        syncMgrMap_.erase(it);
    }
    return HDF_SUCCESS;
}

int32_t LowPowerPlayerFactory::CreateAudioSink(sptr<ILppAudioSinkAdapter>& audioSinkAdapter, uint32_t& audioSinkId)
{
    return HDF_SUCCESS;
}

int32_t LowPowerPlayerFactory::DestroyAudioSink(uint32_t audioSinkId)
{
    return HDF_SUCCESS;
}

uint32_t LowPowerPlayerFactory::GetNextMgrId(void)
{
    uint32_t tempId = 0;
    do {
        tempId = ++syncMgrId_;
    } while (syncMgrMap_.find(tempId) != syncMgrMap_.end());
    return tempId;
}

}  // namespace V1_0
}  // namespace LowPowerPlayer
}  // namespace HDI
}  // namespace OHOS