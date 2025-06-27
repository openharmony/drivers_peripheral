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

#ifndef OHOS_HDI_LPP_V1_0_LPPCOMPONENTFACTORY_H
#define OHOS_HDI_LPP_V1_0_LPPCOMPONENTFACTORY_H

#include <hdf_log.h>
#include <stdint.h>
#include "v1_0/ilow_power_player_factory.h"
#include "v1_0/ilpp_sync_manager_adapter.h"
#include "v1_0/ilpp_audio_sink_adapter.h"


namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

class LowPowerPlayerFactory : public ILowPowerPlayerFactory {
public:
    LowPowerPlayerFactory() = default;
    ~LowPowerPlayerFactory() = default ;
    int32_t CreateSyncMgr(sptr<ILppSyncManagerAdapter>& syncMgrAdapter, uint32_t& syncMgrId);
    int32_t DestroySyncMgr(uint32_t syncMgrId);
    int32_t CreateAudioSink(sptr<ILppAudioSinkAdapter>& audioSinkAdapter, uint32_t& audioSinkId);
    int32_t DestroyAudioSink(uint32_t audioSinkId);

private:
    uint32_t syncMgrId_;
    uint32_t audioSinkId_;
    uint32_t GetNextMgrId();
    uint32_t GetNextSinkId();
    std::map<uint32_t, sptr<ILppSyncManagerAdapter>> syncMgrMap_;
    std::map<uint32_t, sptr<ILppAudioSinkAdapter>> audioSinkMap_;
};

}  // namespace V1_0
}  // namespace LowPowerPlayer
}  // namespace HDI
}  // namespace OHOS

#endif