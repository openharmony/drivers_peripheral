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
 
#ifndef OHOS_HDI_LPP_V1_0_LPPCOMPONENTSERVICE_H
#define OHOS_HDI_LPP_V1_0_LPPCOMPONENTSERVICE_H

#include <mutex>
#include <stdint.h>
#include "lpp_component_vdi.h"
#include "v1_0/ilpp_sync_manager_adapter.h"

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

class LppSyncManagerAdapter : public ILppSyncManagerAdapter {
public:
    LppSyncManagerAdapter(uint32_t instanceId);
    ~LppSyncManagerAdapter();
    int32_t SetVideoChannelId(uint32_t channelId);
    int32_t SetAudioChannelId(uint32_t channelId) { return 0; };
    int32_t StartRender();
    int32_t RenderNextFrame();
    int32_t Pause();
    int32_t Resume();
    int32_t Flush();
    int32_t Stop();
    int32_t Reset();
    int32_t Release();
    int32_t SetTunnelId(uint64_t tunnelId);
    int32_t SetTargetStartFrame(uint64_t framePts, uint32_t timeoutMs);
    int32_t SetPlaybackSpeed(float mode);
    int32_t RegisterCallback(const sptr<ILppSyncManagerCallback>& syncCallback);
    int32_t GetShareBuffer(int32_t& fd);
    int32_t GetParameter(std::map<std::string, std::string>& parameter);
    int32_t SetParameter(const std::map<std::string, std::string>& parameter);
    int32_t UpdateTimeAnchor(uint64_t anchorPts, uint64_t anchorClk);
    int32_t BindOutputBuffers(const std::map<uint32_t, sptr<NativeBuffer>>& outputBuffers);
    int32_t UnbindOutputBuffers();

private:
    int32_t LoadVdi();
    uint32_t instanceId_;
    void *libHandle_;
    std::mutex mutex_;
    ILowPowerPlayerVdi* vdiImpl_;
    CreateLowPowerPlayerVdiFunc createVdi_;
    DestroyLowPowerPlayerVdiFunc destroyVdi_;
};

}  // namespace V1_0
}  // namespace LowPowerPlayer
}  // namespace HDI
}  // namespace OHOS

#endif //OHOS_HDI_LOW_POWER_PLAYER_V1_0_CODECCOMPONENTSERVICE_H