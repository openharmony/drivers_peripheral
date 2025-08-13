/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_LPP_V1_0_LPPCOMPONENTVDI_H
#define OHOS_HDI_LPP_V1_0_LPPCOMPONENTVDI_H

#include <map>
#include <hdf_log.h>
#include <base/native_buffer.h>
#include "lpp_component_vdi.h"
#include "v1_0/ilpp_sync_manager_callback.h"
#include "v1_0/ilpp_types.h"

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

#define LOW_POWER_PLAYER_VDI_LIBRARY "liblpp_vdi_impl.z.so"

class ILowPowerPlayerVdi {
public:
    virtual ~ILowPowerPlayerVdi() = default;
    virtual int32_t Init() = 0;
    virtual int32_t SetVideoChannelId(uint32_t channelId) = 0;
    virtual int32_t StartRender() = 0;
    virtual int32_t RenderNextFrame() = 0;
    virtual int32_t Pause() = 0;
    virtual int32_t Resume() = 0;
    virtual int32_t Flush() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Reset() = 0;
    virtual int32_t Release() = 0;
    virtual int32_t SetTunnelId(uint64_t& tunnelId) = 0;
    virtual int32_t SetPlaybackSpeed(float mode) = 0;
    virtual int32_t GetShareBuffer(int32_t& fd) = 0;
    virtual int32_t GetParameter(std::map<std::string, std::string>& parameter) = 0;
    virtual int32_t SetTargetStartFrame(uint64_t framePts, uint32_t timeoutMs) = 0;
    virtual int32_t RegisterCallback(const sptr<ILppSyncManagerCallback>& syncCallback) = 0;
    virtual int32_t SetParameter(const std::map<std::string, std::string>& parameter) = 0;
    virtual int32_t UpdateTimeAnchor(uint64_t anchorPts, uint64_t anchorClk) = 0;
    virtual int32_t BindOutputBuffers(
        const std::map<uint32_t, sptr<OHOS::HDI::Base::NativeBuffer>> &outputBuffers) = 0;
    virtual int32_t UnbindOutputBuffers() = 0;
    virtual int32_t GetLatestPts(int64_t& pts) = 0;
};

using GetAVCapabilityFunc = int32_t (*)(LppAVCap&);
using CreateLowPowerPlayerVdiFunc = ILowPowerPlayerVdi* (*)();
using DestroyLowPowerPlayerVdiFunc = void (*)(ILowPowerPlayerVdi* vdi);
extern "C" int32_t GetAVCapabilityVdi(LppAVCap&);
extern "C" ILowPowerPlayerVdi* CreateLowPowerPlayerVdi();
extern "C" void DestroyLowPowerPlayerVdi(ILowPowerPlayerVdi* vdi);

}
}
}
}
#endif