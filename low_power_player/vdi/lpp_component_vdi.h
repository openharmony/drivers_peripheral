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
#include "v1_0/ilpp_sync_manager_callback.h"

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

#define LOW_POWER_PLAYER_VDI_LIBRARY "liblpp_vdi_impl.z.so"

class ILowPowerPlayerVdi {
public:
    virtual ~ILowPowerPlayerVdi() = default;
    virtual int32_t Init(int32_t instanceId) = 0;
    virtual int32_t SetVideoChannelId(uint32_t channelId, int32_t instanceId) = 0;
    virtual int32_t StartRender(int32_t instanceId) = 0;
    virtual int32_t RenderNextFrame(int32_t instanceId) = 0;
    virtual int32_t Pause(int32_t instanceId) = 0;
    virtual int32_t Resume(int32_t instanceId) = 0;
    virtual int32_t Flush(int32_t instanceId) = 0;
    virtual int32_t Stop(int32_t instanceId) = 0;
    virtual int32_t Reset(int32_t instanceId) = 0;
    virtual int32_t Release(int32_t instanceId) = 0;
    virtual int32_t SetTunnelId(uint64_t& tunnelId, int32_t instanceId) = 0;
    virtual int32_t SetPlaybackSpeed(float mode, int32_t instanceId) = 0;
    virtual int32_t GetShareBuffer(int32_t& fd, int32_t instanceId) = 0;
    virtual int32_t GetParameter(std::map<std::string, std::string>& parameter, int32_t instanceId) = 0;
    virtual int32_t SetTargetStartFrame(uint64_t framePts, uint32_t timeoutMs, int32_t instanceId) = 0;
    virtual int32_t RegisterCallback(const sptr<ILppSyncManagerCallback>& syncCallback, int32_t instanceId) = 0;
    virtual int32_t SetParameter(const std::map<std::string, std::string>& parameter, int32_t instanceId) = 0;
    virtual int32_t UpdateTimeAnchor(uint64_t anchorPts, uint64_t anchorClk, int32_t instanceId) = 0;
    virtual int32_t BindOutputBuffers(
        const std::map<uint32_t, sptr<OHOS::HDI::Base::NativeBuffer>> &outputBuffers, int32_t instanceId) = 0;
    virtual int32_t UnbindOutputBuffers(int32_t instanceId) = 0;
};

using CreateLowPowerPlayerVdiFunc = ILowPowerPlayerVdi* (*)();
using DestroyLowPowerPlayerVdiFunc = void (*)(ILowPowerPlayerVdi* vdi);
extern "C" ILowPowerPlayerVdi* CreateLowPowerPlayerVdi();
extern "C" void DestroyLowPowerPlayerVdi(ILowPowerPlayerVdi* vdi);

}
}
}
}
#endif