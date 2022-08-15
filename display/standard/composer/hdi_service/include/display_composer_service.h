/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_DISPLAY_V1_0_DISPLAYCOMPOSERSERVICE_H
#define OHOS_HDI_DISPLAY_V1_0_DISPLAYCOMPOSERSERVICE_H

#include "idisplay_composer_hwi.h"
#include "v1_0/display_command/display_cmd_responser.h"
#include "v1_0/idisplay_composer.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
namespace V1_0 {
using namespace OHOS::HDI::Display::Composer::V1_0;

class DisplayComposerService : public IDisplayComposer {
public:
    DisplayComposerService();
    virtual ~DisplayComposerService();
    int32_t RegHotPlugCallback(const sptr<IHotPlugCallback> &cb) override;
    int32_t GetDisplayCapability(uint32_t devId, DisplayCapability &info) override;
    int32_t GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo> &modes) override;
    int32_t GetDisplayMode(uint32_t devId, uint32_t &modeId) override;
    int32_t SetDisplayMode(uint32_t devId, uint32_t modeId) override;
    int32_t GetDisplayPowerStatus(uint32_t devId, DispPowerStatus &status) override;
    int32_t SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status) override;
    int32_t GetDisplayBacklight(uint32_t devId, uint32_t &level) override;
    int32_t SetDisplayBacklight(uint32_t devId, uint32_t level) override;
    int32_t GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t &value) override;
    int32_t GetDisplayCompChange(uint32_t devId, std::vector<uint32_t> &layers, std::vector<int32_t> &type) override;
    int32_t SetDisplayClientCrop(uint32_t devId, const IRect &rect) override;
    int32_t SetDisplayClientDestRect(uint32_t devId, const IRect &rect) override;
    int32_t SetDisplayVsyncEnabled(uint32_t devId, bool enabled) override;
    int32_t RegDisplayVBlankCallback(uint32_t devId, const sptr<IVBlankCallback> &cb) override;
    int32_t GetDisplayReleaseFence(
        uint32_t devId, std::vector<uint32_t> &layers, std::vector<sptr<HdifdParcelable>> &fences) override;
    int32_t CreateVirtualDisplay(uint32_t width, uint32_t height, int32_t &format, uint32_t &devId) override;
    int32_t DestroyVirtualDisplay(uint32_t devId) override;
    int32_t SetVirtualDisplayBuffer(
        uint32_t devId, const sptr<BufferHandleParcelable> &buffer, const sptr<HdifdParcelable> &fence) override;
    int32_t SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value) override;
    int32_t CreateLayer(uint32_t devId, const LayerInfo &layerInfo, uint32_t &layerId) override;
    int32_t DestroyLayer(uint32_t devId, uint32_t layerId) override;
    int32_t InitCmdRequest(const std::shared_ptr<SharedMemQueue<int32_t>> &request) override;
    int32_t CmdRequest(uint32_t inEleCnt, const std::vector<HdifdInfo> &inFds, uint32_t &outEleCnt,
        std::vector<HdifdInfo> &outFds) override;
    int32_t GetCmdReply(std::shared_ptr<SharedMemQueue<int32_t>> &reply) override;

private:
    int32_t LoadHwi();
    static void OnHotPlug(uint32_t outputId, bool connected, void *data);
    static void OnVBlank(unsigned int sequence, uint64_t ns, void *data);

private:
    void *libHandle_;
    CreateComposerHwiFunc_t *createHwiFunc_;
    DestroyComposerHwiFunc_t *destroyHwiFunc_;

    std::shared_ptr<IDisplayComposerHwi> hwiImpl_;
    std::unique_ptr<HdiDisplayCmdResponser> cmdResponser_;
    sptr<IHotPlugCallback> hotPlugCb_;
    sptr<IVBlankCallback> vBlankCb_;
};
} // namespace V1_0
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_DISPLAY_V1_0_DISPLAYCOMPOSERSERVICE_H
