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

#ifndef OHOS_HDI_DISPLAY_V1_1_IDISPLAY_COMPOSER_VDI_H
#define OHOS_HDI_DISPLAY_V1_1_IDISPLAY_COMPOSER_VDI_H

#include <vector>
#include <string>
#include "idisplay_composer_vdi.h"
#include "v1_2/display_composer_type.h"
#include "v1_1/imode_callback.h"
#include "v1_1/iseamless_change_callback.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
using namespace OHOS::HDI::Display::Composer::V1_2;

class IDisplayComposerVdiV1_1 : public IDisplayComposerVdi {
    public:
    virtual int32_t RegSeamlessChangeCallback(SeamlessChangeCallback cb, void* data) = 0;
    virtual int32_t GetDisplaySupportedModesExt(uint32_t devId, std::vector<DisplayModeInfoExt>& modes) = 0;
    virtual int32_t SetDisplayModeAsync(uint32_t devId, uint32_t modeId, ModeCallback cb, void *data) = 0;
    virtual int32_t GetDisplayVBlankPeriod(uint32_t devId, uint64_t& period) = 0;
    virtual int32_t SetLayerPerFrameParameter(uint32_t devId, uint32_t layerId, const std::string& key,
        const std::vector<int8_t>& value) = 0;
    virtual int32_t GetSupportedLayerPerFrameParameterKey(std::vector<std::string>& keys) = 0;
    virtual int32_t SetDisplayOverlayResolution(uint32_t devId, uint32_t width, uint32_t height) = 0;
    virtual int32_t RegRefreshCallback(RefreshCallback cb, void* data) = 0;
    virtual int32_t GetDisplaySupportedColorGamuts(uint32_t devId, std::vector<ColorGamut>& gamuts) = 0;
    virtual int32_t GetHDRCapabilityInfos(uint32_t devId, HDRCapability& info) = 0;
    virtual int32_t RegDisplayVBlankIdleCallback(VBlankIdleCallback cb, void* data) = 0;
    virtual int32_t SetDisplayConstraint(uint32_t devId, uint64_t frameID, uint64_t ns, uint32_t type) = 0;
    virtual int32_t SetHardwareCursorPosition(uint32_t devId, int32_t x, int32_t y) = 0;
    virtual int32_t EnableHardwareCursorStats(uint32_t devId, bool enable) = 0;
    virtual int32_t GetHardwareCursorStats(uint32_t devId, uint32_t& frameCount, uint32_t& vsyncCount) = 0;
    virtual int32_t SetDisplayActiveRegion(uint32_t devId, const IRect& rect) = 0;
};

using CreateComposerVdiFuncV1_1 = IDisplayComposerVdiV1_1* (*)();
using DestroyComposerVdiFuncV1_1 = void (*)(IDisplayComposerVdiV1_1* vdi);
extern "C" IDisplayComposerVdiV1_1* CreateComposerVdiV1_1();
extern "C" void DestroyComposerVdiV1_1(IDisplayComposerVdiV1_1* vdi);
} // namespace Composer
} // namespace Display
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_DISPLAY_V1_1_IDISPLAY_COMPOSER_VDI_H
