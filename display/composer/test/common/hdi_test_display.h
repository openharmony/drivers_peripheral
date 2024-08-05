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

#ifndef HDI_TEST_DISPLAY_H
#define HDI_TEST_DISPLAY_H
#include <cinttypes>
#include "v1_0/include/idisplay_buffer.h"
#include "v1_2/include/idisplay_composer_interface.h"
#include "v1_1/display_composer_type.h"
#include "display_test.h"
#include "hdi_test_device_common.h"
#include "hdi_test_layer.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_1;
class HdiTestDisplay {
public:
    HdiTestDisplay(uint32_t id, sptr<Composer::V1_1::IDisplayComposerInterface> device);
    virtual ~HdiTestDisplay() {}
    int32_t Init();
    int32_t GetModeInfoFromId(int32_t id, DisplayModeInfo& modeInfo) const;
    std::shared_ptr<HdiTestLayer> CreateHdiTestLayer(LayerInfo& info);
    std::shared_ptr<HdiTestLayer> CreateHdiTestLayer(uint32_t w, uint32_t h);
    int32_t Commit();
    int32_t PrepareDisplayLayers();
    DisplayModeInfo GetCurrentMode() const
    {
        return currentMode_;
    }
    int32_t RegDisplayVBlankCallback(VBlankCallback cb, void* data) const;
    int32_t SetDisplayVsyncEnabled(bool enabled) const;
    std::shared_ptr<HdiTestLayer> GetLayerFromId(uint32_t id);
    std::unordered_map<uint32_t, std::shared_ptr<HdiTestLayer>> &GetLayers()
    {
        return layerMaps_;
    }
    void Clear();
    BufferHandle* SnapShot()
    {
        return currentFb_;
    }
    void ResetClientLayer()
    {
        clientLayer_.reset();
    }

private:
    int32_t RefreshLayersCompType();
    int32_t GetLayersReleaseFence();
    uint32_t activeModeId_ = 0;
    DisplayModeInfo currentMode_ = { 0 };
    uint32_t id_;
    sptr<Composer::V1_1::IDisplayComposerInterface> device_;

    DisplayCapability cap_;
    std::vector<DisplayModeInfo> modes_;
    std::unordered_map<uint32_t, std::shared_ptr<HdiTestLayer>> layerMaps_;
    std::unique_ptr<HdiTestLayer> clientLayer_;
    BufferHandle* currentFb_;
    bool needFlushFb_ = false;
};
} // OHOS
} // HDI
} // Display
} // TEST
#endif // HDI_TEST_DISPLAY_H
