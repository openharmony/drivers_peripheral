/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "v1_0/include/idisplay_composer_interface.h"
#include "v1_0/display_composer_type.h"
#include "display_test.h"
#include "hdi_test_device_common.h"
#include "hdi_test_layer.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_0;
class HdiTestDisplay {
public:
    HdiTestDisplay(uint32_t id, std::shared_ptr<IDisplayComposerInterface> device);
    virtual ~HdiTestDisplay() {}
    int32_t Init();
    int32_t GetModeInfoFromId(int32_t id, DisplayModeInfo &modeInfo);
    std::shared_ptr<HdiTestLayer> CreateHdiTestLayer(LayerInfo &info);
    std::shared_ptr<HdiTestLayer> CreateHdiTestLayer(uint32_t w, uint32_t h);
    int32_t Commit();
    int32_t PrepareDisplayLayers();
    DisplayModeInfo GetCurrentMode() const
    {
        return mCurrentMode;
    }
    int32_t RegDisplayVBlankCallback(VBlankCallback cb, void *data);
    int32_t SetDisplayVsyncEnabled(bool enabled);
    std::shared_ptr<HdiTestLayer> GetLayerFromId(uint32_t id);
    std::unordered_map<uint32_t, std::shared_ptr<HdiTestLayer>> &GetLayers()
    {
        return mLayerMaps;
    }
    void Clear();
    BufferHandle *SnapShot()
    {
        DISPLAY_TEST_LOGD("client fb phyaddr %" PRIx64 " virtual addr %p", mCurrentFb->phyAddr, mCurrentFb->virAddr);
        return mCurrentFb;
    }
    void ResetClientLayer()
    {
        mClientLayer.reset();
    }

private:
    int32_t RefreshLayersCompType();
    int32_t GetLayersReleaseFence();
    uint32_t mActiveModeId = 0;
    DisplayModeInfo mCurrentMode = { 0 };
    uint32_t mId;
    std::shared_ptr<IDisplayComposerInterface> device_;

    DisplayCapability mCap;
    std::vector<DisplayModeInfo> mModes;
    std::unordered_map<uint32_t, std::shared_ptr<HdiTestLayer>> mLayerMaps;
    std::unique_ptr<HdiTestLayer> mClientLayer;
    BufferHandle *mCurrentFb;
    bool mNeedFlushFb = false;
};
} // OHOS
} // HDI
} // Display
} // TEST
#endif // HDI_TEST_DISPLAY_H
