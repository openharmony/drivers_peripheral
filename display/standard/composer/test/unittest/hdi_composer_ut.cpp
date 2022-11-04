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

#include "hdi_composer_ut.h"
#include <chrono>
#include <cinttypes>
#include <algorithm>
#include "v1_0/include/idisplay_composer_interface.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "display_test.h"
#include "display_test_utils.h"
#include "hdi_composition_check.h"
#include "hdi_test_device.h"
#include "hdi_test_device_common.h"
#include "hdi_test_display.h"
#include "hdi_test_render_utils.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::TEST;
using namespace testing::ext;

std::shared_ptr<IDisplayComposerInterface> composerDevice {};
static std::shared_ptr<HdiTestLayer> g_testFreshLayer;
const int SLEEP_CONT = 100;
std::vector<uint32_t> displayIds_;
std::shared_ptr<IDisplayBuffer> gralloc_ = nullptr;

static inline std::shared_ptr<HdiTestDisplay> GetFirstDisplay()
{
    return HdiTestDevice::GetInstance().GetFirstDisplay();
}

static int32_t CheckComposition(std::vector<LayerSettings> &layers, BufferHandle *clientBuffer,
    uint32_t checkType = HdiCompositionCheck::CHECK_VERTEX)
{
    DISPLAY_TEST_CHK_RETURN((clientBuffer == nullptr), DISPLAY_NULL_PTR, DISPLAY_TEST_LOGE("client buffer is nullptr"));
    return HdiCompositionCheck::GetInstance().Check(layers, *clientBuffer, checkType);
}

static std::shared_ptr<HdiTestLayer> CreateTestLayer(LayerSettings setting, uint32_t zorder)
{
    int ret;
    HdiTestDevice::GetInstance();
    DISPLAY_TEST_LOGD("color 0x%x", setting.color);
    std::shared_ptr<HdiTestDisplay> display = HdiTestDevice::GetInstance().GetFirstDisplay();
    DISPLAY_TEST_CHK_RETURN((display == nullptr), nullptr, DISPLAY_TEST_LOGE("can not get display"));

    std::shared_ptr<HdiTestLayer> layer = display->CreateHdiTestLayer(setting.bufferSize.w, setting.bufferSize.h);
    DISPLAY_TEST_CHK_RETURN((layer == nullptr), nullptr, DISPLAY_TEST_LOGE("can not create hdi test layer"));

    layer->SetLayerPosition(setting.displayRect);

    layer->SetCompType(setting.compositionType);

    if ((setting.alpha >= 0) && (setting.alpha <= 0xff)) { // alpha rang 0x00 ~ 0xff
        LayerAlpha alpha = { 0 };
        alpha.gAlpha = setting.alpha;
        alpha.enGlobalAlpha = true;
        layer->SetAlpha(alpha);
    }
    HdiGrallocBuffer *handle = layer->GetFrontBuffer();
    DISPLAY_TEST_CHK_RETURN((handle == nullptr), nullptr, DISPLAY_TEST_LOGE("can not get front buffer"));
    ClearColor(*(handle->Get()), setting.color);
    ret = layer->SwapFrontToBackQ();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), nullptr, DISPLAY_TEST_LOGE("SwapFrontToBackQ failed"));
    layer->SetZorder(zorder);
    layer->SetBlendType(setting.blendType);
    layer->SetTransform(setting.rotate);
    return layer;
}

static int PrepareAndPrensent()
{
    int ret;
    DISPLAY_TEST_LOGD();
    std::shared_ptr<HdiTestDisplay> display = HdiTestDevice::GetInstance().GetFirstDisplay();
    DISPLAY_TEST_CHK_RETURN((display == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get display"));

    ret = display->PrepareDisplayLayers();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("PrepareDisplayLayers failed"));

    ret = display->Commit();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("Commit failed"));
    return DISPLAY_SUCCESS;
}

static void TestVBlankCallback(unsigned int sequence, uint64_t ns, void *data)
{
    static uint64_t lastns;
    DISPLAY_TEST_LOGD("seq %d  ns %" PRId64 " duration %" PRId64 " ns", sequence, ns, (ns - lastns));
    lastns = ns;
    VblankCtr::GetInstance().NotifyVblank(sequence, ns, data);
}

static void AdjustLayerSettings(std::vector<LayerSettings> &settings, uint32_t w, uint32_t h)
{
    DISPLAY_TEST_LOGD();
    for (uint32_t i = 0; i < settings.size(); i++) {
        LayerSettings &setting = settings[i];
        DISPLAY_TEST_LOGD(" ratio w: %f  ratio h: %f", setting.rectRatio.w, setting.rectRatio.h);
        if ((setting.rectRatio.w > 0.0f) && (setting.rectRatio.h > 0.0f)) {
            setting.displayRect.h = static_cast<uint32_t>(setting.rectRatio.h * h);
            setting.displayRect.w = static_cast<uint32_t>(setting.rectRatio.w * w);
            setting.displayRect.x = static_cast<uint32_t>(setting.rectRatio.x * w);
            setting.displayRect.y = static_cast<uint32_t>(setting.rectRatio.y * h);
            DISPLAY_TEST_LOGD("display rect adust form %f %f %f %f to %d %d %d %d ", setting.rectRatio.x,
                setting.rectRatio.y, setting.rectRatio.w, setting.rectRatio.h, setting.displayRect.x,
                setting.displayRect.y, setting.displayRect.w, setting.displayRect.h);
        }

        if ((setting.bufferRatio.h > 0.0f) || (setting.bufferRatio.w > 0.0f)) {
            setting.bufferSize.h = static_cast<uint32_t>(setting.bufferRatio.h * h);
            setting.bufferSize.w = static_cast<uint32_t>(setting.bufferRatio.w * w);
            DISPLAY_TEST_LOGD("buffer size adjust for %f %f to %d %d", setting.bufferRatio.w, setting.bufferRatio.h,
                setting.bufferSize.w, setting.bufferSize.h);
        }

        if ((setting.bufferSize.w == 0) || (setting.bufferSize.h == 0)) {
            DISPLAY_TEST_LOGD("buffer size adjust for %d %d to %d %d", setting.bufferSize.w, setting.bufferSize.h,
                setting.displayRect.w, setting.displayRect.h);

            setting.bufferSize.w = setting.displayRect.w;
            setting.bufferSize.h = setting.displayRect.h;
        }
    }
}

static std::vector<std::shared_ptr<HdiTestLayer>> CreateLayers(std::vector<LayerSettings> &settings)
{
    DISPLAY_TEST_LOGD("settings %zd", settings.size());
    std::vector<std::shared_ptr<HdiTestLayer>> layers;
    DisplayModeInfo mode = GetFirstDisplay()->GetCurrentMode();
    AdjustLayerSettings(settings, mode.width, mode.height);
    for (uint32_t i = 0; i < settings.size(); i++) {
        LayerSettings setting = settings[i];

        auto layer = CreateTestLayer(setting, i);
        layers.push_back(layer);
    }

    return layers;
}

static inline void PresentAndCheck(std::vector<LayerSettings> &layerSettings,
    uint32_t checkType = HdiCompositionCheck::CHECK_VERTEX)
{
    int ret = PrepareAndPrensent();
    ASSERT_TRUE((ret == DISPLAY_SUCCESS));
    HdiTestDevice::GetInstance().GetGrallocInterface()->InvalidateCache(*(GetFirstDisplay()->SnapShot()));
    ret = CheckComposition(layerSettings, GetFirstDisplay()->SnapShot(), checkType);
    ASSERT_TRUE((ret == DISPLAY_SUCCESS));
}

void DeviceTest::TearDown()
{
    DISPLAY_TEST_LOGD();
    HdiTestDevice::GetInstance().Clear();
}

void DeviceLayerDisplay::TearDown()
{
    HdiTestDevice::GetInstance().Clear();
}

void VblankCtr::NotifyVblank(unsigned int sequence, uint64_t ns, void *data)
{
    DISPLAY_TEST_LOGD();
    if (data != nullptr) {
        DISPLAY_TEST_LOGD("sequence = %u, ns = %" PRIu64 "", sequence, ns);
    }
    std::unique_lock<std::mutex> lg(mVblankMutex);
    mHasVblank = true;
    mVblankCondition.notify_one();
    DISPLAY_TEST_LOGD();
}

VblankCtr::~VblankCtr() {}

int32_t VblankCtr::WaitVblank(uint32_t ms)
{
    bool ret;
    DISPLAY_TEST_LOGD();
    std::unique_lock<std::mutex> lck(mVblankMutex);
    mHasVblank = false; // must wait next vblank
    ret = mVblankCondition.wait_for(lck, std::chrono::milliseconds(ms), [=] { return mHasVblank; });
    DISPLAY_TEST_LOGD();
    if (!ret) {
        return DISPLAY_FAILURE;
    }
    return DISPLAY_SUCCESS;
}

void VblankTest::TearDown()
{
    auto display = HdiTestDevice::GetInstance().GetFirstDisplay();
    int32_t ret = display->SetDisplayVsyncEnabled(false);
    if (ret != DISPLAY_SUCCESS) {
        DISPLAY_TEST_LOGE("vsync disable failed");
    }
    VblankCtr::GetInstance().WaitVblank(100); // wait for last vsync 100ms.
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_GetDisplayCapability_args_normal, TestSize.Level1)
{
    DisplayCapability info;
    auto ret = composerDevice->GetDisplayCapability(displayIds_[0], info);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayCapability_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    DisplayCapability info;
    auto ret = composerDevice->GetDisplayCapability(devId, info);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->GetDisplayCapability(devId, info);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplaySupportedModes_args_normal, TestSize.Level1)
{
    std::vector<DisplayModeInfo> modes;
    auto ret = composerDevice->GetDisplaySupportedModes(displayIds_[0], modes);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplaySupportedModes_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    std::vector<DisplayModeInfo> modes;
    auto ret = composerDevice->GetDisplaySupportedModes(devId, modes);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->GetDisplaySupportedModes(devId, modes);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayMode_args_normal, TestSize.Level1)
{
    uint32_t mode = 0;
    auto ret = composerDevice->GetDisplayMode(displayIds_[0], mode);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayMode_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    uint32_t mode = 0;
    auto ret = composerDevice->GetDisplayMode(devId, mode);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->GetDisplayMode(devId, mode);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayMode_args_normal, TestSize.Level1)
{
    uint32_t mode = 0;
    auto ret = composerDevice->SetDisplayMode(displayIds_[0], mode);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayMode_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    uint32_t mode = 0;
    auto ret = composerDevice->SetDisplayMode(devId, mode);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->SetDisplayMode(devId, mode);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayMode_arg2_abnormal, TestSize.Level1)
{
    uint32_t mode = 0xffffff;
    auto ret = composerDevice->SetDisplayMode(displayIds_[0], mode);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayMode_args_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    uint32_t mode = 0xffffff;
    auto ret = composerDevice->SetDisplayMode(devId, mode);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->SetDisplayMode(devId, mode);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayPowerStatus_args_normal, TestSize.Level1)
{
    DispPowerStatus powerStatus = DispPowerStatus::POWER_STATUS_OFF;
    auto ret = composerDevice->GetDisplayPowerStatus(displayIds_[0], powerStatus);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayPowerStatus_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    DispPowerStatus powerStatus = DispPowerStatus::POWER_STATUS_OFF;
    auto ret = composerDevice->GetDisplayPowerStatus(devId, powerStatus);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->GetDisplayPowerStatus(devId, powerStatus);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus_POWER_STATUS_ON, TestSize.Level1)
{
    auto ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], DispPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus_POWER_STATUS_STANDBY, TestSize.Level1)
{
    auto ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], DispPowerStatus::POWER_STATUS_STANDBY);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);

    ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], DispPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus_POWER_STATUS_SUSPEND, TestSize.Level1)
{
    auto ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], DispPowerStatus::POWER_STATUS_SUSPEND);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);

    ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], DispPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus_POWER_STATUS_OFF, TestSize.Level1)
{
    auto ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], DispPowerStatus::POWER_STATUS_OFF);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);

    ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], DispPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    auto ret = composerDevice->SetDisplayPowerStatus(devId, DispPowerStatus::POWER_STATUS_OFF);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->SetDisplayPowerStatus(devId, DispPowerStatus::POWER_STATUS_OFF);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus_arg2_abnormal, TestSize.Level1)
{
    DispPowerStatus type = static_cast<DispPowerStatus>(5);
    auto ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], type);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    type = static_cast<DispPowerStatus>(-1);
    ret = composerDevice->SetDisplayPowerStatus(displayIds_[0], type);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus_args_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    DispPowerStatus type = static_cast<DispPowerStatus>(5);
    auto ret = composerDevice->SetDisplayPowerStatus(devId, type);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayBacklight_args_normal, TestSize.Level1)
{
    uint32_t level;
    auto ret = composerDevice->GetDisplayBacklight(displayIds_[0], level);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayBacklight_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    uint32_t level;
    auto ret = composerDevice->GetDisplayBacklight(devId, level);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->GetDisplayBacklight(devId, level);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayBacklight_args_normal, TestSize.Level1)
{
    uint32_t level = 10;
    auto ret = composerDevice->SetDisplayBacklight(displayIds_[0], level);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);

    level = 0;
    ret = composerDevice->SetDisplayBacklight(displayIds_[0], level);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);

    level = UINT32_MAX;
    ret = composerDevice->SetDisplayBacklight(displayIds_[0], level);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayBacklight_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    uint32_t level = 0;
    auto ret = composerDevice->SetDisplayBacklight(devId, level);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayBacklight_arg2_abnormal, TestSize.Level1)
{
    uint32_t level = 0x7FFFFFFF;
    auto ret = composerDevice->SetDisplayBacklight(displayIds_[0], level);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayBacklight_args_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    uint32_t level = 0x7FFFFFFF;
    auto ret = composerDevice->SetDisplayBacklight(devId, level);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayCompChange_args_normal, TestSize.Level1)
{
    std::vector<uint32_t> layers {};
    std::vector<int32_t> type {};
    auto ret = composerDevice->GetDisplayCompChange(displayIds_[0], layers, type);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayCompChange_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    std::vector<uint32_t> layers {};
    std::vector<int32_t> type {};
    auto ret = composerDevice->GetDisplayCompChange(devId, layers, type);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->GetDisplayCompChange(devId, layers, type);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayReleaseFence_args_normal, TestSize.Level1)
{
    std::vector<uint32_t> layers {};
    std::vector<int32_t> fences {};
    auto ret = composerDevice->GetDisplayReleaseFence(displayIds_[0], layers, fences);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayReleaseFence_arg1_abnormal, TestSize.Level1)
{
    uint32_t devId = 0xffffff;
    std::vector<uint32_t> layers {};
    std::vector<int32_t> fences {};
    auto ret = composerDevice->GetDisplayReleaseFence(devId, layers, fences);
    EXPECT_EQ(DISPLAY_FAILURE, ret);

    devId = UINT32_MAX;
    ret = composerDevice->GetDisplayReleaseFence(devId, layers, fences);
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_001, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_002, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBX_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_003, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGB_888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_004, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGR_565;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_005, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRX_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_006, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_422_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_007, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRA_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_008, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_009, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBX_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_010, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRX_5551;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_011, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRA_5551;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_012, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRX_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_013, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRA_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_014, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_420_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_015, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_420_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_016, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_420_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_017, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_420_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_018, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_422_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_019, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_422_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer_args_normal_020, TestSize.Level1)
{
    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_422_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetDisplayClientBuffer(displayIds_[0], *buffer, -1);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_P(DeviceLayerDisplay, test_CreateLayer, TestSize.Level1)
{
    std::vector<LayerSettings> layerSettings = GetParam();
    CreateLayers(layerSettings);
    PresentAndCheck(layerSettings);
    if (TestParemeter::GetInstance().mTestSleep > 0) {
        sleep(TestParemeter::GetInstance().mTestSleep);
    }
}

HWTEST_F(DeviceTest, test_SetLayerCrop_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = RED },
    };
    std::vector<uint32_t> splitColors = { { RED, GREEN } };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    // split the buffer
    auto layer = layers[0];
    HdiGrallocBuffer *handle = layer->GetBackBuffer(); // the backbuffer has not present now
    ASSERT_TRUE((handle != nullptr));
    auto splitRects = SplitBuffer(*(handle->Get()), splitColors);
    PrepareAndPrensent();
    for (uint32_t i = 0; i < splitRects.size(); i++) {
        settings[0].color = splitColors[i];
        layer->SetLayerCrop(splitRects[i]);
        PresentAndCheck(settings);
    }
}

HWTEST_F(DeviceTest, test_SetLayerCrop_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = RED },
    };
    std::vector<uint32_t> splitColors = { { RED, GREEN, YELLOW, BLUE } };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    // split the buffer
    auto layer = layers[0];
    HdiGrallocBuffer *handle = layer->GetBackBuffer(); // the backbuffer has not present now
    ASSERT_TRUE((handle != nullptr));
    auto splitRects = SplitBuffer(*(handle->Get()), splitColors);
    PrepareAndPrensent();
    for (uint32_t i = 0; i < splitRects.size(); i++) {
        settings[0].color = splitColors[i];
        layer->SetLayerCrop(splitRects[i]);
        PresentAndCheck(settings);
    }
}

HWTEST_F(DeviceTest, test_SetLayerCrop_003, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = RED },
    };
    std::vector<uint32_t> splitColors = { { RED, GREEN, YELLOW, BLUE, PINK, PURPLE } };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    // split the buffer
    auto layer = layers[0];
    HdiGrallocBuffer *handle = layer->GetBackBuffer(); // the backbuffer has not present now
    ASSERT_TRUE((handle != nullptr));
    auto splitRects = SplitBuffer(*(handle->Get()), splitColors);
    PrepareAndPrensent();
    for (uint32_t i = 0; i < splitRects.size(); i++) {
        settings[0].color = splitColors[i];
        layer->SetLayerCrop(splitRects[i]);
        PresentAndCheck(settings);
    }
}

HWTEST_F(DeviceTest, test_SetLayerCrop_004, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = RED },
    };
    std::vector<uint32_t> splitColors = { { RED, GREEN, YELLOW, BLUE, PINK, PURPLE, CYAN, TRANSPARENT } };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    // split the buffer
    auto layer = layers[0];
    HdiGrallocBuffer *handle = layer->GetBackBuffer(); // the backbuffer has not present now
    ASSERT_TRUE((handle != nullptr));
    auto splitRects = SplitBuffer(*(handle->Get()), splitColors);
    PrepareAndPrensent();
    for (uint32_t i = 0; i < splitRects.size(); i++) {
        settings[0].color = splitColors[i];
        layer->SetLayerCrop(splitRects[i]);
        PresentAndCheck(settings);
    }
}

HWTEST_F(DeviceTest, test_SetLayerZorder, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = RED },
        {
        .rectRatio = { 0, 0, 1.0f, 0.125f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0.875f, 1.0f, 0.125f },
        .color = YELLOW },
    };

    std::vector<std::vector<int>> zorders = {
        { 3, 2, 1 }, { 1, 3, 2 }, { 3, 1, 2 }, { 1, 2, 3 }, { 2, 1, 3 }, { 9, 100, 3 },
    };
    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);

    for (const auto &zorderList : zorders) {
        // adjust the zorder
        for (uint32_t i = 0; i < zorderList.size(); i++) {
            settings[i].zorder = zorderList[i];
            layers[i]->SetZorder(zorderList[i]);
        }
        std::vector<LayerSettings> tempSettings = settings;
        std::sort(tempSettings.begin(), tempSettings.end(),
            [=](const auto &l, auto const & r) { return l.zorder < r.zorder; });
        // present and check
        PresentAndCheck(tempSettings);
    }
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerPreMulti_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    PrepareAndPrensent();

    auto layer = layers[0];
    bool preMul = true;
    auto ret = composerDevice->SetLayerPreMulti(displayIds_[0], layer->GetId(), preMul);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerPreMulti_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    PrepareAndPrensent();

    auto layer = layers[0];
    bool preMul = false;
    auto ret = composerDevice->SetLayerPreMulti(displayIds_[0], layer->GetId(), preMul);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerAlpha_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0, 0.5f, 0.5f },
        .color = RED },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[1];
    LayerAlpha alpha = { 0 };
    alpha.enGlobalAlpha = true;
    alpha.enPixelAlpha = true;
    alpha.gAlpha = 0;
    alpha.alpha0 = 0;
    alpha.alpha1 = 0;
    layer->SetAlpha(alpha);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerAlpha_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0, 0.5f, 0.5f },
        .color = RED },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[1];
    LayerAlpha alpha = { 0 };
    alpha.enGlobalAlpha = true;
    alpha.enPixelAlpha = true;
    alpha.gAlpha = 255;
    alpha.alpha0 = 0;
    alpha.alpha1 = 0;
    layer->SetAlpha(alpha);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerAlpha_003, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0, 0.5f, 0.5f },
        .color = RED },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[1];
    LayerAlpha alpha = { 0 };
    alpha.enGlobalAlpha = true;
    alpha.enPixelAlpha = true;
    alpha.gAlpha = 255;
    alpha.alpha0 = 255;
    alpha.alpha1 = 0;
    layer->SetAlpha(alpha);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerAlpha_004, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0, 0.5f, 0.5f },
        .color = RED },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[1];
    LayerAlpha alpha = { 0 };
    alpha.enGlobalAlpha = true;
    alpha.enPixelAlpha = true;
    alpha.gAlpha = 255;
    alpha.alpha0 = 255;
    alpha.alpha1 = 255;
    layer->SetAlpha(alpha);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerAlpha_005, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0, 0.5f, 0.5f },
        .color = RED },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[1];
    LayerAlpha alpha = { 0 };
    alpha.enGlobalAlpha = false;
    alpha.enPixelAlpha = true;
    alpha.gAlpha = 255;
    alpha.alpha0 = 255;
    alpha.alpha1 = 255;
    layer->SetAlpha(alpha);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerAlpha_006, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0, 0.5f, 0.5f },
        .color = RED },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[1];
    LayerAlpha alpha = { 0 };
    alpha.enGlobalAlpha = false;
    alpha.enPixelAlpha = false;
    alpha.gAlpha = 255;
    alpha.alpha0 = 255;
    alpha.alpha1 = 255;
    layer->SetAlpha(alpha);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerAlpha_007, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
        .rectRatio = { 0, 0, 1.0f, 1.0f },
        .color = GREEN },
        {
        .rectRatio = { 0, 0, 0.5f, 0.5f },
        .color = RED },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[1];
    LayerAlpha alpha = { 0 };
    alpha.enGlobalAlpha = false;
    alpha.enPixelAlpha = false;
    alpha.gAlpha = 0;
    alpha.alpha0 = 255;
    alpha.alpha1 = 255;
    layer->SetAlpha(alpha);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerPosition_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {.rectRatio = {0, 0, 0.5f, 0.5f}, .color = GREEN, .alpha = 0xFF}
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];
    IRect rect = {100, 100, 0, 0};
    auto ret = composerDevice->SetLayerPosition(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerPosition_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {.rectRatio = {0, 0, 0.5f, 0.5f}, .color = BLUE, .alpha = 0xFF}
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];
    IRect rect = {0, 0, 200, 200};
    auto ret = composerDevice->SetLayerPosition(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerPosition_003, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {.rectRatio = {0, 0, 0.5f, 0.5f}, .color = BLUE, .alpha = 0xFF}
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];
    IRect rect = {-1, -1, 200, 200};
    auto ret = composerDevice->SetLayerPosition(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerPosition_004, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {.rectRatio = {0, 0, 0.5f, 0.5f}, .color = BLUE, .alpha = 0xFF}
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];
    IRect rect = {-1, -1, INT32_MAX, INT32_MAX};
    auto ret = composerDevice->SetLayerPosition(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    IRect rect = {0, 0, 200, 200};
    auto ret = composerDevice->SetLayerDirtyRegion(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    IRect rect = {200, 400, 600, 800};
    auto ret = composerDevice->SetLayerDirtyRegion(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion_003, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    IRect rect = {200, 400, 600, 800};
    auto ret = composerDevice->SetLayerDirtyRegion(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion_004, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    IRect rect = {200, 400, 600, 800};
    auto ret = composerDevice->SetLayerDirtyRegion(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion_005, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    IRect rect = {400, 400, 400, 400};
    auto ret = composerDevice->SetLayerDirtyRegion(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion_006, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    IRect rect = {800, 800, 800, 800};
    auto ret = composerDevice->SetLayerDirtyRegion(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion_007, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    IRect rect = {200, 200, 200, 200};
    auto ret = composerDevice->SetLayerDirtyRegion(displayIds_[0], layer->GetId(), rect);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetTransformMode_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0.4f, 0.4f, 0.1f, 0.4f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    PrepareAndPrensent();

    auto layer = layers[0];

    TransformType type = TransformType::ROTATE_90;
    auto ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_180;
    ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_270;
    ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetTransformMode_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0.4f, 0.4f, 0.1f, 0.4f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    PrepareAndPrensent();

    auto layer = layers[0];

    TransformType type = TransformType::ROTATE_90;
    auto ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_180;
    ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_270;
    ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetTransformMode_003, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0.4f, 0.4f, 0.1f, 0.4f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    PrepareAndPrensent();

    auto layer = layers[0];

    TransformType type = TransformType::ROTATE_90;
    auto ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_180;
    ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_270;
    ret = composerDevice->SetTransformMode(displayIds_[0], layer->GetId(), type);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerVisibleRegion_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0.4f, 0.4f, 0.1f, 0.4f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    PrepareAndPrensent();
    auto layer = layers[0];

    IRect region = {0, 0, 500, 500};
    std::vector<IRect> regions = {};
    regions.push_back(region);
    auto ret = composerDevice->SetLayerVisibleRegion(displayIds_[0], layer->GetId(), regions);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBX_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_003, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGB_888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_004, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format =  PIXEL_FMT_BGR_565;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_005, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRX_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_006, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRA_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_007, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_008, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBX_4444;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_009, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRX_5551;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_010, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRA_5551;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_011, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRX_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_012, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_BGRA_8888;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_013, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_CLUT8 + 11;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_014, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_420_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_015, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_420_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_016, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_420_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_017, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_420_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_018, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_422_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_019, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_422_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_020, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_422_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_021, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_422_SP;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_022, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCBCR_422_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer_023, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BufferHandle *buffer = nullptr;

    AllocInfo info;
    info.width  = 800;
    info.height = 600;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_YCRCB_422_P;

    gralloc_->AllocMem(info, buffer);

    auto ret = composerDevice->SetLayerBuffer(displayIds_[0], layer->GetId(), *buffer, -1);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerCompositionType_COMPOSITION_CLIENT, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    CompositionType type = CompositionType::COMPOSITION_CLIENT;
    auto ret = composerDevice->SetLayerCompositionType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerCompositionType_COMPOSITION_DEVICE, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    CompositionType type = CompositionType::COMPOSITION_DEVICE;
    auto ret = composerDevice->SetLayerCompositionType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerCompositionType_COMPOSITION_CURSOR, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = YELLOW
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    CompositionType type = CompositionType::COMPOSITION_CURSOR;
    auto ret = composerDevice->SetLayerCompositionType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerCompositionType_COMPOSITION_VIDEO, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    CompositionType type = CompositionType::COMPOSITION_VIDEO;
    auto ret = composerDevice->SetLayerCompositionType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_NONE, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_NONE;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_CLEAR, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_CLEAR;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    composerDevice->SetLayerBlendType(displayIds_[0], layers[1]->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_SRC, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_SRC;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_SRCOVER, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = YELLOW
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_SRCOVER;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_DSTOVER, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = YELLOW
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_DSTOVER;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_SRCIN, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_SRCIN;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_DSTIN, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_DSTIN;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_SRCOUT, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = YELLOW
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_SRCOUT;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_DSTOUT, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = YELLOW
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_DSTOUT;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_SRCATOP, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PINK
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_SRCATOP;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_DSTATOP, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PINK
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PURPLE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_DSTATOP;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_ADD, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PURPLE
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = CYAN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_ADD;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_XOR, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PURPLE
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = CYAN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_XOR;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_DST, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PURPLE
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = CYAN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_DST;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_AKS, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PURPLE
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = CYAN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    BlendType type = BlendType::BLEND_AKS;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType_BLEND_AKD, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PURPLE
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = CYAN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    PrepareAndPrensent();

    auto layer = layers[1];

    BlendType type = BlendType::BLEND_AKD;
    auto ret = composerDevice->SetLayerBlendType(displayIds_[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer_001, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = PURPLE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    PrepareAndPrensent();
    sleep(1);
    auto ret = composerDevice->DestroyLayer(displayIds_[0], layer->GetId());
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer_002, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    PrepareAndPrensent();
    sleep(1);
    auto ret = composerDevice->DestroyLayer(displayIds_[0], layer->GetId());
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer_003, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    PrepareAndPrensent();
    sleep(1);
    auto ret = composerDevice->DestroyLayer(displayIds_[0], layer->GetId());
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer_004, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    PrepareAndPrensent();
    sleep(1);
    auto ret = composerDevice->DestroyLayer(displayIds_[0], layer->GetId());
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer_arg1_abnormal, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    PrepareAndPrensent();
    sleep(1);
    auto ret = composerDevice->DestroyLayer(9999, layer->GetId());
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer_arg2_abnormal, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    PrepareAndPrensent();
    sleep(1);
    auto ret = composerDevice->DestroyLayer(displayIds_[0], 9999);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer_args_abnormal, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];

    PrepareAndPrensent();
    sleep(1);
    auto ret = composerDevice->DestroyLayer(9999, 9999);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(VblankTest, test_RegDisplayVBlankCallback, TestSize.Level1)
{
    int ret;
    DISPLAY_TEST_LOGD();
    std::shared_ptr<HdiTestDisplay> display = HdiTestDevice::GetInstance().GetFirstDisplay();
    ret = display->RegDisplayVBlankCallback(TestVBlankCallback, nullptr);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "RegDisplayVBlankCallback failed";
    ret = display->SetDisplayVsyncEnabled(true);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "SetDisplayVsyncEnabled failed";
    ret = VblankCtr::GetInstance().WaitVblank(1000); // 1000ms
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "WaitVblank timeout";
    ret = display->SetDisplayVsyncEnabled(false);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "SetDisplayVsyncEnabled failed";
    usleep(100 * 1000);                              // wait for 100ms avoid the last vsync.
    ret = VblankCtr::GetInstance().WaitVblank(1000); // 1000ms
    ASSERT_TRUE(ret != DISPLAY_SUCCESS) << "vblank do not disable";
}

int main(int argc, char **argv)
{
    int ret = HdiTestDevice::GetInstance().InitDevice();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("Init Device Failed"));
    ::testing::InitGoogleTest(&argc, argv);
    composerDevice = HdiTestDevice::GetInstance().GetDeviceInterface();
    gralloc_.reset(IDisplayBuffer::Get());
    auto display = HdiTestDevice::GetInstance().GetFirstDisplay();
    if (display != nullptr) {
        displayIds_ = HdiTestDevice::GetInstance().GetDevIds();
        // avoid vsync call back affer the destruction of VblankCtr
        display->SetDisplayVsyncEnabled(false);
        VblankCtr::GetInstance().WaitVblank(SLEEP_CONT);
    }
    ret = RUN_ALL_TESTS();
    HdiTestDevice::GetInstance().GetFirstDisplay()->ResetClientLayer();
    return ret;
}
