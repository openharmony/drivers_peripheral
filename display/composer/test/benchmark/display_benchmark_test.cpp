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

#include <mutex>
#include <chrono>
#include <cinttypes>
#include <algorithm>
#include <condition_variable>
#include <benchmark/benchmark.h>
#include "gtest/gtest.h"
#include "v1_2/include/idisplay_composer_interface.h"
#include "v1_1/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "display_test.h"
#include "display_test_utils.h"
#include "hdi_composition_check.h"
#include "hdi_test_device.h"
#include "hdi_test_device_common.h"
#include "hdi_test_display.h"
#include "hdi_test_render_utils.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_2;
using namespace OHOS::HDI::Display::TEST;
using namespace testing::ext;

static sptr<Composer::V1_2::IDisplayComposerInterface> g_composerDevice = nullptr;
static std::shared_ptr<IDisplayBuffer> g_gralloc = nullptr;
static std::vector<uint32_t> g_displayIds;

namespace {
class DisplayBenchmarkTest : public benchmark::Fixture {
public:
    void TearDown(const ::benchmark::State &state);
    static void OnMode(uint32_t modeId, uint64_t vBlankPeriod, void* data);
    static void OnseamlessChange(uint32_t devId, void* data);
    static void TestRefreshCallback(uint32_t devId, void* data);
};

void DisplayBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    HdiTestDevice::GetInstance().Clear();
}

void DisplayBenchmarkTest::OnMode(uint32_t modeId, uint64_t vBlankPeriod, void* data)
{
}

void DisplayBenchmarkTest::OnseamlessChange(uint32_t devId, void* data)
{
}

void DisplayBenchmarkTest::TestRefreshCallback(uint32_t devId, void* data)
{
}

static inline std::shared_ptr<HdiTestDisplay> GetFirstDisplay()
{
    return HdiTestDevice::GetInstance().GetFirstDisplay();
}

static std::shared_ptr<HdiTestLayer> CreateTestLayer(LayerSettings setting, uint32_t zorder)
{
    int ret;
    HdiTestDevice::GetInstance();
    DISPLAY_TEST_LOGE("color 0x%x", setting.color);
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
    HdiGrallocBuffer* handle = layer->GetFrontBuffer();
    DISPLAY_TEST_CHK_RETURN((handle == nullptr), nullptr, DISPLAY_TEST_LOGE("can not get front buffer"));
    ClearColor(*(handle->Get()), setting.color);
    ret = layer->SwapFrontToBackQ();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), nullptr, DISPLAY_TEST_LOGE("SwapFrontToBackQ failed"));
    layer->SetZorder(zorder);
    layer->SetBlendType(setting.blendType);
    layer->SetTransform(setting.rotate);
    return layer;
}

static int PrepareAndCommit()
{
    int ret;
    DISPLAY_TEST_LOGE();
    std::shared_ptr<HdiTestDisplay> display = HdiTestDevice::GetInstance().GetFirstDisplay();
    DISPLAY_TEST_CHK_RETURN((display == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get display"));

    ret = display->PrepareDisplayLayers();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("PrepareDisplayLayers failed"));

    ret = display->Commit();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("Commit failed"));
    return DISPLAY_SUCCESS;
}

static void AdjustLayerSettings(std::vector<LayerSettings> &settings, uint32_t w, uint32_t h)
{
    DISPLAY_TEST_LOGE();
    for (uint32_t i = 0; i < settings.size(); i++) {
        LayerSettings& setting = settings[i];
        DISPLAY_TEST_LOGE(" ratio w: %f  ratio h: %f", setting.rectRatio.w, setting.rectRatio.h);
        if ((setting.rectRatio.w > 0.0f) && (setting.rectRatio.h > 0.0f)) {
            setting.displayRect.h = static_cast<uint32_t>(setting.rectRatio.h * h);
            setting.displayRect.w = static_cast<uint32_t>(setting.rectRatio.w * w);
            setting.displayRect.x = static_cast<uint32_t>(setting.rectRatio.x * w);
            setting.displayRect.y = static_cast<uint32_t>(setting.rectRatio.y * h);
            DISPLAY_TEST_LOGE("display rect adust form %f %f %f %f to %{public}d %{public}d %{public}d %{public}d ",
                setting.rectRatio.x, setting.rectRatio.y, setting.rectRatio.w,
                setting.rectRatio.h, setting.displayRect.x, setting.displayRect.y,
                setting.displayRect.w, setting.displayRect.h);
        }

        if ((setting.bufferRatio.h > 0.0f) || (setting.bufferRatio.w > 0.0f)) {
            setting.bufferSize.h = static_cast<uint32_t>(setting.bufferRatio.h * h);
            setting.bufferSize.w = static_cast<uint32_t>(setting.bufferRatio.w * w);
            DISPLAY_TEST_LOGE("buffer size adjust for %f %f to %{public}d %{public}d",
                setting.bufferRatio.w, setting.bufferRatio.h, setting.bufferSize.w, setting.bufferSize.h);
        }

        if ((setting.bufferSize.w == 0) || (setting.bufferSize.h == 0)) {
            DISPLAY_TEST_LOGE("buffer size adjust for %{public}d %{public}d to %{public}d %{public}d",
                setting.bufferSize.w, setting.bufferSize.h, setting.displayRect.w, setting.displayRect.h);

            setting.bufferSize.w = setting.displayRect.w;
            setting.bufferSize.h = setting.displayRect.h;
        }
    }
}

static std::vector<std::shared_ptr<HdiTestLayer>> CreateLayers(std::vector<LayerSettings> &settings)
{
    DISPLAY_TEST_LOGE("settings %{public}zd", settings.size());
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

/**
  * @tc.name: SetClientBufferCacheCountTest
  * @tc.desc: Benchmarktest for interface SetClientBufferCacheCount.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetClientBufferCacheCountTest)(benchmark::State &state)
{
    int32_t ret;
    const uint32_t CACHE_COUNT = 5;
    for (auto _ : state) {
        ret = g_composerDevice->SetClientBufferCacheCount(g_displayIds[0], CACHE_COUNT);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

/**
  * @tc.name: GetDisplayCapabilityTest
  * @tc.desc: Benchmarktest for interface GetDisplayCapability.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayCapabilityTest)(benchmark::State &state)
{
    int32_t ret;
    DisplayCapability info;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayCapability(g_displayIds[0], info);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayCapabilityTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplaySupportedModesTest
  * @tc.desc: Benchmarktest for interface GetDisplaySupportedModes.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplaySupportedModesTest)(benchmark::State &state)
{
    int32_t ret;
    std::vector<DisplayModeInfo> modes;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplaySupportedModes(g_displayIds[0], modes);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplaySupportedModesTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayModeTest
  * @tc.desc: Benchmarktest for interface GetDisplayMode.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayModeTest)(benchmark::State &state)
{
    int32_t ret;
    uint32_t modeId = 0;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayMode(modeId, modeId);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayModeTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayModeTest
  * @tc.desc: Benchmarktest for interface SetDisplayMode.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayModeTest)(benchmark::State &state)
{
    int32_t ret;
    const uint32_t modeId = 0;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayMode(g_displayIds[0], modeId);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayModeTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayPowerStatusTest
  * @tc.desc: Benchmarktest for interface GetDisplayPowerStatus.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayPowerStatusTest)(benchmark::State &state)
{
    int32_t ret;
    Composer::V1_0::DispPowerStatus powerStatus = Composer::V1_0::DispPowerStatus::POWER_STATUS_OFF;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayPowerStatus(g_displayIds[0], powerStatus);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayPowerStatusTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayPowerStatusTest
  * @tc.desc: Benchmarktest for interface SetDisplayPowerStatus.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayPowerStatusTest)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayPowerStatus(g_displayIds[0],
            Composer::V1_0::DispPowerStatus::POWER_STATUS_ON);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayPowerStatusTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayBacklightTest
  * @tc.desc: Benchmarktest for interface GetDisplayBacklight.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayBacklightTest)(benchmark::State &state)
{
    int32_t ret;
    uint32_t level;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayBacklight(g_displayIds[0], level);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayBacklightTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayBacklightTest
  * @tc.desc: Benchmarktest for interface SetDisplayBacklight.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayBacklightTest)(benchmark::State &state)
{
    int32_t ret;
    const uint32_t level = 10;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayBacklight(g_displayIds[0], level);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayBacklightTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: CreateAndDestroyLayerTest
  * @tc.desc: Benchmarktest for interface CreateLayer And DestroyLayer.
  */
BENCHMARK_F(DisplayBenchmarkTest, CreateAndDestroyLayerTest)(benchmark::State &state)
{
    int32_t ret;
    LayerInfo layerInfo;
    uint32_t layerId;
    for (auto _ : state) {
        uint32_t bufferCount = 3;
        ret = g_composerDevice->CreateLayer(g_displayIds[0], layerInfo, bufferCount, layerId);
        EXPECT_EQ(DISPLAY_SUCCESS, ret);
        ret = g_composerDevice->DestroyLayer(g_displayIds[0], layerId);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, CreateAndDestroyLayerTest)->
    Iterations(10)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayCompChangeTest
  * @tc.desc: Benchmarktest for interface GetDisplayCompChange.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayCompChangeTest)(benchmark::State &state)
{
    std::vector<uint32_t> layers {};
    std::vector<int32_t> type {};
    int32_t ret;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayCompChange(g_displayIds[0], layers, type);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayCompChangeTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayReleaseFenceTest
  * @tc.desc: Benchmarktest for interface GetDisplayReleaseFence.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayReleaseFenceTest)(benchmark::State &state)
{
    std::vector<uint32_t> layers {};
    std::vector<int32_t> fences {};
    int32_t ret;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayReleaseFence(g_displayIds[0], layers, fences);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayReleaseFenceTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: CreateAndDestroyVirtualDisplayTest
  * @tc.desc: Benchmarktest for interface CreateVirtualDisplay and DestroyVirtualDisplay.
  */
BENCHMARK_F(DisplayBenchmarkTest, CreateAndDestroyVirtualDisplayTest)(benchmark::State &state)
{
    int32_t ret;
    const uint32_t WIDTH = 100;
    const uint32_t HEIGHT = 100;
    int32_t format = 0;
    for (auto _ : state) {
        ret = g_composerDevice->CreateVirtualDisplay(WIDTH, HEIGHT, format, g_displayIds[0]);
        EXPECT_EQ(DISPLAY_FAILURE, ret);
        ret = g_composerDevice->DestroyVirtualDisplay(g_displayIds[0]);
    }
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, CreateAndDestroyVirtualDisplayTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetVirtualDisplayBufferTest
  * @tc.desc: Benchmarktest for interface SetVirtualDisplayBuffer.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetVirtualDisplayBufferTest)(benchmark::State &state)
{
    BufferHandle* buffer = nullptr;
    int32_t ret;
    int32_t fence = -1;

    AllocInfo info;
    info.width  = 100;
    info.height = 100;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = Composer::V1_0::PIXEL_FMT_RGBA_8888;

    g_gralloc->AllocMem(info, buffer);
    ASSERT_TRUE(buffer != nullptr);

    for (auto _ : state) {
        ret = g_composerDevice->SetVirtualDisplayBuffer(g_displayIds[0], *buffer, fence);
    }
    g_gralloc->FreeMem(*buffer);
    // not support
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetVirtualDisplayBufferTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayPropertyTest
  * @tc.desc: Benchmarktest for interface SetDisplayProperty.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayPropertyTest)(benchmark::State &state)
{
    int32_t ret;
    uint32_t id = 1;
    uint64_t value = 0;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayProperty(g_displayIds[0], id, value);
    }
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayPropertyTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayPropertyTest
  * @tc.desc: Benchmarktest for interface GetDisplayProperty.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayPropertyTest)(benchmark::State &state)
{
    int32_t ret;
    uint32_t id = 1;
    uint64_t value = 0;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayProperty(g_displayIds[0], id, value);
    }
    int32_t result = DISPLAY_FAILURE;
    if (ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT) {
        result = DISPLAY_SUCCESS;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, result);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayPropertyTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();


/**
  * @tc.name: GetDisplaySupportedModesExtTest
  * @tc.desc: Benchmarktest for interface GetDisplaySupportedModesExtTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplaySupportedModesExtTest)(benchmark::State &state)
{
    int32_t ret;
    std::vector<DisplayModeInfoExt> modes;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplaySupportedModesExt(g_displayIds[0], modes);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplaySupportedModesExtTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayModeAsyncTest
  * @tc.desc: Benchmarktest for interface SetDisplayModeAsyncTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayModeAsyncTest)(benchmark::State &state)
{
    int32_t ret;
    uint32_t modeid = 0;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayModeAsync(g_displayIds[0], modeid, OnMode);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayModeAsyncTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayVBlankPeriodTest
  * @tc.desc: Benchmarktest for interface GetDisplayVBlankPeriodTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayVBlankPeriodTest)(benchmark::State &state)
{
    int32_t ret;
    uint64_t period = 0;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayVBlankPeriod(g_displayIds[0], period);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayVBlankPeriodTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: RegSeamlessChangeCallbackTest
  * @tc.desc: Benchmarktest for interface RegSeamlessChangeCallbackTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, RegSeamlessChangeCallbackTest)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_composerDevice->RegSeamlessChangeCallback(OnseamlessChange, nullptr);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, RegSeamlessChangeCallbackTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetLayerPerFrameParameterTest
  * @tc.desc: Benchmarktest for interface SetLayerPerFrameParameter.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetLayerPerFrameParameterTest)(benchmark::State &state)
{
    int32_t ret;
    LayerInfo layerInfo;
    uint32_t layerId;
    std::string key = "FilmFilter";
    std::vector<int8_t> value = { 1 };
    uint32_t bufferCount = 3;
    ret = g_composerDevice->CreateLayer(g_displayIds[0], layerInfo, bufferCount, layerId);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_composerDevice->SetLayerPerFrameParameter(g_displayIds[0], layerId, key, value);
    }
    g_composerDevice->DestroyLayer(g_displayIds[0], layerId);
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetLayerPerFrameParameterTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetSupportedLayerPerFrameParameterKeyTest
  * @tc.desc: Benchmarktest for interface GetSupportedLayerPerFrameParameterKey.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetSupportedLayerPerFrameParameterKeyTest)(benchmark::State &state)
{
    int32_t ret;
    std::vector<std::string> keys;
    for (auto _ : state) {
        ret = g_composerDevice->GetSupportedLayerPerFrameParameterKey(keys);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetSupportedLayerPerFrameParameterKeyTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayOverlayResolutionTest
  * @tc.desc: Benchmarktest for interface SetDisplayOverlayResolution.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayOverlayResolutionTest)(benchmark::State &state)
{
    int32_t ret;
    DisplayModeInfo mode = HdiTestDevice::GetInstance().GetFirstDisplay()->GetCurrentMode();
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayOverlayResolution(g_displayIds[0], mode.width, mode.height);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayOverlayResolutionTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: RegRefreshCallbackTest
  * @tc.desc: Benchmarktest for interface RegRefreshCallback.
  */
BENCHMARK_F(DisplayBenchmarkTest, RegRefreshCallbackTest)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_composerDevice->RegRefreshCallback(TestRefreshCallback, nullptr);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, RegRefreshCallbackTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplaySupportedColorGamutsTest
  * @tc.desc: Benchmarktest for interface GetDisplaySupportedColorGamuts.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplaySupportedColorGamutsTest)(benchmark::State &state)
{
    int32_t ret;
    std::vector<ColorGamut> gamuts;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplaySupportedColorGamuts(g_displayIds[0], gamuts);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplaySupportedColorGamutsTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetHDRCapabilityInfosTest
  * @tc.desc: Benchmarktest for interface GetHDRCapabilityInfos.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetHDRCapabilityInfosTest)(benchmark::State &state)
{
    int32_t ret;
    HDRCapability info = { 0 };
    for (auto _ : state) {
        ret = g_composerDevice->GetHDRCapabilityInfos(g_displayIds[0], info);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetHDRCapabilityInfosTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayClientCropTest
  * @tc.desc: Benchmarktest for interface SetDisplayClientCrop.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayClientCropTest)(benchmark::State &state)
{
    int32_t ret;
    int32_t width = 100;
    int32_t height = 100;
    IRect rect = {0, 0, width, height};
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayClientCrop(g_displayIds[0], rect);
    }
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayClientCropTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: UpdateHardwareCursorTest
  * @tc.desc: Benchmarktest for interface UpdateHardwareCursorTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, UpdateHardwareCursorTest)(benchmark::State &state)
{
    int32_t ret = 0;
    int32_t x = 1;
    int32_t y = 1;
    BufferHandle* buffer = nullptr;

    AllocInfo info;
    info.width  = 512;
    info.height = 512;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_HW_COMPOSER;
    info.format = Composer::V1_0::PIXEL_FMT_RGBA_8888;

    g_gralloc->AllocMem(info, buffer);
    ASSERT_TRUE(buffer != nullptr);

    std::vector<LayerSettings> settings = {
        {.rectRatio = { 0, 0, 1.0f, 1.0f }, .color = RED,},
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    auto layer = layers[0];
    PrepareAndCommit();
    sleep(1);
    HdiTestDevice::GetInstance().Clear();
    DestroyLayer(layer);

    for (auto _ : state) {
        ret = g_composerDevice->UpdateHardwareCursor(g_displayIds[0], x, y, buffer);
    }
    if (ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT) {
        ret = DISPLAY_SUCCESS;
    }
    g_gralloc->FreeMem(*buffer);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, UpdateHardwareCursorTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: EnableHardwareCursorStatsTest
  * @tc.desc: Benchmarktest for interface EnableHardwareCursorStatsTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, EnableHardwareCursorStatsTest)(benchmark::State &state)
{
    int32_t ret = 0;
    bool enable = true;
    for (auto _ : state) {
        ret = g_composerDevice->EnableHardwareCursorStats(g_displayIds[0], enable);
    }
    if (ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT) {
        ret = DISPLAY_SUCCESS;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, EnableHardwareCursorStatsTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetHardwareCursorStatsTest
  * @tc.desc: Benchmarktest for interface GetHardwareCursorStatsTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetHardwareCursorStatsTest)(benchmark::State &state)
{
    int32_t ret = 0;
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    for (auto _ : state) {
        ret = g_composerDevice->GetHardwareCursorStats(g_displayIds[0], frameCount, vsyncCount);
    }
    if (ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT) {
        ret = DISPLAY_SUCCESS;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetHardwareCursorStatsTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: ClearClientBufferTest
  * @tc.desc: Benchmarktest for interface ClearClientBufferTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, ClearClientBufferTest)(benchmark::State &state)
{
    int32_t ret = 0;
    for (auto _ : state) {
        ret = g_composerDevice->ClearClientBuffer(g_displayIds[0]);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, ClearClientBufferTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: ClearLayerBufferTest
  * @tc.desc: Benchmarktest for interface ClearLayerBufferTest.
  */
BENCHMARK_F(DisplayBenchmarkTest, ClearLayerBufferTest)(benchmark::State &state)
{
    int32_t ret = 0;
    uint32_t layerId = 1;
    for (auto _ : state) {
        ret = g_composerDevice->ClearLayerBuffer(g_displayIds[0], layerId);
    }
    if (ret == DISPLAY_NOT_SUPPORT) {
        return;
    }
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, ClearLayerBufferTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

} // namespace

int main(int argc, char** argv)
{
    int ret = HdiTestDevice::GetInstance().InitDevice();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("Init Device Failed"));
    ::testing::InitGoogleTest(&argc, argv);
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }
    g_composerDevice = HdiTestDevice::GetInstance().GetDeviceInterface();
    DISPLAY_TEST_CHK_RETURN((g_composerDevice == nullptr), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("get composer interface failed"));
    g_gralloc.reset(IDisplayBuffer::Get());
    DISPLAY_TEST_CHK_RETURN((g_gralloc == nullptr), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("get buffer interface failed"));
    auto display = HdiTestDevice::GetInstance().GetFirstDisplay();
    if (display != nullptr) {
        g_displayIds = HdiTestDevice::GetInstance().GetDevIds();
        display->SetDisplayVsyncEnabled(false);
    }
    ::benchmark::RunSpecifiedBenchmarks();
    ::benchmark::Shutdown();
    HdiTestDevice::GetInstance().GetFirstDisplay()->ResetClientLayer();
    return ret;
}
