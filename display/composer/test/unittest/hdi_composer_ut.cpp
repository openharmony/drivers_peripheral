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
#include "v1_0/hdi_impl/display_buffer_hdi_impl.h"
#include "v1_0/display_command/display_cmd_requester.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::TEST;
using namespace testing::ext;

static sptr<IDisplayComposerInterface> g_composerDevice = nullptr;
static std::shared_ptr<IDisplayBuffer> g_gralloc = nullptr;
static std::vector<uint32_t> g_displayIds;
const int SLEEP_CONT_100 = 100;
const int SLEEP_CONT_2000 = 2000;

static inline std::shared_ptr<HdiTestDisplay> GetFirstDisplay()
{
    return HdiTestDevice::GetInstance().GetFirstDisplay();
}

static int32_t CheckComposition(std::vector<LayerSettings> &layers, BufferHandle* clientBuffer,
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

static void TestVBlankCallback(unsigned int sequence, uint64_t ns, void* data)
{
    static uint64_t lastns;
    DISPLAY_TEST_LOGD("seq %{public}d  ns %" PRId64 " duration %" PRId64 " ns", sequence, ns, (ns - lastns));
    lastns = ns;
    VblankCtr::GetInstance().NotifyVblank(sequence, ns, data);
}

static void AdjustLayerSettings(std::vector<LayerSettings> &settings, uint32_t w, uint32_t h)
{
    DISPLAY_TEST_LOGD();
    for (uint32_t i = 0; i < settings.size(); i++) {
        LayerSettings& setting = settings[i];
        DISPLAY_TEST_LOGD(" ratio w: %f  ratio h: %f", setting.rectRatio.w, setting.rectRatio.h);
        if ((setting.rectRatio.w > 0.0f) && (setting.rectRatio.h > 0.0f)) {
            setting.displayRect.h = static_cast<uint32_t>(setting.rectRatio.h * h);
            setting.displayRect.w = static_cast<uint32_t>(setting.rectRatio.w * w);
            setting.displayRect.x = static_cast<uint32_t>(setting.rectRatio.x * w);
            setting.displayRect.y = static_cast<uint32_t>(setting.rectRatio.y * h);
            DISPLAY_TEST_LOGD("display rect adust form %f %f %f %f to %{public}d %{public}d %{public}d %{public}d ",
                setting.rectRatio.x, setting.rectRatio.y, setting.rectRatio.w, setting.rectRatio.h,
                setting.displayRect.x, setting.displayRect.y, setting.displayRect.w, setting.displayRect.h);
        }

        if ((setting.bufferRatio.h > 0.0f) || (setting.bufferRatio.w > 0.0f)) {
            setting.bufferSize.h = static_cast<uint32_t>(setting.bufferRatio.h * h);
            setting.bufferSize.w = static_cast<uint32_t>(setting.bufferRatio.w * w);
            DISPLAY_TEST_LOGD("buffer size adjust for %f %f to %{public}d %{public}d",
                setting.bufferRatio.w, setting.bufferRatio.h, setting.bufferSize.w, setting.bufferSize.h);
        }

        if ((setting.bufferSize.w == 0) || (setting.bufferSize.h == 0)) {
            DISPLAY_TEST_LOGD("buffer size adjust for %{public}d %{public}d to %{public}d %{public}d",
                setting.bufferSize.w, setting.bufferSize.h, setting.displayRect.w, setting.displayRect.h);

            setting.bufferSize.w = setting.displayRect.w;
            setting.bufferSize.h = setting.displayRect.h;
        }
    }
}

static std::vector<std::shared_ptr<HdiTestLayer>> CreateLayers(std::vector<LayerSettings> &settings)
{
    DISPLAY_TEST_LOGD("settings %{public}zd", settings.size());
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
    if ((GetFirstDisplay()->SnapShot()) != nullptr) {
        HdiTestDevice::GetInstance().GetGrallocInterface()->InvalidateCache(*(GetFirstDisplay()->SnapShot()));
        ret = CheckComposition(layerSettings, GetFirstDisplay()->SnapShot(), checkType);
        ASSERT_TRUE((ret == DISPLAY_SUCCESS));
    }
}

void DeviceTest::SetUpTestCase()
{
    int ret = HdiTestDevice::GetInstance().InitDevice();
    ASSERT_TRUE(ret == DISPLAY_SUCCESS);

    g_composerDevice = HdiTestDevice::GetInstance().GetDeviceInterface();
    ASSERT_TRUE(g_composerDevice != nullptr);

    g_gralloc.reset(IDisplayBuffer::Get());
    ASSERT_TRUE(g_gralloc != nullptr);

    g_displayIds = HdiTestDevice::GetInstance().GetDevIds();
    ASSERT_TRUE(g_displayIds.size() > 0);
}

void DeviceTest::TearDownTestCase()
{
    HdiTestDevice::GetInstance().Clear();
    HdiTestDevice::GetInstance().GetFirstDisplay()->ResetClientLayer();
}

void VblankCtr::NotifyVblank(unsigned int sequence, uint64_t ns, const void* data)
{
    DISPLAY_TEST_LOGD();
    if (data != nullptr) {
        DISPLAY_TEST_LOGD("sequence = %{public}u, ns = %" PRIu64 "", sequence, ns);
    }
    std::unique_lock<std::mutex> lg(vblankMutex_);
    hasVblank_ = true;
    vblankCondition_.notify_one();
    DISPLAY_TEST_LOGD();
}

VblankCtr::~VblankCtr() {}

int32_t VblankCtr::WaitVblank(uint32_t ms)
{
    bool ret = false;
    DISPLAY_TEST_LOGD();
    std::unique_lock<std::mutex> lck(vblankMutex_);
    hasVblank_ = false; // must wait next vblank
    ret = vblankCondition_.wait_for(lck, std::chrono::milliseconds(ms), [=] { return hasVblank_; });
    DISPLAY_TEST_LOGD();
    if (!ret) {
        return DISPLAY_FAILURE;
    }
    return DISPLAY_SUCCESS;
}

HWTEST_F(DeviceTest, test_SetClientBufferCacheCount, TestSize.Level1)
{
    const uint32_t CACHE_COUNT = 5;
    auto ret = g_composerDevice->SetClientBufferCacheCount(g_displayIds[0], CACHE_COUNT);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayCapability, TestSize.Level1)
{
    DisplayCapability info;
    auto ret = g_composerDevice->GetDisplayCapability(g_displayIds[0], info);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplaySupportedModes, TestSize.Level1)
{
    std::vector<DisplayModeInfo> modes;
    auto ret = g_composerDevice->GetDisplaySupportedModes(g_displayIds[0], modes);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayMode, TestSize.Level1)
{
    uint32_t MODE = 0;
    auto ret = g_composerDevice->GetDisplayMode(g_displayIds[0], MODE);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayMode, TestSize.Level1)
{
    const uint32_t MODE = 0;
    auto ret = g_composerDevice->SetDisplayMode(g_displayIds[0], MODE);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayPowerStatus, TestSize.Level1)
{
    DispPowerStatus powerStatus = DispPowerStatus::POWER_STATUS_OFF;
    auto ret = g_composerDevice->GetDisplayPowerStatus(g_displayIds[0], powerStatus);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayPowerStatus, TestSize.Level1)
{
    auto ret = g_composerDevice->SetDisplayPowerStatus(g_displayIds[0], DispPowerStatus::POWER_STATUS_STANDBY);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);

    ret = g_composerDevice->SetDisplayPowerStatus(g_displayIds[0], DispPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

#ifdef DISPLAY_COMMUNITY
HWTEST_F(DeviceTest, test_GetDisplayBacklight, TestSize.Level1)
{
    uint32_t level;
    auto ret = g_composerDevice->GetDisplayBacklight(g_displayIds[0], level);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}
#endif

HWTEST_F(DeviceTest, test_SetDisplayBacklight, TestSize.Level1)
{
    const uint32_t LEVEL = 10;
    auto ret = g_composerDevice->SetDisplayBacklight(g_displayIds[0], LEVEL);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayProperty, TestSize.Level1)
{
    const uint32_t PROPERTY_ID = 1;
    uint64_t propertyValue = 0;
    auto ret = g_composerDevice->GetDisplayProperty(g_displayIds[0], PROPERTY_ID, propertyValue);
    // not support
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayCompChange, TestSize.Level1)
{
    std::vector<uint32_t> layers {};
    std::vector<int32_t> type {};
    auto ret = g_composerDevice->GetDisplayCompChange(g_displayIds[0], layers, type);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientCrop, TestSize.Level1)
{
    const int32_t WIDTH = 1920;
    const int32_t HEIGHT = 1080;
    IRect rect = {0, 0, WIDTH, HEIGHT};
    auto ret = g_composerDevice->SetDisplayClientCrop(g_displayIds[0], rect);
    // not support
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_GetDisplayReleaseFence, TestSize.Level1)
{
    std::vector<uint32_t> layers {};
    std::vector<int32_t> fences {};
    auto ret = g_composerDevice->GetDisplayReleaseFence(g_displayIds[0], layers, fences);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientBuffer, TestSize.Level1)
{
    BufferHandle* buffer = nullptr;
    const int32_t WIDTH = 800;
    const int32_t HEIGHT = 600;

    AllocInfo info;
    info.width  = WIDTH;
    info.height = HEIGHT;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_8888;

    g_gralloc->AllocMem(info, buffer);
    ASSERT_TRUE(buffer != nullptr);

    uint32_t bufferSeq = 1;
    auto ret = g_composerDevice->SetDisplayClientBuffer(g_displayIds[0], buffer, bufferSeq, -1);
    g_gralloc->FreeMem(*buffer);
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayClientDamage, TestSize.Level1)
{
    const int32_t WIDTH = 1920;
    const int32_t HEIGHT = 1080;
    IRect rect = {0, 0, WIDTH, HEIGHT};
    std::vector<IRect> vRects;
    vRects.push_back(rect);
    auto ret = g_composerDevice->SetDisplayClientDamage(g_displayIds[0], vRects);
    // not support
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_CreateVirtualDisplay, TestSize.Level1)
{
    const uint32_t WIDTH = 1920;
    const uint32_t HEIGHT = 1080;
    int32_t format = 0;
    uint32_t devId = 0;
    auto ret = g_composerDevice->CreateVirtualDisplay(WIDTH, HEIGHT, format, devId);
    // not support
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_DestroyVirtualDisplay, TestSize.Level1)
{
    uint32_t devId = 0;
    auto ret = g_composerDevice->DestroyVirtualDisplay(devId);
    // not support
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetVirtualDisplayBuffer, TestSize.Level1)
{
    BufferHandle* buffer = nullptr;
    int32_t fence = -1;
    const int32_t WIDTH = 800;
    const int32_t HEIGHT = 600;

    AllocInfo info;
    info.width  = WIDTH;
    info.height = HEIGHT;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_8888;

    g_gralloc->AllocMem(info, buffer);
    ASSERT_TRUE(buffer != nullptr);

    auto ret = g_composerDevice->SetVirtualDisplayBuffer(g_displayIds[0], *buffer, fence);
    g_gralloc->FreeMem(*buffer);
    // not support
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetDisplayProperty, TestSize.Level1)
{
    const uint32_t PROPERTY_ID = 1;
    const uint64_t PROPERTY_VALUE = 0;
    auto ret = g_composerDevice->SetDisplayProperty(g_displayIds[0], PROPERTY_ID, PROPERTY_VALUE);
    // not support
    EXPECT_EQ(DISPLAY_FAILURE, ret);
}

HWTEST_F(DeviceTest, test_SetLayerCrop, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        },
    };
    std::vector<uint32_t> splitColors = { { RED, GREEN, YELLOW, BLUE, PINK, PURPLE, CYAN, TRANSPARENT } };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    // split the buffer
    auto layer = layers[0];
    HdiGrallocBuffer* handle = layer->GetBackBuffer(); // the backbuffer has not present now
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
            .color = RED
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = YELLOW
        },
    };

    std::vector<std::vector<int>> zorders = {
        { 3, 2, 1 }, { 1, 3, 2 }, { 3, 1, 2 }, { 1, 2, 3 }, { 2, 1, 3 }, { 2, 3, 1 },
    };
    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);

    for (const auto& zorderList : zorders) {
        // adjust the zorder
        for (uint32_t i = 0; i < zorderList.size(); i++) {
            settings[i].zorder = zorderList[i];
            layers[i]->SetZorder(zorderList[i]);
        }
        std::vector<LayerSettings> tempSettings = settings;
        std::sort(tempSettings.begin(), tempSettings.end(),
            [=](const auto& l, auto const & r) { return l.zorder < r.zorder; });
        // present and check
        PresentAndCheck(tempSettings);
    }
    HdiTestDevice::GetInstance().Clear();
}

HWTEST_F(DeviceTest, test_SetLayerPreMulti, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        },
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    PrepareAndPrensent();

    auto layer = layers[0];
    bool preMul = true;
    auto ret = g_composerDevice->SetLayerPreMulti(g_displayIds[0], layer->GetId(), preMul);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerAlpha, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = GREEN
        },
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        },
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

HWTEST_F(DeviceTest, test_SetLayerRegion, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {.rectRatio = {0, 0, 1.0f, 1.0f}, .color = GREEN, .alpha = 0xFF}
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    const int32_t WIDTH = 100;
    const int32_t HEIGHT = 100;
    auto layer = layers[0];
    IRect rect = {0, 0, WIDTH, HEIGHT};
    auto ret = g_composerDevice->SetLayerRegion(g_displayIds[0], layer->GetId(), rect);

    PrepareAndPrensent();
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerDirtyRegion, TestSize.Level1)
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

    const int32_t WIDTH = 100;
    const int32_t HEIGHT = 100;
    IRect rect = {0, 0, WIDTH, HEIGHT};
    std::vector<IRect> vRects;
    vRects.push_back(rect);
    auto ret = g_composerDevice->SetLayerDirtyRegion(g_displayIds[0], layer->GetId(), vRects);

    PrepareAndPrensent();
    HdiTestDevice::GetInstance().Clear();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerTransformMode, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = RED
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));

    PrepareAndPrensent();

    auto layer = layers[0];

    TransformType type = TransformType::ROTATE_90;
    auto ret = g_composerDevice->SetLayerTransformMode(g_displayIds[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_180;
    ret = g_composerDevice->SetLayerTransformMode(g_displayIds[0], layer->GetId(), type);
    PrepareAndPrensent();

    type = TransformType::ROTATE_270;
    ret = g_composerDevice->SetLayerTransformMode(g_displayIds[0], layer->GetId(), type);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerVisibleRegion, TestSize.Level1)
{
    std::vector<LayerSettings> settings = {
        {
            .rectRatio = { 0, 0, 1.0f, 1.0f },
            .color = BLUE
        }
    };

    std::vector<std::shared_ptr<HdiTestLayer>> layers = CreateLayers(settings);
    ASSERT_TRUE((layers.size() > 0));
    PrepareAndPrensent();
    auto layer = layers[0];

    const int32_t WIDTH = 500;
    const int32_t HEIGHT = 500;
    IRect region = {0, 0, WIDTH, HEIGHT};
    std::vector<IRect> regions = {};
    regions.push_back(region);
    auto ret = g_composerDevice->SetLayerVisibleRegion(g_displayIds[0], layer->GetId(), regions);
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBuffer, TestSize.Level1)
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

    auto graphicBuffer = layer->AcquireBackBuffer();
    int32_t ret = graphicBuffer->SetGraphicBuffer([&](const BufferHandle* buffer, uint32_t seqNo) -> int32_t {
        std::vector<uint32_t> deletingList;
        int32_t result = g_composerDevice->SetLayerBuffer(g_displayIds[0], layer->GetId(), buffer, seqNo, -1,
            deletingList);
        return result;
    });
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerCompositionType, TestSize.Level1)
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
    auto ret = g_composerDevice->SetLayerCompositionType(g_displayIds[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerBlendType, TestSize.Level1)
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
    auto ret = g_composerDevice->SetLayerBlendType(g_displayIds[0], layer->GetId(), type);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerMaskInfo, TestSize.Level1)
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

    MaskInfo maskInfo = MaskInfo::LAYER_HBM_SYNC;
    auto ret = g_composerDevice->SetLayerMaskInfo(g_displayIds[0], layer->GetId(), maskInfo);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_SetLayerColor, TestSize.Level1)
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
    const uint32_t COLOR_R = 155;
    const uint32_t COLOR_G = 224;
    const uint32_t COLOR_B = 88;
    const uint32_t COLOR_A = 128;

    LayerColor layerColor = {
        .r = COLOR_R,
        .g = COLOR_G,
        .b = COLOR_B,
        .a = COLOR_A
    };

    auto ret = g_composerDevice->SetLayerColor(g_displayIds[0], layer->GetId(), layerColor);

    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_DestroyLayer, TestSize.Level1)
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
    auto ret = g_composerDevice->DestroyLayer(g_displayIds[0], layer->GetId());
    PrepareAndPrensent();

    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

HWTEST_F(DeviceTest, test_RegDisplayVBlankCallback, TestSize.Level1)
{
    int ret;
    DISPLAY_TEST_LOGD();
    std::shared_ptr<HdiTestDisplay> display = HdiTestDevice::GetInstance().GetFirstDisplay();
    ASSERT_TRUE(display != nullptr) << "get display failed";
    ret = display->RegDisplayVBlankCallback(TestVBlankCallback, nullptr);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "RegDisplayVBlankCallback failed";
    ret = display->SetDisplayVsyncEnabled(true);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "SetDisplayVsyncEnabled failed";
    ret = VblankCtr::GetInstance().WaitVblank(SLEEP_CONT_2000); // 2000ms
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "WaitVblank timeout";
    ret = display->SetDisplayVsyncEnabled(false);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS) << "SetDisplayVsyncEnabled failed";
    usleep(SLEEP_CONT_100 * SLEEP_CONT_2000); // wait for 100ms avoid the last vsync.
    ret = VblankCtr::GetInstance().WaitVblank(SLEEP_CONT_2000); // 2000ms
    ASSERT_TRUE(ret != DISPLAY_SUCCESS) << "vblank do not disable";
}

constexpr int32_t FD_INVALID = -1;
constexpr int32_t FD_INVALID_2 = 1000;

// test Init() with invalid fd
HWTEST_F(DeviceTest, test_HdifdParcelable_Init_1, TestSize.Level1)
{
    bool ret;
    HdifdParcelable hdifdParcelable(FD_INVALID);
    ret = hdifdParcelable.Init(FD_INVALID);
    EXPECT_EQ(false, ret);
}

// test Init() with invalid fd that is not -1
HWTEST_F(DeviceTest, test_HdifdParcelable_Init_2, TestSize.Level1)
{
    bool ret;
    HdifdParcelable hdifdParcelable(FD_INVALID);
    ret = hdifdParcelable.Init(FD_INVALID_2);
    EXPECT_EQ(false, ret);
}

// test Move() with invalid fd
HWTEST_F(DeviceTest, test_Move, TestSize.Level1)
{
    int32_t hdiFd;
    HdifdParcelable hdifdParcelable;
    hdiFd = hdifdParcelable.Move();
    EXPECT_EQ(FD_INVALID, hdiFd);
}

// test GetFd() with invalid fd
HWTEST_F(DeviceTest, test_GetFd, TestSize.Level1)
{
    int32_t hdiFd;
    HdifdParcelable hdifdParcelable;
    hdiFd = hdifdParcelable.GetFd();
    EXPECT_EQ(FD_INVALID, hdiFd);
}

// test Dump with invalid fd
HWTEST_F(DeviceTest, test_Dump, TestSize.Level1)
{
    HdifdParcelable hdifdParcelable;
    std::string  str = hdifdParcelable.Dump();
    std::string dump("fd: {-1}\n");
    ASSERT_TRUE(dump.compare(str) == 0) << "Dump Result" << str;
}

HWTEST_F(DeviceTest, test_AddDeathRecipient, TestSize.Level1)
{
    bool ret;
    sptr<IRemoteObject::DeathRecipient> recipient;
    ret = g_gralloc->AddDeathRecipient(recipient);
    EXPECT_EQ(true, ret);
}

HWTEST_F(DeviceTest, test_IsSupportedAlloc, TestSize.Level1)
{
    int32_t ret;
    const std::vector<VerifyAllocInfo> infos;
    std::vector<bool> supporteds;
    ret = g_gralloc->IsSupportedAlloc(infos, supporteds);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}