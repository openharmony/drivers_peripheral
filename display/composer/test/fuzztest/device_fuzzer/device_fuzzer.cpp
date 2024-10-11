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

#include "device_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <string>

#include "display_common_fuzzer.h"

namespace OHOS {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_2;

static sptr<Composer::V1_2::IDisplayComposerInterface> g_composerInterface = nullptr;
static std::shared_ptr<IDisplayBuffer> g_bufferInterface = nullptr;

static bool g_isInit = false;
static const uint8_t* g_data = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

static int32_t GetAllocInfo(AllocInfo& info)
{
    uint32_t lenUsage = GetArrLength(CONVERT_TABLE_USAGE);
    if (lenUsage == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_USAGE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t lenFormat = GetArrLength(CONVERT_TABLE_FORMAT);
    if (lenFormat == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_FORMAT length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }

    info.width = GetData<uint32_t>() % WIDTH;
    info.height = GetData<uint32_t>() % HEIGHT;
    info.usage = CONVERT_TABLE_USAGE[GetData<uint32_t>() % lenUsage];
    info.format = CONVERT_TABLE_FORMAT[GetData<uint32_t>() % lenFormat];
    info.expectedSize = info.width * info.height;

    return DISPLAY_SUCCESS;
}

static int32_t GetIRect(IRect& rect)
{
    rect.x = GetData<int32_t>();
    rect.y = GetData<int32_t>();
    rect.w = GetData<int32_t>();
    rect.h = GetData<int32_t>();
    return DISPLAY_SUCCESS;
}

BufferHandle* UsingAllocmem()
{
    AllocInfo info = { 0 };
    int32_t ret = GetAllocInfo(info);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetAllocInfo failed", __func__);
        return nullptr;
    }

    BufferHandle* handle = nullptr;
    ret = g_bufferInterface->AllocMem(info, handle);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function AllocMem failed", __func__);
        return nullptr;
    }
    return handle;
}

int32_t TestSetClientBufferCacheCount(uint32_t devId)
{
    uint32_t cacheCount = GetData<uint32_t>();
    int32_t ret = g_composerInterface->SetClientBufferCacheCount(devId, cacheCount);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetClientBufferCacheCount failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestGetDisplaySupportedModes(uint32_t devId)
{
    DisplayModeInfo info = { 0 };
    info.width = GetData<int32_t>() % WIDTH;
    info.height = GetData<int32_t>() % HEIGHT;
    info.freshRate = GetData<uint32_t>();
    info.id = GetData<int32_t>();

    std::vector<DisplayModeInfo> infos;
    infos.push_back(info);
    int32_t ret = g_composerInterface->GetDisplaySupportedModes(devId, infos);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplaySupportedModes failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetGetDisplayMode(uint32_t devId)
{
    uint32_t modeId = GetData<uint32_t>();
    int32_t ret = g_composerInterface->SetDisplayMode(devId, modeId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayMode failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->GetDisplayMode(devId, modeId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayMode failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetGetDisplayPowerStatus(uint32_t devId)
{
    uint32_t len = GetArrLength(CONVERT_TABLE_POWER_STATUS);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_POWER_STATUS length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    Composer::V1_0::DispPowerStatus status = CONVERT_TABLE_POWER_STATUS[GetData<uint32_t>() % len];
    int32_t ret = g_composerInterface->SetDisplayPowerStatus(devId, status);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayPowerStatus failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->GetDisplayPowerStatus(devId, status);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayPowerStatus failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestPrepareDisplayLayers(uint32_t devId)
{
    bool needFlushFb = GetRandBoolValue(GetData<uint32_t>());
    int32_t ret = g_composerInterface->PrepareDisplayLayers(devId, needFlushFb);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function PrepareDisplayLayers failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetGetDisplayBacklight(uint32_t devId)
{
    uint32_t level = GetData<uint32_t>();
    int32_t ret = g_composerInterface->SetDisplayBacklight(devId, level);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayBacklight failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->GetDisplayBacklight(devId, level);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayBacklight failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestGetDisplayProperty(uint32_t devId)
{
    uint32_t id = GetData<uint32_t>();
    uint64_t value = GetData<uint32_t>();
    int32_t ret = g_composerInterface->GetDisplayProperty(devId, id, value);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayProperty failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetHardwareCursorPosition(uint32_t devId)
{
    int32_t x = GetData<uint32_t>();
    int32_t y = GetData<uint32_t>();
    int32_t ret = g_composerInterface->SetHardwareCursorPosition(devId, x, y);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: function SetHardwareCursorPosition failed, %{public}d", __func__, ret);
        return DISPLAY_FAILURE;
    }
    return DISPLAY_SUCCESS;
}

int32_t TestEnableHardwareCursorStats(uint32_t devId)
{
    bool enable = GetRandBoolValue(GetData<uint32_t>());
    int32_t ret = g_composerInterface->EnableHardwareCursorStats(devId, enable);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: function EnableHardwareCursorStats failed, %{public}d", __func__, ret);
        return DISPLAY_FAILURE;
    }
    return DISPLAY_SUCCESS;
}

int32_t TestGetHardwareCursorStats(uint32_t devId)
{
    uint32_t frameCount = GetData<uint32_t>();
    uint32_t vsyncCount = GetData<uint32_t>();
    int32_t ret = g_composerInterface->GetHardwareCursorStats(devId, frameCount, vsyncCount);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: function GetHardwareCursorStats failed, %{public}d", __func__, ret);
        return DISPLAY_FAILURE;
    }
    return DISPLAY_SUCCESS;
}

int32_t TestGetDisplayCompChange(uint32_t devId)
{
    std::vector<uint32_t> layers;
    layers.push_back(GetData<uint32_t>());
    std::vector<int32_t> types;
    types.push_back(GetData<int32_t>());

    int32_t ret = g_composerInterface->GetDisplayCompChange(devId, layers, types);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayCompChange failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetDisplayClientCrop(uint32_t devId)
{
    IRect rect;
    int32_t ret = GetIRect(rect);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->SetDisplayClientCrop(devId, rect);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayClientCrop failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetDisplayClientDamage(uint32_t devId)
{
    IRect rect;
    int32_t ret = GetIRect(rect);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    std::vector<IRect> rects;
    rects.push_back(rect);
    ret = g_composerInterface->SetDisplayClientDamage(devId, rects);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayClientDamage failed", __func__);
    }
    return ret;
}

int32_t TestSetDisplayVsyncEnabled(uint32_t devId)
{
    bool enabled = GetRandBoolValue(GetData<uint32_t>());
    int32_t ret = g_composerInterface->SetDisplayVsyncEnabled(devId, enabled);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetDisplayVsyncEnabled failed", __func__);
    }
    return ret;
}

int32_t TestRegDisplayVBlankCallback(uint32_t devId)
{
    uint32_t param1 = GetData<uint32_t>();
    VBlankCallback param2 = GetData<VBlankCallback>();
    void* param3 = malloc(PARAM_VOIDPTR_LEN);
    if (param3 == nullptr) {
        HDF_LOGE("%{public}s: void* param3 malloc failed", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t ret = g_composerInterface->RegDisplayVBlankCallback(param1, param2, param3);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function RegDisplayVBlankCallback failed", __func__);
    }
    free(param3);
    param3 = nullptr;
    return ret;
}

int32_t TestGetDisplayReleaseFence(uint32_t devId)
{
    std::vector<uint32_t> layers;
    layers.push_back(GetData<uint32_t>());
    std::vector<int32_t> fences;
    fences.push_back(GetData<int32_t>());

    int32_t ret = g_composerInterface->GetDisplayReleaseFence(devId, layers, fences);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetDisplayReleaseFence failed", __func__);
    }
    return ret;
}

int32_t TestDestroyVirtualDisplay(uint32_t devId)
{
    int32_t ret = g_composerInterface->DestroyVirtualDisplay(devId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function DestroyVirtualDisplay failed", __func__);
    }
    return ret;
}

int32_t TestSetVirtualDisplayBuffer(uint32_t devId)
{
    int32_t fence = GetData<int32_t>();
    BufferHandle* buffer = UsingAllocmem();
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: Failed to UsingAllocmem", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t ret = g_composerInterface->SetVirtualDisplayBuffer(devId, *buffer, fence);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetVirtualDisplayBuffer failed", __func__);
    }
    g_bufferInterface->FreeMem(*buffer);
    return ret;
}

int32_t TestSetDisplayProperty(uint32_t devId)
{
    uint32_t id = GetData<uint32_t>();
    uint64_t value = GetData<uint64_t>();
    int32_t ret = g_composerInterface->SetDisplayProperty(devId, id, value);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: SetDisplayProperty failed", __func__);
    }
    return ret;
}

int32_t TestCommit(uint32_t devId)
{
    int32_t fence = GetData<int32_t>();
    int32_t ret = g_composerInterface->Commit(devId, fence);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function Commit failed", __func__);
    }
    return ret;
}

int TestGetDisplaySupportedModesExt(uint32_t devId)
{
    std::vector<DisplayModeInfoExt> modes;
    modes.push_back(GetData<DisplayModeInfoExt>());
    int32_t ret = g_composerInterface->GetDisplaySupportedModesExt(devId, modes);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: GetDisplaySupportedModesExt failed", __func__);
    }
    return ret;
}

void TestModeCallback(uint32_t modeId, uint64_t vBlankPeriod, void* data)
{
}

int TestSetDisplayModeAsync(uint32_t devId)
{
    uint32_t modeid = GetData<uint32_t>();
    int32_t ret = g_composerInterface->SetDisplayModeAsync(devId, modeid, TestModeCallback);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: SetDisplayModeAsync failed", __func__);
    }
    return ret;
}

int TestGetDisplayVBlankPeriod(uint32_t devId)
{
    uint64_t period = GetData<uint64_t>();
    int32_t ret = g_composerInterface->GetDisplayVBlankPeriod(devId, period);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: GetDisplayVBlankPeriod failed", __func__);
    }
    return ret;
}

void TestSeamlessChangeCallback(uint32_t devId, void* data)
{
}

int TestRegSeamlessChangeCallback(uint32_t devId)
{
    int32_t ret = g_composerInterface->RegSeamlessChangeCallback(TestSeamlessChangeCallback, nullptr);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: SetDisplayModeAsync failed", __func__);
    }
    return ret;
}

int TestGetSupportedLayerPerFrameParameterKey(uint32_t devId)
{
    std::vector<std::string> keys;
    int32_t ret = g_composerInterface->GetSupportedLayerPerFrameParameterKey(keys);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: failed with ret=%{public}d", __func__, ret);
    }
    return ret;
}

int TestSetDisplayOverlayResolution(uint32_t devId)
{
    uint32_t width = GetData<uint32_t>() % WIDTH;
    uint32_t height = GetData<uint32_t>() % HEIGHT;
    int32_t ret = g_composerInterface->SetDisplayOverlayResolution(devId, width, height);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: failed with ret=%{public}d", __func__, ret);
    }
    return ret;
}

static void TestRefreshCallback(uint32_t devId, void* data)
{
}

int TestRegRefreshCallback(uint32_t devId)
{
    int32_t ret = g_composerInterface->RegRefreshCallback(TestRefreshCallback, nullptr);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: failed with ret=%{public}d", __func__, ret);
    }
    return ret;
}

int TestGetDisplaySupportedColorGamuts(uint32_t devId)
{
    std::vector<ColorGamut> gamuts;
    int32_t ret = g_composerInterface->GetDisplaySupportedColorGamuts(devId, gamuts);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: failed with ret=%{public}d", __func__, ret);
    }
    return ret;
}

int TestGetHDRCapabilityInfos(uint32_t devId)
{
    HDRCapability info = { 0 };
    int32_t ret = g_composerInterface->GetHDRCapabilityInfos(devId, info);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: failed with ret=%{public}d", __func__, ret);
    }
    return ret;
}

typedef int32_t (*TestFuncs[])(uint32_t);

TestFuncs g_testFuncs = {
    TestSetClientBufferCacheCount,
    TestGetDisplaySupportedModes,
    TestSetGetDisplayMode,
    TestSetGetDisplayPowerStatus,
    TestPrepareDisplayLayers,
    TestSetGetDisplayBacklight,
    TestGetDisplayProperty,
    TestSetHardwareCursorPosition,
    TestEnableHardwareCursorStats,
    TestGetHardwareCursorStats,
    TestGetDisplayCompChange,
    TestSetDisplayClientCrop,
    TestSetDisplayClientDamage,
    TestSetDisplayVsyncEnabled,
    TestGetDisplayReleaseFence,
    TestDestroyVirtualDisplay,
    TestSetVirtualDisplayBuffer,
    TestSetDisplayProperty,
    TestGetDisplaySupportedModesExt,
    TestSetDisplayModeAsync,
    TestGetDisplayVBlankPeriod,
    TestRegSeamlessChangeCallback,
    TestGetSupportedLayerPerFrameParameterKey,
    TestSetDisplayOverlayResolution,
    TestRegRefreshCallback,
    TestGetDisplaySupportedColorGamuts,
    TestGetHDRCapabilityInfos,
    TestCommit,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    // initialize service
    if (!g_isInit) {
        g_isInit = true;
        g_composerInterface = Composer::V1_2::IDisplayComposerInterface::Get();
        if (g_composerInterface == nullptr) {
            HDF_LOGE("%{public}s: get IDisplayComposerInterface failed", __func__);
            return false;
        }
        g_bufferInterface.reset(IDisplayBuffer::Get());
        if (g_bufferInterface == nullptr) {
            HDF_LOGE("%{public}s: get IDisplayBuffer failed", __func__);
            return false;
        }
    }

    // initialize data
    g_data = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t devId = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len == 0) {
        HDF_LOGE("%{public}s: g_testFuncs length is equal to 0", __func__);
        return false;
    }

    int32_t ret = g_testFuncs[code % len](devId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("function %{public}u failed", code % len);
        return false;
    }

    return true;
}
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::FuzzTest(data, size);
    return 0;
}
