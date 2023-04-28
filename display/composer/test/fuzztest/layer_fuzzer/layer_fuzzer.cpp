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

#include "layer_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "display_common_fuzzer.h"
#include "v1_0/include/idisplay_composer_interface.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"

namespace OHOS {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;

static std::shared_ptr<IDisplayComposerInterface> g_composerInterface = nullptr;
static bool g_isInit = false;

static int32_t GetLayerInfo(LayerInfo& layerInfo, uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    // This will be read width, height, type, bpp and pixFormat of LayerInfo,
    // so we determine whether the size of the data is sufficient.
    size_t usedLen = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempWidth = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint32_t tempHeight = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempWidth)));
    uint32_t tempTypeIndex = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempWidth) + sizeof(tempHeight)));
    uint32_t lenLayerType = GetArrLength(CONVERT_TABLE_LAYER_TYPE);
    if (lenLayerType == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_LAYER_TYPE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempBpp = *reinterpret_cast<uint32_t*>(
        ShiftPointer(data, sizeof(tempWidth) + sizeof(tempHeight) + sizeof(tempTypeIndex)));
    uint32_t tempFormatIndex = *reinterpret_cast<uint32_t*>(
        ShiftPointer(data, sizeof(tempWidth) + sizeof(tempHeight) + sizeof(tempTypeIndex) + sizeof(tempBpp)));
    uint32_t lenFormat = GetArrLength(CONVERT_TABLE_FORMAT);
    if (lenFormat == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_FORMAT length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    layerInfo.width = tempWidth % WIDTH;
    layerInfo.height = tempHeight % HEIGHT;
    layerInfo.type = CONVERT_TABLE_LAYER_TYPE[tempTypeIndex % lenLayerType];
    layerInfo.bpp = tempBpp;
    layerInfo.pixFormat = CONVERT_TABLE_FORMAT[tempFormatIndex % lenFormat];
    return DISPLAY_SUCCESS;
}

static int32_t GetLayerAlpha(LayerAlpha& alpha, uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    // This will be read enGlobalAlpha, enPixelAlpha, alpha0, alpha1 and gAlpha of LayerAlpha,
    // so we determine whether the size of the data is sufficient.
    size_t usedLen = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempEnGlobalAlpha = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint32_t tempEnPixelAlpha = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempEnGlobalAlpha)));
    uint32_t tempAlpha0 = *reinterpret_cast<uint32_t*>(ShiftPointer(data,
        sizeof(tempEnGlobalAlpha) + sizeof(tempEnPixelAlpha)));
    uint32_t tempAlpha1 = *reinterpret_cast<uint32_t*>(ShiftPointer(data,
        sizeof(tempEnGlobalAlpha) + sizeof(tempEnPixelAlpha) + sizeof(tempAlpha0)));
    uint32_t tempGAlpha = *reinterpret_cast<uint32_t*>(ShiftPointer(data,
        sizeof(tempEnGlobalAlpha) + sizeof(tempEnPixelAlpha) + sizeof(tempAlpha0) + sizeof(tempAlpha1)));
    alpha.enGlobalAlpha = GetRandBoolValue(tempEnGlobalAlpha);
    alpha.enPixelAlpha = GetRandBoolValue(tempEnPixelAlpha);
    alpha.alpha0 = tempAlpha0 % ALPHAVALUERANGE;
    alpha.alpha1 = tempAlpha1 % ALPHAVALUERANGE;
    alpha.gAlpha = tempGAlpha % ALPHAVALUERANGE;
    return DISPLAY_SUCCESS;
}

int32_t UsingCreateLayer(uint8_t* data, size_t size, uint32_t devId, uint32_t& layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    LayerInfo layerInfo;
    int32_t ret = GetLayerInfo(layerInfo, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetLayerInfo failed", __func__);
        return DISPLAY_FAILURE;
    }

    ret = g_composerInterface->CreateLayer(devId, layerInfo, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function CreateLayer failed", __func__);
    }
    return ret;
}

int32_t UsingCloseLayer(uint32_t devId, uint32_t layerId)
{
    int32_t ret = g_composerInterface->DestroyLayer(devId, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function CloseLayer failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetLayerAlpha(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    LayerAlpha alpha = {0};
    int32_t ret = GetLayerAlpha(alpha, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetLayerAlpha failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->SetLayerAlpha(0, 0, alpha);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLyerAlpha failed", __func__);
        return DISPLAY_FAILURE;
    }
    return ret;
}

int32_t TestSetLayerRegion(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    IRect rect;
    int32_t ret = GetIRect(rect, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->SetLayerRegion(devId, layerId, rect);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerRegion failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerCrop(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    IRect rect;
    int32_t ret = GetIRect(rect, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    ret = g_composerInterface->SetLayerCrop(devId, layerId, rect);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerCrop failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerZorder(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t zorder = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    int32_t ret = g_composerInterface->SetLayerZorder(devId, layerId, zorder);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerZorder failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerPreMulti(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t temPreMul = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    bool preMul = GetRandBoolValue(temPreMul);
    int32_t ret = g_composerInterface->SetLayerPreMulti(devId, layerId, preMul);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerPreMulti failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerTransformMode(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    static const TransformType CONVERT_TABLE[] = {
        ROTATE_NONE,
        ROTATE_90,
        ROTATE_180,
        ROTATE_270,
        ROTATE_BUTT,
    };
    uint32_t tableIndex = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint32_t len = GetArrLength(CONVERT_TABLE);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    TransformType type = CONVERT_TABLE[tableIndex % len];
    int32_t ret = g_composerInterface->SetLayerTransformMode(devId, layerId, type);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerTransformMode failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerDirtyRegion(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    IRect region;
    int32_t ret = GetIRect(region, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    std::vector<IRect> vRects;
    vRects.push_back(region);
    ret = g_composerInterface->SetLayerDirtyRegion(devId, layerId, vRects);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerDirtyRegion failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerVisibleRegion(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    IRect rect;
    int32_t ret = GetIRect(rect, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetIRect failed", __func__);
        return DISPLAY_FAILURE;
    }
    std::vector<IRect> vRects;
    vRects.push_back(rect);
    ret = g_composerInterface->SetLayerVisibleRegion(devId, layerId, vRects);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerVisibleRegion failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerBuffer(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(int32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t fence = *reinterpret_cast<int32_t*>(ShiftPointer(data, 0));
    BufferHandle* buffer = UsingAllocmem(data, size);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: Failed to UsingAllocmem", __func__);
        return DISPLAY_FAILURE;
    }
    int32_t ret = g_composerInterface->SetLayerBuffer(devId, layerId, *buffer, fence);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerBuffer failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerCompositionType(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    static const CompositionType CONVERT_TABLE[] = {
        COMPOSITION_CLIENT,
        COMPOSITION_DEVICE,
        COMPOSITION_CURSOR,
        COMPOSITION_VIDEO,
        COMPOSITION_DEVICE_CLEAR,
        COMPOSITION_CLIENT_CLEAR,
        COMPOSITION_TUNNEL,
        COMPOSITION_BUTT,
    };
    uint32_t tableIndex = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint32_t len = GetArrLength(CONVERT_TABLE);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    CompositionType type = CONVERT_TABLE[tableIndex % len];
    int32_t ret = g_composerInterface->SetLayerCompositionType(devId, layerId, type);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerCompositionType failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerBlendType(uint8_t* data, size_t size, uint32_t devId, uint32_t layerId)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(uint32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    static const BlendType CONVERT_TABLE[] = {
        BLEND_NONE,
        BLEND_CLEAR,
        BLEND_SRC,
        BLEND_SRCOVER,
        BLEND_DSTOVER,
        BLEND_SRCIN,
        BLEND_DSTIN,
        BLEND_SRCOUT,
        BLEND_DSTOUT,
        BLEND_SRCATOP,
        BLEND_DSTATOP,
        BLEND_ADD,
        BLEND_XOR,
        BLEND_DST,
        BLEND_AKS,
        BLEND_AKD,
        BLEND_BUTT,
    };
    uint32_t tableIndex = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint32_t len = GetArrLength(CONVERT_TABLE);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    BlendType type = CONVERT_TABLE[tableIndex % len];
    int32_t ret = g_composerInterface->SetLayerBlendType(devId, layerId, type);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerBlendType failed", __func__);
    }
    return ret;
}

typedef int32_t (*TestFuncs[])(uint8_t*, size_t, uint32_t, uint32_t);

TestFuncs g_testFuncs = {
    TestSetLayerAlpha,
    TestSetLayerRegion,
    TestSetLayerCrop,
    TestSetLayerZorder,
    TestSetLayerPreMulti,
    TestSetLayerTransformMode,
    TestSetLayerDirtyRegion,
    TestSetLayerVisibleRegion,
    TestSetLayerBuffer,
    TestSetLayerCompositionType,
    TestSetLayerBlendType
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr || size < (OFFSET + OFFSET + OFFSET)) {
        return false;
    }

    if (!g_isInit) {
        g_isInit = true;
        g_composerInterface.reset(IDisplayComposerInterface::Get());
        if (g_composerInterface == nullptr) {
            HDF_LOGE("%{public}s: get IDisplayComposerInterface failed", __func__);
            return false;
        }
    }

    uint32_t code = Convert2Uint32(rawData, size);
    rawData = rawData + OFFSET;
    size = size - OFFSET;
    uint32_t devId = Convert2Uint32(rawData, size);
    rawData = rawData + OFFSET;
    uint32_t layerId = Convert2Uint32(rawData, size);
    rawData = rawData + OFFSET;

    uint8_t* data = const_cast<uint8_t*>(rawData);
    if (data == nullptr) {
        HDF_LOGE("%{public}s: can not get data", __func__);
        return false;
    }

    int32_t ret = UsingCreateLayer(data, size, devId, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function UsingCreateLayer failed", __func__);
        return false;
    }

    uint32_t len = GetArrLength(g_testFuncs);
    if (len == 0) {
        HDF_LOGE("%{public}s: g_testFuncs length is equal to 0", __func__);
        return false;
    }

    ret = g_testFuncs[code % len](data, size, devId, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("function %{public}u failed", code % len);
        return false;
    }

    ret = UsingCloseLayer(devId, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function UsingCloseLayer failed", __func__);
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
