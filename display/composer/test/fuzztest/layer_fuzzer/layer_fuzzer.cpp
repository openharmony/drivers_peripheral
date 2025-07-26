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
#include <securec.h>

#include "display_common_fuzzer.h"

namespace OHOS {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_1;

static sptr<Composer::V1_3::IDisplayComposerInterface> g_composerInterface = nullptr;
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

static int32_t GetLayerInfo(LayerInfo& layerInfo)
{
    uint32_t lenLayerType = GetArrLength(CONVERT_TABLE_LAYER_TYPE);
    if (lenLayerType == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_LAYER_TYPE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }

    uint32_t lenFormat = GetArrLength(CONVERT_TABLE_FORMAT);
    if (lenFormat == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_FORMAT length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    layerInfo.width = GetData<uint32_t>() % WIDTH;
    layerInfo.height = GetData<uint32_t>() % HEIGHT;
    layerInfo.type = CONVERT_TABLE_LAYER_TYPE[GetData<uint32_t>() % lenLayerType];
    layerInfo.bpp = GetData<uint32_t>();
    layerInfo.pixFormat = CONVERT_TABLE_FORMAT[GetData<uint32_t>() % lenFormat];
    return DISPLAY_SUCCESS;
}

static int32_t GetLayerAlpha(LayerAlpha& alpha)
{
    alpha.enGlobalAlpha = GetRandBoolValue(GetData<uint32_t>());
    alpha.enPixelAlpha = GetRandBoolValue(GetData<uint32_t>());
    alpha.alpha0 = GetData<uint32_t>() % ALPHA_VALUE_RANGE;
    alpha.alpha1 = GetData<uint32_t>() % ALPHA_VALUE_RANGE;
    alpha.gAlpha = GetData<uint32_t>() % ALPHA_VALUE_RANGE;
    return DISPLAY_SUCCESS;
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

int32_t UsingCreateLayer(uint32_t devId, uint32_t& layerId)
{
    LayerInfo layerInfo;
    int32_t ret = GetLayerInfo(layerInfo);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetLayerInfo failed", __func__);
        return DISPLAY_FAILURE;
    }

    uint32_t bufferCount = 3;
    ret = g_composerInterface->CreateLayer(devId, layerInfo, bufferCount, layerId);
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

int32_t TestSetLayerAlpha(uint32_t devId, uint32_t layerId)
{
    LayerAlpha alpha = {0};
    int32_t ret = GetLayerAlpha(alpha);
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

int32_t TestSetLayerRegion(uint32_t devId, uint32_t layerId)
{
    IRect rect;
    int32_t ret = GetIRect(rect);
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

int32_t TestSetLayerCrop(uint32_t devId, uint32_t layerId)
{
    IRect rect;
    int32_t ret = GetIRect(rect);
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

int32_t TestSetLayerZorder(uint32_t devId, uint32_t layerId)
{
    uint32_t zorder = GetData<uint32_t>();
    int32_t ret = g_composerInterface->SetLayerZorder(devId, layerId, zorder);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerZorder failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerPreMulti(uint32_t devId, uint32_t layerId)
{
    bool preMul = GetRandBoolValue(GetData<uint32_t>());
    int32_t ret = g_composerInterface->SetLayerPreMulti(devId, layerId, preMul);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerPreMulti failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerTransformMode(uint32_t devId, uint32_t layerId)
{
    uint32_t len = GetArrLength(CONVERT_TABLE_ROTATE);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_ROTATE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    TransformType type = CONVERT_TABLE_ROTATE[GetData<uint32_t>() % len];
    int32_t ret = g_composerInterface->SetLayerTransformMode(devId, layerId, type);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerTransformMode failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerDirtyRegion(uint32_t devId, uint32_t layerId)
{
    IRect region;
    int32_t ret = GetIRect(region);
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

int32_t TestSetLayerVisibleRegion(uint32_t devId, uint32_t layerId)
{
    IRect rect;
    int32_t ret = GetIRect(rect);
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

int32_t TestSetLayerBuffer(uint32_t devId, uint32_t layerId)
{
    int32_t fence = GetData<int32_t>();
    BufferHandle* buffer = UsingAllocmem();
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: Failed to UsingAllocmem", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t seqNo = GetData<uint32_t>();
    std::vector<uint32_t> deletingList;
    int32_t ret = g_composerInterface->SetLayerBuffer(devId, layerId, buffer, seqNo, fence, deletingList);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerBuffer failed", __func__);
    }
    g_bufferInterface->FreeMem(*buffer);
    return ret;
}

int32_t TestSetLayerCompositionType(uint32_t devId, uint32_t layerId)
{
    uint32_t len = GetArrLength(CONVERT_TABLE_COMPOSITION);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_COMPOSITION length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    Composer::V1_0::CompositionType type = CONVERT_TABLE_COMPOSITION[GetData<uint32_t>() % len];
    int32_t ret = g_composerInterface->SetLayerCompositionType(devId, layerId, type);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerCompositionType failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerBlendType(uint32_t devId, uint32_t layerId)
{
    uint32_t len = GetArrLength(CONVERT_TABLE_BLEND);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_BLEND length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    BlendType type = CONVERT_TABLE_BLEND[GetData<uint32_t>() % len];
    int32_t ret = g_composerInterface->SetLayerBlendType(devId, layerId, type);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerBlendType failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerMaskInfo(uint32_t devId, uint32_t layerId)
{
    uint32_t len = GetArrLength(CONVERT_TABLE_MASK);
    if (len == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_MASK length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    MaskInfo maskInfo = CONVERT_TABLE_MASK[GetData<uint32_t>() % len];
    int32_t ret = g_composerInterface->SetLayerMaskInfo(devId, layerId, maskInfo);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerMaskInfo failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerColor(uint32_t devId, uint32_t layerId)
{
    LayerColor layerColor = {
        .r = GetData<uint32_t>() % ALPHA_VALUE_RANGE,
        .g = GetData<uint32_t>() % ALPHA_VALUE_RANGE,
        .b = GetData<uint32_t>() % ALPHA_VALUE_RANGE,
        .a = GetData<uint32_t>() % ALPHA_VALUE_RANGE
    };
    int32_t ret = g_composerInterface->SetLayerColor(devId, layerId, layerColor);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function SetLayerColor failed", __func__);
    }
    return ret;
}

int32_t TestSetLayerPerFrameParameter(uint32_t devId, uint32_t layerId)
{
    std::vector<std::string> ValidKeys = { "FilmFilter", "ArsrDoEnhance", "SDRBrightnessRatio", "BrightnessNit",
        "ViewGroupHasValidAlpha", "SourceCropTuning" };
    std::string key = ValidKeys[0];
    std::vector<int8_t> value;
    value.push_back(GetData<int8_t>());
    int32_t ret = g_composerInterface->SetLayerPerFrameParameter(devId, layerId, key, value);
    if ((ret != DISPLAY_SUCCESS) && (ret != DISPLAY_NOT_SUPPORT)) {
        HDF_LOGE("%{public}s: failed with ret=%{public}d", __func__, ret);
    }
    return ret;
}

typedef int32_t (*TestFuncs[])(uint32_t, uint32_t);

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
    TestSetLayerBlendType,
    TestSetLayerColor,
    TestSetLayerPerFrameParameter,
    TestSetLayerMaskInfo
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    if (!g_isInit) {
        g_isInit = true;
        g_composerInterface = Composer::V1_3::IDisplayComposerInterface::Get();
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
    uint32_t layerId = GetData<uint32_t>();
    int32_t ret = UsingCreateLayer(devId, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function UsingCreateLayer failed", __func__);
        return false;
    }
    
    uint32_t len = GetArrLength(g_testFuncs);
    if (len == 0) {
        HDF_LOGE("%{public}s: g_testFuncs length is equal to 0", __func__);
        return false;
    }

    ret = g_testFuncs[code % len](devId, layerId);
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
