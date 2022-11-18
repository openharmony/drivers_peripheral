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

#include "hdi_test_display.h"
#include "display_test_utils.h"
#include "hdi_test_device.h"
namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_0;
    HdiTestDisplay::HdiTestDisplay(uint32_t id, std::shared_ptr<IDisplayComposerInterface> device)
        : mId(id), device_(device)
{
}

int32_t HdiTestDisplay::Init()
{
    DISPLAY_TEST_LOGD();
    int ret = device_->GetDisplayCapability(mId, mCap);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get cap"));
    DISPLAY_TEST_LOGD("the capablility name %s type : %d phyWidth : %d phyHeight : %d", mCap.name.c_str(), mCap.type,
        mCap.phyWidth, mCap.phyHeight);
    // get the modes
    ret = device_->GetDisplaySupportedModes(mId, mModes);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get modes"));
    DISPLAY_TEST_LOGD("the modes size() %zd", mModes.size());

    ret = device_->GetDisplayMode(mId, mActiveModeId);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("the mode id is : %d", mActiveModeId));

    ret = GetModeInfoFromId(mActiveModeId, mCurrentMode);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get the mode of id : %d", mActiveModeId));

    LayerInfo layerinfo = {0};
    layerinfo.width = mCurrentMode.width;
    layerinfo.height = mCurrentMode.height;
    layerinfo.pixFormat = PIXEL_FMT_BGRA_8888;
    const uint32_t clientLayerId = 0xffffffff; // invalid id
    mClientLayer = std::make_unique<HdiTestLayer>(layerinfo, clientLayerId, mId);
    ret = mClientLayer->Init();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("the client layer can not be created"));
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::GetModeInfoFromId(int32_t id, DisplayModeInfo &modeInfo)
{
    DISPLAY_TEST_LOGD();
    for (const auto &mode : mModes) {
        if (mode.id == id) {
            modeInfo = mode;
            DISPLAY_TEST_LOGD("the mode width: %d height : %d freshRate : %u id: %d", mode.width, mode.height,
                mode.freshRate, mode.id);
            return DISPLAY_SUCCESS;
        }
    }
    DISPLAY_TEST_LOGE("can not find the modeinfo id : %d", id);
    return DISPLAY_FAILURE;
}

std::shared_ptr<HdiTestLayer> HdiTestDisplay::CreateHdiTestLayer(LayerInfo &info)
{
    DISPLAY_TEST_LOGD();
    uint32_t layerId = 0;
    int ret = device_->CreateLayer(mId, info, layerId);
    DISPLAY_TEST_LOGD(" layerId %d", layerId);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), nullptr, DISPLAY_TEST_LOGE("layer creat failed"));
    auto layer = std::make_shared<HdiTestLayer>(info, layerId, mId);
    ret = layer->Init();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), nullptr, DISPLAY_TEST_LOGE("layer init failed"));
    mLayerMaps.emplace(layerId, layer);
    return layer;
}

std::shared_ptr<HdiTestLayer> HdiTestDisplay::CreateHdiTestLayer(uint32_t w, uint32_t h)
{
    const int32_t bpp = 32;

    LayerInfo info = {w, h, LAYER_TYPE_GRAPHIC, bpp, PIXEL_FMT_RGBA_8888};
    return CreateHdiTestLayer(info);
}

int32_t HdiTestDisplay::RefreshLayersCompType()
{
    int ret;
    std::vector<uint32_t> layers;
    std::vector<int32_t> types;
    ret = device_->GetDisplayCompChange(mId, layers, types);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("GetDisplayCompChange get layers and types failed"));
    DISPLAY_TEST_LOGD("the change numbers %zu, layers size %zu", layers.size(), layers.size());
    for (uint32_t i = 0; i < layers.size(); i++) {
        DISPLAY_TEST_LOGD(" the layer id %d ", layers[i]);
        std::shared_ptr<HdiTestLayer> layer = GetLayerFromId(layers[i]);
        layer->SetCompType(static_cast<CompositionType>(types[i]));
    }
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::GetLayersReleaseFence()
{
    int ret;
    std::vector<uint32_t> layers;
    std::vector<int32_t> fences;

    ret = device_->GetDisplayReleaseFence(mId, layers, fences);
    DISPLAY_TEST_CHK_RETURN((ret != 0), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("GetDisplayReleaseFence get data failed"));
    DISPLAY_TEST_LOGD("the release fence numbers %zu, layers size %zu", layers.size(), layers.size());
    for (uint32_t i = 0; i < layers.size(); i++) {
        DISPLAY_TEST_LOGD(" the layer id %d, fence: 0x%x", layers[i], fences[i]);
        std::shared_ptr<HdiTestLayer> layer = GetLayerFromId(layers[i]);
        layer->SetReleaseFence(fences[i]);
    }
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::PrepareDisplayLayers()
{
    int ret;
    mNeedFlushFb = false;
    DISPLAY_TEST_LOGD("id : %d  layer size %zd", mId, mLayerMaps.size());
    for (const auto &layerMap : mLayerMaps) {
        ret = layerMap.second->PreparePresent();
        DISPLAY_TEST_CHK_RETURN(
            (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("layer %d Prepare failed", layerMap.first));
    }
    ret = device_->PrepareDisplayLayers(mId, mNeedFlushFb);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("PrepareDisplayLayers failed display id %d", mId));
    ret = RefreshLayersCompType();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("RefreshLayersCompType failed"));
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::Commit()
{
    int32_t fenceFd;
    int ret;
    HdiGrallocBuffer *buffer = nullptr;
    if (mNeedFlushFb) {
        ret = mClientLayer->SwapFrontToBackQ();
        DISPLAY_TEST_CHK_RETURN(
            (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("has no front buffer display id %d", mId));

        buffer = mClientLayer->GetBackBuffer();
        DISPLAY_TEST_CHK_RETURN((buffer == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get back buffer"));
        BufferHandle *handle = buffer->Get();
        DISPLAY_TEST_CHK_RETURN((handle == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("BufferHandle is null"));
        ClearColor(*handle, 0); // need clear the fb first
        ret = device_->SetDisplayClientBuffer(mId, *handle, -1);
        mCurrentFb = handle;
        DISPLAY_TEST_LOGD("client fb phyaddr %" PRIx64 " vritual addr %p", handle->phyAddr, handle->virAddr);
        DISPLAY_TEST_CHK_RETURN(
            (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("set client buffer handle failed"));
    }

    ret = device_->Commit(mId, fenceFd);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("commit failed display id %d", mId));
    ret = GetLayersReleaseFence();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("GetLayersReleaseFence failed %d", mId));
    buffer->SetReleaseFence(fenceFd);
    if (mNeedFlushFb) {
        ret = mClientLayer->SwapBackToFrontQ();
    }
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("has no back buffer display id %d", mId));
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::RegDisplayVBlankCallback(VBlankCallback cb, void *data)
{
    int ret = device_->RegDisplayVBlankCallback(mId, cb, data);
    return ret;
}

int32_t HdiTestDisplay::SetDisplayVsyncEnabled(bool enabled)
{
    int ret = device_->SetDisplayVsyncEnabled(mId, enabled);
    return ret;
}

std::shared_ptr<HdiTestLayer> HdiTestDisplay::GetLayerFromId(uint32_t id)
{
    auto layerMap = mLayerMaps.find(id);
    DISPLAY_TEST_CHK_RETURN(
        (layerMap == mLayerMaps.end()), nullptr, DISPLAY_TEST_LOGE("can not find the layer id : %d", id));
    return layerMap->second;
}

void HdiTestDisplay::Clear()
{
    DISPLAY_TEST_LOGD();
    for (auto const &iter : mLayerMaps) {
        uint32_t layerId = iter.first;
        device_->DestroyLayer(mId, layerId);
    }
    mLayerMaps.clear();
    DISPLAY_TEST_LOGD("mLayerMaps size %zd", mLayerMaps.size());
}
} // namespace TEST
} // namespace Display
} // namespace HDI
} // namespace OHOS
