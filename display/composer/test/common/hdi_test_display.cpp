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

#include "hdi_test_display.h"
#include "unistd.h"
#include "display_test_utils.h"
#include "hdi_test_device.h"
namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_1;
HdiTestDisplay::HdiTestDisplay(uint32_t id, sptr<Composer::V1_3::IDisplayComposerInterface> device)
    : id_(id), device_(device), currentFb_(nullptr)
{
}

int32_t HdiTestDisplay::Init()
{
    DISPLAY_TEST_LOGD();
    int ret = device_->GetDisplayCapability(id_, cap_);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get cap"));
    DISPLAY_TEST_LOGD("the capablility name %s type : %{public}d phyWidth : %{public}d phyHeight : %{public}d",
        cap_.name.c_str(), cap_.type, cap_.phyWidth, cap_.phyHeight);
    // get the modes
    ret = device_->GetDisplaySupportedModes(id_, modes_);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get modes"));
    DISPLAY_TEST_LOGD("the modes size() %{public}zu", modes_.size());

    ret = device_->GetDisplayMode(id_, activeModeId_);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("the mode id is : %{public}u", activeModeId_));

    ret = GetModeInfoFromId(activeModeId_, currentMode_);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("can not get the mode of id : %{public}u", activeModeId_));

    ret = device_->SetDisplayPowerStatus(id_, Composer::V1_0::DispPowerStatus::POWER_STATUS_ON);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("SetDisplayPowerStatus failed, id_ : %{public}u", id_));

    ret = device_->SetDisplayMode(id_, currentMode_.id);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("SetDisplayMode failed, id_ : %{public}u", id_));

    LayerInfo layerinfo = {0};
    layerinfo.width = currentMode_.width;
    layerinfo.height = currentMode_.height;
    layerinfo.pixFormat = Composer::V1_0::PIXEL_FMT_BGRA_8888;
    const uint32_t CLIENT_LAYER_ID = 0xffffffff; // invalid id
    clientLayer_ = std::make_unique<HdiTestLayer>(layerinfo, CLIENT_LAYER_ID, id_);
    ret = clientLayer_->Init();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("the client layer can not be created"));

    ret = device_->SetClientBufferCacheCount(id_, clientLayer_->GetLayerBuffercount());
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("setClientBufferCount error"));
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::GetModeInfoFromId(int32_t id, DisplayModeInfo& modeInfo) const
{
    DISPLAY_TEST_LOGD();
    auto iter = std::find_if (std::begin(modes_), std::end(modes_), [id](const auto& mode) {
        return mode.id == id;
    });
    if (iter != std::end(modes_)) {
        modeInfo = *iter;
        DISPLAY_TEST_LOGD("the mode width: %{public}d height : %{public}d freshRate : %{public}u id: %{public}d",
            iter->width, iter->height, iter->freshRate, iter->id);
        return DISPLAY_SUCCESS;
    }
    DISPLAY_TEST_LOGE("can not find the modeinfo id : %{public}d", id);
    return DISPLAY_FAILURE;
}

std::shared_ptr<HdiTestLayer> HdiTestDisplay::CreateHdiTestLayer(LayerInfo& info)
{
    DISPLAY_TEST_LOGD();
    uint32_t layerId = 0;
    int ret = device_->CreateLayer(id_, info, HdiTestLayer::MAX_BUFFER_COUNT, layerId);
    DISPLAY_TEST_LOGD("CreateLayer layerId %{public}u", layerId);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), nullptr, DISPLAY_TEST_LOGE("layer creat failed"));
    auto layer = std::make_shared<HdiTestLayer>(info, layerId, id_);
    ret = layer->Init();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), nullptr, DISPLAY_TEST_LOGE("layer init failed"));
    layerMaps_.emplace(layerId, layer);
    return layer;
}

std::shared_ptr<HdiTestLayer> HdiTestDisplay::CreateHdiTestLayer(uint32_t w, uint32_t h)
{
    const int32_t BPP = 32;

    LayerInfo info = {w, h, LAYER_TYPE_GRAPHIC, BPP, Composer::V1_0::PIXEL_FMT_RGBA_8888};
    return CreateHdiTestLayer(info);
}

int32_t HdiTestDisplay::RefreshLayersCompType()
{
    int ret;
    std::vector<uint32_t> layers;
    std::vector<int32_t> types;
    ret = device_->GetDisplayCompChange(id_, layers, types);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("GetDisplayCompChange get layers and types failed"));
    DISPLAY_TEST_LOGD("the change numbers %{public}zu, layers size %{public}zu", layers.size(), layers.size());
    for (uint32_t i = 0; i < layers.size(); i++) {
        DISPLAY_TEST_LOGD(" the layer id %{public}u ", layers[i]);
        std::shared_ptr<HdiTestLayer> layer = GetLayerFromId(layers[i]);
        layer->SetCompType(static_cast<Composer::V1_0::CompositionType>(types[i]));
    }
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::GetLayersReleaseFence()
{
    int ret;
    std::vector<uint32_t> layers;
    std::vector<int32_t> fences;

    ret = device_->GetDisplayReleaseFence(id_, layers, fences);
    DISPLAY_TEST_CHK_RETURN((ret != 0), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("GetDisplayReleaseFence get data failed"));
    DISPLAY_TEST_LOGD("the release fence numbers %{public}zu, layers size %{public}zu", layers.size(), layers.size());
    for (uint32_t i = 0; i < layers.size(); i++) {
        DISPLAY_TEST_LOGD(" the layer id %{public}u, fence: 0x%x", layers[i], fences[i]);
        std::shared_ptr<HdiTestLayer> layer = GetLayerFromId(layers[i]);
        layer->SetReleaseFence(fences[i]);
    }
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::PrepareDisplayLayers()
{
    int ret;
    needFlushFb_ = false;
    DISPLAY_TEST_LOGD("id : %{public}u  layer size %{public}zu", id_, layerMaps_.size());
    for (const auto& layerMap : layerMaps_) {
        ret = layerMap.second->PreparePresent();
        DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
            DISPLAY_TEST_LOGE("layer %{public}d Prepare failed", layerMap.first));
    }
    ret = device_->PrepareDisplayLayers(id_, needFlushFb_);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("PrepareDisplayLayers failed display id %{public}u", id_));
    ret = RefreshLayersCompType();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("RefreshLayersCompType failed"));
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::Commit()
{
    int32_t fenceFd;
    int ret;
    HdiGrallocBuffer* buffer = nullptr;
    if (needFlushFb_) {
        ret = clientLayer_->SwapFrontToBackQ();
        DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE,
            DISPLAY_TEST_LOGE("has no front buffer display id %{public}u", id_));

        buffer = clientLayer_->GetBackBuffer();
        DISPLAY_TEST_CHK_RETURN((buffer == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get back buffer"));
        BufferHandle* handle = buffer->Get();
        DISPLAY_TEST_CHK_RETURN((handle == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("BufferHandle is null"));
        ClearColor(*handle, 0); // need clear the fb first

        ret = buffer->SetGraphicBuffer([&](const BufferHandle* buffer, uint32_t seqNo) -> int32_t {
            int32_t result = device_->SetDisplayClientBuffer(id_, buffer, seqNo, -1);
            DISPLAY_TEST_CHK_RETURN(
                (result != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("set client buffer handle failed"));
            return DISPLAY_SUCCESS;
        });
        currentFb_ = handle;
        DISPLAY_TEST_CHK_RETURN(
            (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("set client buffer handle failed"));
    }

    ret = device_->Commit(id_, fenceFd);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("commit failed display id %{public}u", id_));
    ret = GetLayersReleaseFence();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("GetLayersReleaseFence failed %{public}u", id_));

    if (needFlushFb_) {
        DISPLAY_TEST_LOGD("commit out client buffer fence: %{public}d", fenceFd);
        buffer->SetReleaseFence(fenceFd);
        ret = clientLayer_->SwapBackToFrontQ();
    }
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("has no back buffer display id %{public}u", id_));
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::RegDisplayVBlankCallback(VBlankCallback cb, void* data) const
{
    int ret = device_->RegDisplayVBlankCallback(id_, cb, data);
    return ret;
}

int32_t HdiTestDisplay::SetDisplayVsyncEnabled(bool enabled) const
{
    int ret = device_->SetDisplayVsyncEnabled(id_, enabled);
    return ret;
}

std::shared_ptr<HdiTestLayer> HdiTestDisplay::GetLayerFromId(uint32_t id)
{
    auto layerMap = layerMaps_.find(id);
    DISPLAY_TEST_CHK_RETURN(
        (layerMap == layerMaps_.end()), nullptr, DISPLAY_TEST_LOGE("can not find the layer id : %{public}u", id));
    return layerMap->second;
}

void HdiTestDisplay::Clear()
{
    DISPLAY_TEST_LOGD();
    for (auto const& iter : layerMaps_) {
        uint32_t layerId = iter.first;
        device_->DestroyLayer(id_, layerId);
    }
    layerMaps_.clear();
    DISPLAY_TEST_LOGD("layerMaps_ size %{public}zu", layerMaps_.size());
}
} // namespace TEST
} // namespace Display
} // namespace HDI
} // namespace OHOS
