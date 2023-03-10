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
using namespace OHOS::HDI::Display::Composer::V1_0;
    HdiTestDisplay::HdiTestDisplay(uint32_t id, std::shared_ptr<IDisplayComposerInterface> device)
        : id_(id), device_(device)
{
}

int32_t HdiTestDisplay::Init()
{
    DISPLAY_TEST_LOGD();
    int ret = device_->GetDisplayCapability(id_, cap_);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get cap"));
    DISPLAY_TEST_LOGD("the capablility name %s type : %d phyWidth : %d phyHeight : %d", cap_.name.c_str(), cap_.type,
        cap_.phyWidth, cap_.phyHeight);
    // get the modes
    ret = device_->GetDisplaySupportedModes(id_, modes_);
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get modes"));
    DISPLAY_TEST_LOGD("the modes size() %zd", modes_.size());

    ret = device_->GetDisplayMode(id_, activeModeId_);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("the mode id is : %d", activeModeId_));

    ret = GetModeInfoFromId(activeModeId_, currentMode_);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get the mode of id : %d", activeModeId_));

    ret = device_->SetDisplayPowerStatus(id_, DispPowerStatus::POWER_STATUS_ON);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("SetDisplayPowerStatus failed, id_ : %d", id_));

    ret = device_->SetDisplayMode(id_, currentMode_.id);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("SetDisplayMode failed, id_ : %d", id_));

    LayerInfo layerinfo = {0};
    layerinfo.width = currentMode_.width;
    layerinfo.height = currentMode_.height;
    layerinfo.pixFormat = PIXEL_FMT_BGRA_8888;
    const uint32_t CLIENT_LAYER_ID = 0xffffffff; // invalid id
    clientLayer_ = std::make_unique<HdiTestLayer>(layerinfo, CLIENT_LAYER_ID, id_);
    ret = clientLayer_->Init();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("the client layer can not be created"));
    return DISPLAY_SUCCESS;
}

int32_t HdiTestDisplay::GetModeInfoFromId(int32_t id, DisplayModeInfo& modeInfo)
{
    DISPLAY_TEST_LOGD();
    for (const auto& mode : modes_) {
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

std::shared_ptr<HdiTestLayer> HdiTestDisplay::CreateHdiTestLayer(LayerInfo& info)
{
    DISPLAY_TEST_LOGD();
    uint32_t layerId = 0;
    int ret = device_->CreateLayer(id_, info, layerId);
    DISPLAY_TEST_LOGD("CreateLayer layerId %d", layerId);
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

    LayerInfo info = {w, h, LAYER_TYPE_GRAPHIC, BPP, PIXEL_FMT_RGBA_8888};
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

    ret = device_->GetDisplayReleaseFence(id_, layers, fences);
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
    needFlushFb_ = false;
    DISPLAY_TEST_LOGD("id : %d  layer size %zd", id_, layerMaps_.size());
    for (const auto& layerMap : layerMaps_) {
        ret = layerMap.second->PreparePresent();
        DISPLAY_TEST_CHK_RETURN(
            (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("layer %d Prepare failed", layerMap.first));
    }
    ret = device_->PrepareDisplayLayers(id_, needFlushFb_);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("PrepareDisplayLayers failed display id %d", id_));
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
        DISPLAY_TEST_CHK_RETURN(
            (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("has no front buffer display id %d", id_));

        buffer = clientLayer_->GetBackBuffer();
        DISPLAY_TEST_CHK_RETURN((buffer == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("can not get back buffer"));
        BufferHandle* handle = buffer->Get();
        DISPLAY_TEST_CHK_RETURN((handle == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("BufferHandle is null"));
        ClearColor(*handle, 0); // need clear the fb first
        ret = device_->SetDisplayClientBuffer(id_, *handle, -1);
        currentFb_ = handle;
        DISPLAY_TEST_CHK_RETURN(
            (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("set client buffer handle failed"));
    }

    ret = device_->Commit(id_, fenceFd);
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("commit failed display id %d", id_));
    ret = GetLayersReleaseFence();
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("GetLayersReleaseFence failed %d", id_));

    if (needFlushFb_) {
        DISPLAY_TEST_LOGD("commit out client buffer fence: %d", fenceFd);
        buffer->SetReleaseFence(fenceFd);
        ret = clientLayer_->SwapBackToFrontQ();
    }
    DISPLAY_TEST_CHK_RETURN(
        (ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("has no back buffer display id %d", id_));
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
        (layerMap == layerMaps_.end()), nullptr, DISPLAY_TEST_LOGE("can not find the layer id : %d", id));
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
    DISPLAY_TEST_LOGD("layerMaps_ size %zd", layerMaps_.size());
}
} // namespace TEST
} // namespace Display
} // namespace HDI
} // namespace OHOS
