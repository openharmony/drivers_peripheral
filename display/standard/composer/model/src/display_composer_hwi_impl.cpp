/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "display_composer_hwi_impl.h"
#include <hdf_base.h>
#include "hdf_log.h"
#include "display_log.h"

namespace OHOS {
namespace Model {
namespace Composer {
using namespace OHOS::Model::Composer;

DisplayComposerHwiImpl::DisplayComposerHwiImpl()
{
    composerModel_.reset(&HdiSession::GetInstance());
}

DisplayComposerHwiImpl::~DisplayComposerHwiImpl()
{
}

// *** device func
int32_t DisplayComposerHwiImpl::RegHotPlugCallback(HotPlugCallback cb, void *data)
{
    composerModel_->RegHotPlugCallback(cb, data);
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::GetDisplayCapability(uint32_t devId, DisplayCapability& info)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayCapability, &info);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::GetDisplaySupportedModes(uint32_t devId,
    std::vector<DisplayModeInfo>& modes)
{
    DisplayModeInfo* placeHoler = nullptr;
    uint32_t num = 0;
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplaySupportedModes,
        &num, placeHoler);
    if (ec == HDF_SUCCESS && num != 0) {
        modes.resize(num);
        ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplaySupportedModes, &num, modes.data());
    }
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::GetDisplayMode(uint32_t devId, uint32_t& modeId)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayMode, &modeId);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayMode, modeId);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::GetDisplayPowerStatus(uint32_t devId, DispPowerStatus& status)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayPowerStatus, &status);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayPowerStatus, status);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::GetDisplayBacklight(uint32_t devId, uint32_t& level)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayBacklight, &level);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayBacklight, level);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::GetDisplayCompChange(uint32_t devId, std::vector<uint32_t>& layers,
    std::vector<int32_t>& types)
{
    uint32_t* layersHoler = nullptr;
    int32_t* typesHoler = nullptr;
    uint32_t num = 0;
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayCompChange,
        &num, layersHoler, typesHoler);
    if (ec == HDF_SUCCESS && num != 0) {
        layers.resize(num);
        types.resize(num);
        ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayCompChange,
            &num, layers.data(), types.data());
    }
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetDisplayClientCrop(uint32_t devId, const IRect& rect)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::SetDisplayClientDestRect(uint32_t devId, const IRect& rect)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::SetDisplayClientBuffer(uint32_t devId,
    const BufferHandle& buffer, int32_t fence)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayClientBuffer, &buffer,
        fence);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetDisplayClientDamage(uint32_t devId, std::vector<IRect>& rects)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayVsyncEnabled, enabled);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::RegDisplayVBlankCallback(uint32_t devId, VBlankCallback cb,
    void* data)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::RegDisplayVBlankCallback,
        cb, data);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::GetDisplayReleaseFence(uint32_t devId,
    std::vector<uint32_t>& layers, std::vector<int32_t>& fences)
{
    uint32_t* layersHoler = nullptr;
    int32_t* typesHoler = nullptr;
    uint32_t num = 0;
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayReleaseFence,
        &num, layersHoler, typesHoler);
    if (ec == HDF_SUCCESS && num != 0) {
        layers.resize(num);
        fences.resize(num);
        ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayReleaseFence,
            &num, layers.data(), fences.data());
    }
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::CreateVirtualDisplay(uint32_t width, uint32_t height,
    int32_t& format, uint32_t& devId)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::DestroyVirtualDisplay(uint32_t devId)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::SetVirtualDisplayBuffer(uint32_t devId,
    const BufferHandle& buffer, const int32_t fence)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value)
{
    return HDF_SUCCESS;
}

int32_t DisplayComposerHwiImpl::Commit(uint32_t devId, int32_t& fence)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::Commit, &fence);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

// *** layer func
int32_t DisplayComposerHwiImpl::CreateLayer(uint32_t devId, const LayerInfo& layerInfo,
    uint32_t& layerId)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::CreateLayer, &layerInfo, &layerId);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::DestroyLayer(uint32_t devId, uint32_t layerId)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::DestroyLayer, layerId);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::PrepareDisplayLayers(uint32_t devId, bool& needFlushFb)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::PrepareDisplayLayers,
        &needFlushFb);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerAlpha(uint32_t devId, uint32_t layerId,
    const LayerAlpha& alpha)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerAlpha,
        const_cast<LayerAlpha*>(&alpha));
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerPosition(uint32_t devId, uint32_t layerId, const IRect& rect)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerPosition,
        const_cast<IRect*>(&rect));
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerCrop(uint32_t devId, uint32_t layerId, const IRect& rect)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerCrop,
        const_cast<IRect*>(&rect));
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerZorder(uint32_t devId, uint32_t layerId, uint32_t zorder)
{
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetLayerZorder, layerId, zorder);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerPreMulti(uint32_t devId, uint32_t layerId, bool preMul)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerPreMulti, preMul);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetTransformMode(uint32_t devId, uint32_t layerId,
    TransformType type)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetTransformMode, type);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerDirtyRegion(uint32_t devId, uint32_t layerId,
    const IRect& region)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerDirtyRegion,
        const_cast<IRect*>(&region));
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerVisibleRegion(uint32_t devId, uint32_t layerId,
    std::vector<IRect>& rects)
{
    //for (uint32_t i = 0; i < rects.size(); i++) {
    //}
    //int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerVisibleRegion,
    //    rects.size(), rects.data());
    //return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
    return DISPLAY_SUCCESS;
}

int32_t DisplayComposerHwiImpl::SetLayerBuffer(uint32_t devId, uint32_t layerId,
    const BufferHandle& buffer, int32_t fence)
{
    const BufferHandle* holder = &buffer;
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerBuffer,
        holder, fence);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerCompositionType(uint32_t devId, uint32_t layerId,
    CompositionType type)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerCompositionType, type);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerBlendType(uint32_t devId, uint32_t layerId, BlendType type)
{
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerBlendType, type);
    return ec == DISPLAY_SUCCESS ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t DisplayComposerHwiImpl::SetLayerVisible(uint32_t devId, uint32_t layerId, bool visible)
{
    return HDF_SUCCESS;
}

extern "C" IDisplayComposerHwi *CreateComposerHwi()
{
    return new DisplayComposerHwiImpl();
}

extern "C" void DestroyComposerHwi(IDisplayComposerHwi* hwi)
{
    delete hwi;
}

} // namespace Composer
} // namespace Model
} // namespace OHOS
