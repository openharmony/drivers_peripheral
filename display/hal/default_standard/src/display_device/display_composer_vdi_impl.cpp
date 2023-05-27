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

#include "display_composer_vdi_impl.h"
#include <hdf_base.h>
#include "display_log.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace DISPLAY {
DisplayComposerVdiImpl::DisplayComposerVdiImpl()
{
    composerModel_.reset(&HdiSession::GetInstance());
}

DisplayComposerVdiImpl::~DisplayComposerVdiImpl()
{
}

int32_t DisplayComposerVdiImpl::RegHotPlugCallback(HotPlugCallback cb, void* data)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    composerModel_->RegHotPlugCallback(cb, data);
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::GetDisplayCapability(uint32_t devId, DisplayCapability& info)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayCapability, &info);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::GetDisplaySupportedModes(uint32_t devId, std::vector<DisplayModeInfo>& modes)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    DisplayModeInfo* placeHoler = nullptr;
    uint32_t num = 0;
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplaySupportedModes,
        &num, placeHoler);
    if (ec != DISPLAY_SUCCESS) {
        DISPLAY_LOGE("failed, ec=%{public}d", ec);
        return HDF_FAILURE;
    }
    if (num != 0) {
        modes.resize(num);
        ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplaySupportedModes, &num, modes.data());
    }
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::GetDisplayMode(uint32_t devId, uint32_t& modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayMode, &modeId);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetDisplayMode(uint32_t devId, uint32_t modeId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayMode, modeId);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::GetDisplayPowerStatus(uint32_t devId, DispPowerStatus& status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayPowerStatus, &status);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetDisplayPowerStatus(uint32_t devId, DispPowerStatus status)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayPowerStatus, status);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::GetDisplayBacklight(uint32_t devId, uint32_t& level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayBacklight, &level);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetDisplayBacklight(uint32_t devId, uint32_t level)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayBacklight, level);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::GetDisplayProperty(uint32_t devId, uint32_t id, uint64_t& value)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::GetDisplayCompChange(uint32_t devId, std::vector<uint32_t>& layers,
    std::vector<int32_t>& types)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    uint32_t* layersHoler = nullptr;
    int32_t* typesHoler = nullptr;
    uint32_t num = 0;
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayCompChange, &num, layersHoler,
        typesHoler);
    if (ec == HDF_SUCCESS && num != 0) {
        layers.resize(num);
        types.resize(num);
        ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayCompChange, &num, layers.data(),
            types.data());
    }
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetDisplayClientCrop(uint32_t devId, const IRect& rect)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::SetDisplayClientBuffer(uint32_t devId, const BufferHandle& buffer, int32_t fence)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayClientBuffer, &buffer, fence);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetDisplayClientDamage(uint32_t devId, std::vector<IRect>& rects)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::SetDisplayVsyncEnabled(uint32_t devId, bool enabled)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetDisplayVsyncEnabled, enabled);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::RegDisplayVBlankCallback(uint32_t devId, VBlankCallback cb, void* data)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::RegDisplayVBlankCallback, cb, data);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::GetDisplayReleaseFence(uint32_t devId, std::vector<uint32_t>& layers,
    std::vector<int32_t>& fences)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    uint32_t* layersHoler = nullptr;
    int32_t* typesHoler = nullptr;
    uint32_t num = 0;
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayReleaseFence, &num, layersHoler,
        typesHoler);
    if (ec == HDF_SUCCESS && num != 0) {
        layers.resize(num);
        fences.resize(num);
        ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::GetDisplayReleaseFence, &num, layers.data(),
            fences.data());
    }
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::CreateVirtualDisplay(uint32_t width, uint32_t height, int32_t& format, uint32_t& devId)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::DestroyVirtualDisplay(uint32_t devId)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::SetVirtualDisplayBuffer(uint32_t devId, const BufferHandle& buffer, const int32_t fence)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::SetDisplayProperty(uint32_t devId, uint32_t id, uint64_t value)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::Commit(uint32_t devId, int32_t& fence)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::Commit, &fence);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::CreateLayer(uint32_t devId, const LayerInfo& layerInfo, uint32_t& layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::CreateLayer, &layerInfo, &layerId);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::DestroyLayer(uint32_t devId, uint32_t layerId)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::DestroyLayer, layerId);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::PrepareDisplayLayers(uint32_t devId, bool& needFlushFb)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::PrepareDisplayLayers, &needFlushFb);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerAlpha(uint32_t devId, uint32_t layerId, const LayerAlpha& alpha)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerAlpha,
        const_cast<LayerAlpha*>(&alpha));
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerRegion(uint32_t devId, uint32_t layerId, const IRect& rect)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerRegion,
        const_cast<IRect*>(&rect));
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerCrop(uint32_t devId, uint32_t layerId, const IRect& rect)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerCrop, const_cast<IRect*>(&rect));
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerZorder(uint32_t devId, uint32_t layerId, uint32_t zorder)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallDisplayFunction(devId, &HdiDisplay::SetLayerZorder, layerId, zorder);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerPreMulti(uint32_t devId, uint32_t layerId, bool preMul)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerPreMulti, preMul);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerTransformMode(uint32_t devId, uint32_t layerId, TransformType type)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerTransformMode, type);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerDirtyRegion(uint32_t devId, uint32_t layerId, const std::vector<IRect>& rects)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerDirtyRegion,
        const_cast<IRect*>(rects.data()));
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerVisibleRegion(uint32_t devId, uint32_t layerId, std::vector<IRect>& rects)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::SetLayerBuffer(uint32_t devId, uint32_t layerId, const BufferHandle& buffer,
    int32_t fence)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    const BufferHandle* holder = &buffer;
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerBuffer, holder, fence);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerCompositionType(uint32_t devId, uint32_t layerId, CompositionType type)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerCompositionType, type);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerBlendType(uint32_t devId, uint32_t layerId, BlendType type)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    int32_t ec = composerModel_->CallLayerFunction(devId, layerId, &HdiLayer::SetLayerBlendType, type);
    DISPLAY_CHK_RETURN(ec != DISPLAY_SUCCESS, HDF_FAILURE, DISPLAY_LOGE("failed, ec=%{public}d", ec));
    return HDF_SUCCESS;
}

int32_t DisplayComposerVdiImpl::SetLayerMaskInfo(uint32_t devId, uint32_t layerId, const MaskInfo maskInfo)
{
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t DisplayComposerVdiImpl::SetLayerColor(uint32_t devId, uint32_t layerId, const LayerColor& layerColor)
{
    CHECK_NULLPOINTER_RETURN_VALUE(composerModel_, HDF_FAILURE);
    DISPLAY_LOGE("%s layerColor: r=%{public}d, g=%{public}d, b=%{public}d, a=%{public}d",
        __func__, layerColor.r, layerColor.g, layerColor.b, layerColor.a);
    DISPLAY_LOGE("%s is not supported", __func__);
    return HDF_ERR_NOT_SUPPORT;
}

extern "C" IDisplayComposerVdi *CreateComposerVdi()
{
    return new DisplayComposerVdiImpl();
}

extern "C" void DestroyComposerVdi(IDisplayComposerVdi* vdi)
{
    delete vdi;
}
} // DISPLAY
} // HDI
} // OHOS
