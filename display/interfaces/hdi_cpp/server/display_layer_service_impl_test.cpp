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

#include "display_layer_service_impl_test.h"
#include <hdf_log.h>
#include <hdf_base.h>

namespace OHOS {
namespace HDI {
namespace Display {
namespace V1_0 {

DispErrCode DisplayLayerService::InitDisplay(unsigned int devId)
{
    HDF_LOGE("[service]--%{public}s: enter, devId = %{public}d", __func__, devId);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::DeinitDisplay(unsigned int devId)
{
    HDF_LOGE("[service]--%{public}s: enter, devId = %{public}d", __func__, devId);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::GetDisplayInfo(unsigned int devId, std::shared_ptr<DisplayInfo> &dispInfo)
{
    dispInfo->width = 480;  // x-solution
    dispInfo->height = 800; // y-solution
    dispInfo->rotAngle = 0;
    HDF_LOGE("[service]--%{public}s: width = %{public}d, height = %{public}d, rotAngle = %{public}d",
        __func__, dispInfo->width, dispInfo->height, dispInfo->rotAngle);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::CreateLayer(unsigned int devId, LayerInfo &layerInfo, unsigned int &layerId)
{
    layerId = 0;
    HDF_LOGE("[service]--%{public}s: width= %{public}d, height = %{public}d, type = %{public}d, bpp = %{public}d",
        __func__, layerInfo.width, layerInfo.height, layerInfo.type, layerInfo.bpp);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::CloseLayer(unsigned int devId, unsigned int layerId)
{
    HDF_LOGE("[service]--%{public}s: enter, devId = %{public}d", __func__, devId);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::SetLayerVisible(unsigned int devId, unsigned int layerId, bool visible)
{
    HDF_LOGE("[service]--%{public}s: devId = %{public}d, visible = %{public}d", __func__, devId, visible);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::GetLayerVisibleState(unsigned int devId, unsigned int layerId, bool &visible)
{
    visible = true;
    HDF_LOGE("[service]--%{public}s: devId = %{public}d, visible is true", __func__, devId);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::SetLayerRect(unsigned int devId, unsigned int layerId, IRect &rect)
{
    HDF_LOGE("[service]--%{public}s: [x,y,w,h]= [%{public}d, %{public}d, %{public}d, %{public}d]",
        __func__, rect.x, rect.y, rect.w, rect.h);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::GetLayerRect(unsigned int devId, unsigned int layerId, std::shared_ptr<IRect> &rect)
{
    rect->x = 0;
    rect->y = 0;
    rect->w = 480; // x-solution
    rect->h = 800; // y-solution
    HDF_LOGE("[service]--%{public}s: [x,y,w,h] = [%{public}d, %{public}d, %{public}d, %{public}d]",
        __func__, rect->x, rect->y, rect->w, rect->h);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::SetLayerZorder(unsigned int devId, unsigned int layerId, unsigned int zorder)
{
    HDF_LOGE("[service]--%{public}s: devId = %{public}d, zorder = %{public}d", __func__, devId, zorder);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::GetLayerZorder(unsigned int devId, unsigned int layerId, unsigned int &zorder)
{
    zorder = 3; // specific zorder
    HDF_LOGE("[service]--%{public}s: devId = %{public}d, zorder is 3", __func__, devId);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::SetTransformMode(unsigned int devId, unsigned int layerId, TransformType &type)
{
    HDF_LOGE("[service]--%{public}s: devId = %{public}d, transformType = %{public}d", __func__, devId, type);
    return DISPLAY_SUCCESS;
}

DispErrCode DisplayLayerService::SetLayerBuffer(unsigned int devId, unsigned int layerId, const BufferHandle &buffer, int fence)
{
    HDF_LOGE("[service]--%{public}s: fd= %{public}d, w= %{public}d, h= %{public}d, size= %{public}d, fmt= %{public}d",
        __func__, buffer.fd, buffer.width, buffer.height, buffer.size, buffer.format);
    return DISPLAY_SUCCESS;
}

} // namespace V1_0
} // namespace Display
} // namespace HDI
} // namespace OHOS
