/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "light_if_service.h"
#include <hdf_base.h>
#include "light_uhdf_log.h"
#include "hitrace_meter.h"

#define HDF_LOG_TAG   "uhdf_light_service"

namespace OHOS {
namespace HDI {
namespace Light {
namespace V1_0 {
LightIfService::LightIfService()
{
    int32_t ret = GetLightVdiImpl();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get light vdi instance failed", __func__);
    }
}

LightIfService::~LightIfService()
{
    if (vdi_ != nullptr) {
        HdfCloseVdi(vdi_);
    }
}

int32_t LightIfService::GetLightVdiImpl()
{
    struct VdiWrapperLight *vdiWrapperLight = nullptr;
    uint32_t version = 0;
    vdi_ = HdfLoadVdi(HDI_LIGHT_VDI_LIBNAME);
    if (vdi_ == nullptr || vdi_->vdiBase == nullptr) {
        HDF_LOGE("%{public}s: load light vdi failed", __func__);
        return HDF_FAILURE;
    }

    version = HdfGetVdiVersion(vdi_);
    if (version != 1) {
        HDF_LOGE("%{public}s: get light vdi version failed", __func__);
        return HDF_FAILURE;
    }

    vdiWrapperLight = reinterpret_cast<struct VdiWrapperLight *>(vdi_->vdiBase);
    lightVdiImpl_ = vdiWrapperLight->lightModule;
    if (lightVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get light impl failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t LightIfService::Init()
{
    if (lightVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: lightVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = lightVdiImpl_->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s Init failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t LightIfService::GetLightInfo(std::vector<HdfLightInfo>& info)
{
    HDF_LOGD("%{public}s: Enter the GetLightInfo function.", __func__);
    if (lightVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: lightVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    std::vector<HdfLightInfoVdi> lightInfoVdi;
    StartTrace(HITRACE_TAG_HDF, "GetLightInfo");
    int32_t ret = lightVdiImpl_->GetLightInfo(lightInfoVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetLightInfo failed, error code is %{public}d", __func__, ret);
        return ret;
    }
    FinishTrace(HITRACE_TAG_HDF);

    if (lightInfoVdi.empty()) {
        HDF_LOGE("%{public}s: no sensor info in list", __func__);
        return HDF_FAILURE;
    }

    for (const auto &iter : lightInfoVdi) {
        HdfLightInfo hdfLightInfo;
        hdfLightInfo.lightId = iter.lightId;
        hdfLightInfo.lightType = iter.lightType;
        hdfLightInfo.lightName = iter.lightName;
        hdfLightInfo.lightNumber = iter.lightNumber;
        info.push_back(std::move(hdfLightInfo));
    }
    return HDF_SUCCESS;
}

int32_t LightIfService::TurnOnLight(int32_t lightId, const HdfLightEffect& effect)
{
    HDF_LOGD("%{public}s: Enter the TurnOnLight function, lightId is %{public}d", __func__, lightId);
    if (lightVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: lightVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    HdfLightEffectVdi lightEffectVdi;
    lightEffectVdi.lightColor.colorValue.rgbColor.b = effect.lightColor.colorValue.rgbColor.b;
    lightEffectVdi.lightColor.colorValue.rgbColor.g = effect.lightColor.colorValue.rgbColor.g;
    lightEffectVdi.lightColor.colorValue.rgbColor.r = effect.lightColor.colorValue.rgbColor.r;
    lightEffectVdi.lightColor.colorValue.wrgbColor.b = effect.lightColor.colorValue.wrgbColor.b;
    lightEffectVdi.lightColor.colorValue.wrgbColor.g = effect.lightColor.colorValue.wrgbColor.g;
    lightEffectVdi.lightColor.colorValue.wrgbColor.r = effect.lightColor.colorValue.wrgbColor.r;
    lightEffectVdi.lightColor.colorValue.wrgbColor.w = effect.lightColor.colorValue.wrgbColor.w;
    lightEffectVdi.flashEffect.flashMode = effect.flashEffect.flashMode;
    lightEffectVdi.flashEffect.onTime = effect.flashEffect.onTime;
    lightEffectVdi.flashEffect.offTime = effect.flashEffect.offTime;

    StartTrace(HITRACE_TAG_HDF, "TurnOnLight");
    int32_t ret = lightVdiImpl_->TurnOnLight(lightId, lightEffectVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s TurnOnLight failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t LightIfService::TurnOnMultiLights(int32_t lightId, const std::vector<HdfLightColor>& colors)
{
    HDF_LOGD("%{public}s: Enter the TurnOnMultiLights function, lightId is %{public}d", __func__, lightId);
    std::vector<HdfLightColorVdi> colorVdi;
    if (lightVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: lightVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    for (auto iter : colors) {
        HdfLightColorVdi lightColorVdi;
        lightColorVdi.colorValue.rgbColor.b = iter.colorValue.rgbColor.b;
        lightColorVdi.colorValue.rgbColor.g = iter.colorValue.rgbColor.g;
        lightColorVdi.colorValue.rgbColor.r = iter.colorValue.rgbColor.r;
        lightColorVdi.colorValue.wrgbColor.b = iter.colorValue.wrgbColor.b;
        lightColorVdi.colorValue.wrgbColor.g = iter.colorValue.wrgbColor.g;
        lightColorVdi.colorValue.wrgbColor.r = iter.colorValue.wrgbColor.r;
        lightColorVdi.colorValue.wrgbColor.w = iter.colorValue.wrgbColor.w;
        colorVdi.push_back(std::move(lightColorVdi));
    }

    StartTrace(HITRACE_TAG_HDF, "TurnOnMultiLights");
    int32_t ret = lightVdiImpl_->TurnOnMultiLights(lightId, colorVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s TurnOnMultiLights failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t LightIfService::TurnOffLight(int32_t lightId)
{
    HDF_LOGD("%{public}s: Enter the TurnOffLight function, lightId is %{public}d", __func__, lightId);
    if (lightVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: lightVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }
    StartTrace(HITRACE_TAG_HDF, "TurnOffLight");
    int32_t ret = lightVdiImpl_->TurnOffLight(lightId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s TurnOffLight failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

extern "C" ILightInterface *LightInterfaceImplGetInstance(void)
{
    LightIfService *impl = new (std::nothrow) LightIfService();
    if (impl == nullptr) {
        HDF_LOGE("%{public}s: impl nullptr", __func__);
        return nullptr;
    }

    int32_t ret = impl->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: service init failed, error code is %{public}d", __func__, ret);
        delete impl;
        return nullptr;
    }

    return impl;
}
} // V1_0
} // Light
} // HDI
} // OHOS
