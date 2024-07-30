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

#include "vibrator_if_service.h"
#include <hdf_base.h>
#include "vibrator_uhdf_log.h"
#include "hitrace_meter.h"

#define HDF_LOG_TAG    "uhdf_vibrator_service"

namespace OHOS {
namespace HDI {
namespace Vibrator {
namespace V1_3 {
VibratorIfService::VibratorIfService()
{
    int32_t ret = GetVibratorVdiImpl();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get vibrator vdi instance failed", __func__);
    }
}

VibratorIfService::~VibratorIfService()
{
    if (vdi_ != nullptr) {
        HdfCloseVdi(vdi_);
    }
}

int32_t VibratorIfService::GetVibratorVdiImpl()
{
    struct VdiWrapperVibrator *vdiWrapperVibrator = nullptr;
    uint32_t version = 0;
    vdi_ = HdfLoadVdi(HDI_VIBRATOR_VDI_LIBNAME);
    if (vdi_ == nullptr || vdi_->vdiBase == nullptr) {
        HDF_LOGE("%{public}s: load vibrator vdi failed", __func__);
        return HDF_FAILURE;
    }

    version = HdfGetVdiVersion(vdi_);
    if (version != 1) {
        HDF_LOGE("%{public}s: get vibrator vdi version failed", __func__);
        return HDF_FAILURE;
    }

    vdiWrapperVibrator = reinterpret_cast<struct VdiWrapperVibrator *>(vdi_->vdiBase);
    vibratorVdiImpl_ = vdiWrapperVibrator->vibratorModule;
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get vibrator impl failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t VibratorIfService::Init()
{
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = vibratorVdiImpl_->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s Init failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t VibratorIfService::StartOnce(uint32_t duration)
{
    HDF_LOGD("%{public}s: Enter the StartOnce function, duration is %{public}u", __func__, duration);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "StartOnce");
    int32_t ret = vibratorVdiImpl_->StartOnce(duration);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s StartOnce failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::Start(const std::string &effectType)
{
    HDF_LOGD("%{public}s: Enter the Start function", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Start");
    int32_t ret = vibratorVdiImpl_->Start(effectType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s Start failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::Stop(HdfVibratorMode mode)
{
    HDF_LOGD("%{public}s: Enter the Stop function, mode: %{public}d", __func__, mode);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    HdfVibratorModeVdi vibratorMode;
    if (mode == HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE) {
        vibratorMode = VDI_VIBRATOR_MODE_ONCE;
    } else if (mode == HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET) {
        vibratorMode = VDI_VIBRATOR_MODE_PRESET;
    } else if (mode == HdfVibratorMode::HDF_VIBRATOR_MODE_BUTT) {
        vibratorMode = VDI_VIBRATOR_MODE_BUTT;
    } else {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_FAILURE;
    }
    
    StartTrace(HITRACE_TAG_HDF, "Stop");
    int32_t ret = vibratorVdiImpl_->Stop(vibratorMode);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s Stop failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::StopV1_2(int32_t mode)
{
    HDF_LOGD("%{public}s: Enter the Stop function, mode: %{public}d", __func__, mode);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    HdfVibratorModeVdi vibratorMode;
    if (mode == HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE) {
        vibratorMode = VDI_VIBRATOR_MODE_ONCE;
    } else if (mode == HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_PRESET) {
        vibratorMode = VDI_VIBRATOR_MODE_PRESET;
    } else if (mode == HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_HDHAPTIC) {
        vibratorMode = VDI_VIBRATOR_MODE_HDHAPTIC;
    } else if (mode == HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_BUTT) {
        vibratorMode = VDI_VIBRATOR_MODE_BUTT;
    } else {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_FAILURE;
    }
    
    StartTrace(HITRACE_TAG_HDF, "Stop");
    int32_t ret = vibratorVdiImpl_->Stop(vibratorMode);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s Stop failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::GetVibratorInfo(std::vector<HdfVibratorInfo> &vibratorInfo)
{
    HDF_LOGD("%{public}s: Enter the GetVibratorInfo function.", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    std::vector<HdfVibratorInfoVdi> vibratorInfoVdi;
    StartTrace(HITRACE_TAG_HDF, "GetVibratorInfo");
    int32_t ret = vibratorVdiImpl_->GetVibratorInfo(vibratorInfoVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetVibratorInfo failed, error code is %{public}d", __func__, ret);
        return ret;
    }
    FinishTrace(HITRACE_TAG_HDF);

    if (vibratorInfoVdi.empty()) {
        HDF_LOGE("%{public}s no vibrator info in list", __func__);
        return HDF_FAILURE;
    }
    for (const auto &iter : vibratorInfoVdi) {
        HdfVibratorInfo hdfVibratorInfo;
        hdfVibratorInfo.isSupportIntensity = iter.isSupportIntensity;
        hdfVibratorInfo.isSupportFrequency = iter.isSupportFrequency;
        hdfVibratorInfo.intensityMaxValue = iter.intensityMaxValue;
        hdfVibratorInfo.intensityMinValue = iter.intensityMinValue;
        hdfVibratorInfo.frequencyMaxValue = iter.frequencyMaxValue;
        hdfVibratorInfo.frequencyMinValue = iter.frequencyMinValue;
        vibratorInfo.push_back(std::move(hdfVibratorInfo));
    }

    return HDF_SUCCESS;
}

int32_t VibratorIfService::EnableVibratorModulation(uint32_t duration, uint16_t intensity, int16_t frequency)
{
    HDF_LOGD("%{public}s: duration is %{public}u, intensity is %{public}u, frequency is %{public}d.",
        __func__, duration, intensity, frequency);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "EnableVibratorModulation");
    int32_t ret = vibratorVdiImpl_->EnableVibratorModulation(duration, intensity, frequency);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s EnableVibratorModulation failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::EnableCompositeEffect(const HdfCompositeEffect &effect)
{
    HDF_LOGD("%{public}s: Enter the EnableCompositeEffect function.", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    std::vector<HdfEffectVdi> effectVdi;
    for (const auto &compositeEffects : effect.compositeEffects) {
        HdfEffectVdi hdfEffectVdi;
        if (effect.type == HDF_EFFECT_TYPE_TIME) {
            hdfEffectVdi.timeEffect.delay = compositeEffects.timeEffect.delay;
            hdfEffectVdi.timeEffect.time = compositeEffects.timeEffect.time;
            hdfEffectVdi.timeEffect.intensity = compositeEffects.timeEffect.intensity;
            hdfEffectVdi.timeEffect.frequency = compositeEffects.timeEffect.frequency;
        } else if (effect.type == HDF_EFFECT_TYPE_PRIMITIVE) {
            hdfEffectVdi.primitiveEffect.delay = compositeEffects.primitiveEffect.delay;
            hdfEffectVdi.primitiveEffect.effectId = compositeEffects.primitiveEffect.effectId;
            hdfEffectVdi.primitiveEffect.intensity = compositeEffects.primitiveEffect.intensity;
        }
        effectVdi.push_back(std::move(hdfEffectVdi));
    }

    HdfCompositeEffectVdi compositeEffectVdi;
    compositeEffectVdi.type = effect.type;
    compositeEffectVdi.effects = effectVdi;
    StartTrace(HITRACE_TAG_HDF, "EnableCompositeEffect");
    int32_t ret = vibratorVdiImpl_->EnableCompositeEffect(compositeEffectVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s  EnableCompositeEffect failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::GetEffectInfo(const std::string &effectType, HdfEffectInfo &effectInfo)
{
    HDF_LOGD("%{public}s: Enter the GetEffectInfo function.", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    HdfEffectInfoVdi effectInfoVdi;
    StartTrace(HITRACE_TAG_HDF, "GetEffectInfo");
    int32_t ret = vibratorVdiImpl_->GetEffectInfo(effectType, effectInfoVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetEffectInfo failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    effectInfo.isSupportEffect = effectInfoVdi.isSupportEffect;
    effectInfo.duration = effectInfoVdi.duration;

    return ret;
}

int32_t VibratorIfService::IsVibratorRunning(bool& state)
{
    HDF_LOGD("%{public}s: Enter the IsVibratorRunning function", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "IsVibratorRunning");
    int32_t ret = vibratorVdiImpl_->IsVibratorRunning(state);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s IsVibratorRunning failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::PlayHapticPattern(const HapticPaket& pkg)
{
    HDF_LOGD("%{public}s: Enter the PlayHapticPattern function", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    HapticPaketVdi hapticPaketVdi;
    hapticPaketVdi.time = pkg.time;
    hapticPaketVdi.eventNum = pkg.eventNum;
    for (const auto &event : pkg.events) {
        HapticEventVdi hapticEventVdi;
        if (event.type == CONTINUOUS) {
            hapticEventVdi.type = VDI_CONTINUOUS;
        } else if (event.type == TRANSIENT) {
            hapticEventVdi.type = VDI_TRANSIENT;
        }
        hapticEventVdi.time = event.time;
        hapticEventVdi.duration = event.duration;
        hapticEventVdi.intensity = event.intensity;
        hapticEventVdi.frequency = event.frequency;
        hapticEventVdi.index = event.index;
        hapticEventVdi.pointNum = event.pointNum;
        for (const auto &point : event.points) {
            CurvePointVdi curvePointVdip;
            curvePointVdip.time = point.time;
            curvePointVdip.intensity = point.intensity;
            curvePointVdip.frequency = point.frequency;
            hapticEventVdi.points.push_back(std::move(curvePointVdip));
        }
        hapticPaketVdi.events.push_back(std::move(hapticEventVdi));
    }
    StartTrace(HITRACE_TAG_HDF, "PlayHapticPattern");
    int32_t ret = vibratorVdiImpl_->PlayHapticPattern(hapticPaketVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s PlayHapticPattern failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::GetHapticCapacity(HapticCapacity& hapticCapacity)
{
    HDF_LOGD("%{public}s: Enter the GetHapticCapacity function", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    HapticCapacityVdi hapticCapacityVdi;
    StartTrace(HITRACE_TAG_HDF, "GetHapticCapacity");
    int32_t ret = vibratorVdiImpl_->GetHapticCapacity(hapticCapacityVdi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetHapticCapacity failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);
    hapticCapacity.isSupportHdHaptic = hapticCapacityVdi.isSupportHdHaptic;
    hapticCapacity.isSupportPresetMapping = hapticCapacityVdi.isSupportPresetMapping;
    hapticCapacity.isSupportTimeDelay = hapticCapacityVdi.isSupportTimeDelay;

    return ret;
}

int32_t VibratorIfService::GetHapticStartUpTime(int32_t mode, int32_t& startUpTime)
{
    HDF_LOGD("%{public}s: Enter the GetHapticStartUpTime function", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "GetHapticStartUpTime");
    int32_t ret = vibratorVdiImpl_->GetHapticStartUpTime(mode, startUpTime);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetHapticStartUpTime failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::StartByIntensity(const std::string& effectType, uint16_t intensity)
{
    HDF_LOGD("%{public}s: Enter the StartByIntensity function", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "StartByIntensity");
    int32_t ret = vibratorVdiImpl_->StartByIntensity(effectType, intensity);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s StartByIntensity failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::GetAllWaveInfo(int32_t vibratorId, std::vector<HdfWaveInformation> &info)
{
    HDF_LOGD("%{public}s: Enter the GetAllWaveInfo function", __func__);
    if (vibratorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImpl_ is nullptr", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "GetAllWaveInfo");
    int32_t ret = vibratorVdiImpl_->GetAllWaveInfo(vibratorId, info);
    FinishTrace(HITRACE_TAG_HDF);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetAllWaveInfo failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

extern "C" IVibratorInterface *VibratorInterfaceImplGetInstance(void)
{
    VibratorIfService *impl = new (std::nothrow) VibratorIfService();
    if (impl == nullptr) {
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
} // V1_3
} // Vibrator
} // HDI
} // OHOS
