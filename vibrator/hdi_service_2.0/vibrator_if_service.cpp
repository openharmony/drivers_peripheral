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
namespace V2_0 {
#define DEFAULT_DEVICE_ID (-1)
#define DEFAULT_VIBRATOR_ID 1
#define DEFAULT_POSITION 0
#define DEFAULT_IS_LOCAL 1

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
    struct OHOS::HDI::Vibrator::V1_1::VdiWrapperVibrator *vdiWrapperVibrator = nullptr;
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

    vdiWrapperVibrator = reinterpret_cast<struct OHOS::HDI::Vibrator::V1_1::VdiWrapperVibrator *>(vdi_->vdiBase);
    vibratorVdiImplV1_1_ = vdiWrapperVibrator->vibratorModule;
    bool ret = vibratorVdiImplV1_1_ == nullptr;
    if (ret) {
        HDF_LOGE("%{public}s: get vibrator impl failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t VibratorIfService::Init()
{
    if (vibratorVdiImplV1_1_ == nullptr) {
        HDF_LOGE("%{public}s: vibratorVdiImplV1_1_ is nullptr", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = vibratorVdiImplV1_1_->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s Init failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

//version 2.0 interface
int32_t VibratorIfService::StartOnce(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                     uint32_t duration)
{
    HDF_LOGD("%{public}s: Enter the StartOnce function duration is %{public}u", __func__, duration);

    StartTrace(HITRACE_TAG_HDF, "StartOnce");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->StartOnce(deviceVibratorInfo, duration);
#else
    int32_t ret = vibratorVdiImplV1_1_->StartOnce(duration);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::Start(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                 const std::string &effectType)
{
    HDF_LOGD("%{public}s: Enter the Start function", __func__);

    StartTrace(HITRACE_TAG_HDF, "Start");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->Start(deviceVibratorInfo, effectType);
#else
    int32_t ret = vibratorVdiImplV1_1_->Start(effectType);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::Stop(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                V2_0::HdfVibratorMode mode)
{
    HDF_LOGD("%{public}s: Enter the Stop function, mode: %{public}d", __func__, mode);

    HdfVibratorModeVdi vibratorMode;
    if (mode == HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE) {
        vibratorMode = VDI_VIBRATOR_MODE_ONCE;
    } else if (mode == HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET) {
        vibratorMode = VDI_VIBRATOR_MODE_PRESET;
    } else if (mode == HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC) {
        vibratorMode = VDI_VIBRATOR_MODE_HDHAPTIC;
    } else if (mode == HdfVibratorMode::HDF_VIBRATOR_MODE_BUTT) {
        vibratorMode = VDI_VIBRATOR_MODE_BUTT;
    } else {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Stop");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->Stop(deviceVibratorInfo, vibratorMode);
#else
    int32_t ret = vibratorVdiImplV1_1_->Stop(vibratorMode);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::GetVibratorInfo(std::vector<V2_0::HdfVibratorInfo> &vibratorInfo)
{
    HDF_LOGD("%{public}s: Enter the GetVibratorInfo function.", __func__);

    StartTrace(HITRACE_TAG_HDF, "GetVibratorInfo");
    std::vector<OHOS::HDI::Vibrator::V1_1::HdfVibratorInfoVdi> vibratorInfoVdi;
    int32_t ret = vibratorVdiImplV1_1_->GetVibratorInfo(vibratorInfoVdi);
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetVibratorInfo failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    if (vibratorInfoVdi.empty()) {
        HDF_LOGE("%{public}s no vibrator info in list", __func__);
        return HDF_SUCCESS;
    }
    for (const auto &iter : vibratorInfoVdi) {
        HdfVibratorInfo hdfVibratorInfo;
        hdfVibratorInfo.isSupportIntensity = iter.isSupportIntensity;
        hdfVibratorInfo.isSupportFrequency = iter.isSupportFrequency;
        hdfVibratorInfo.intensityMaxValue = iter.intensityMaxValue;
        hdfVibratorInfo.intensityMinValue = iter.intensityMinValue;
        hdfVibratorInfo.frequencyMaxValue = iter.frequencyMaxValue;
        hdfVibratorInfo.frequencyMinValue = iter.frequencyMinValue;
#ifdef TV_FLAG
        hdfVibratorInfo.deviceId = iter.deviceId;
        hdfVibratorInfo.vibratorId = iter.vibratorId;
        hdfVibratorInfo.position = iter.position;
        hdfVibratorInfo.isLocal = iter.isLocal;
#else
        hdfVibratorInfo.deviceId = DEFAULT_DEVICE_ID;
        hdfVibratorInfo.vibratorId = DEFAULT_VIBRATOR_ID;
        hdfVibratorInfo.position = DEFAULT_POSITION;
        hdfVibratorInfo.isLocal = DEFAULT_IS_LOCAL;
#endif
        vibratorInfo.push_back(std::move(hdfVibratorInfo));
    }

    return HDF_SUCCESS;
}

int32_t VibratorIfService::GetVibratorIdSingle(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                               std::vector<HdfVibratorInfo> &vibratorInfo)
{
    HDF_LOGD("%{public}s: Enter the GetVibratorInfo function.", __func__);

    std::vector<OHOS::HDI::Vibrator::V1_1::HdfVibratorInfoVdi> vibratorInfoVdi;
    int32_t ret = HDF_FAILURE;
    StartTrace(HITRACE_TAG_HDF, "GetVibratorInfo");
#ifdef TV_FLAG
    ret = vibratorVdiImplV1_1_->GetVibratorIdSingle(deviceVibratorInfo, vibratorInfoVdi);
#else
    HDF_LOGI("%{public}s: sensorVdiImplV1_1_ not support", __func__);
    ret =  HDF_SUCCESS;
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetVibratorInfo failed, error code is %{public}d", __func__, ret);
        return ret;
    }

    if (vibratorInfoVdi.empty()) {
        HDF_LOGE("%{public}s no vibrator info in list", __func__);
        return HDF_SUCCESS;
    }
    for (const auto &iter : vibratorInfoVdi) {
        HdfVibratorInfo hdfVibratorInfo;
        hdfVibratorInfo.isSupportIntensity = iter.isSupportIntensity;
        hdfVibratorInfo.isSupportFrequency = iter.isSupportFrequency;
        hdfVibratorInfo.intensityMaxValue = iter.intensityMaxValue;
        hdfVibratorInfo.intensityMinValue = iter.intensityMinValue;
        hdfVibratorInfo.frequencyMaxValue = iter.frequencyMaxValue;
        hdfVibratorInfo.frequencyMinValue = iter.frequencyMinValue;
#ifdef TV_FLAG
        hdfVibratorInfo.deviceId = iter.deviceId;
        hdfVibratorInfo.vibratorId = iter.vibratorId;
        hdfVibratorInfo.position = iter.position;
        hdfVibratorInfo.isLocal = iter.isLocal;
#else
#else
        hdfVibratorInfo.deviceId = DEFAULT_DEVICE_ID;
        hdfVibratorInfo.vibratorId = DEFAULT_VIBRATOR_ID;
        hdfVibratorInfo.position = DEFAULT_POSITION;
        hdfVibratorInfo.isLocal = DEFAULT_IS_LOCAL;
#endif
#endif
        vibratorInfo.push_back(std::move(hdfVibratorInfo));
    }

    return HDF_SUCCESS;
}

int32_t VibratorIfService::EnableVibratorModulation(
    const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo, uint32_t duration, uint16_t intensity,
    int16_t frequency)
{
    HDF_LOGD("%{public}s: duration is %{public}u, intensity is %{public}u, frequency is %{public}d.",
        __func__, duration, intensity, frequency);

    StartTrace(HITRACE_TAG_HDF, "EnableVibratorModulation");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->EnableVibratorModulation(deviceVibratorInfo, duration, intensity, frequency);
#else
    int32_t ret = vibratorVdiImplV1_1_->EnableVibratorModulation(duration, intensity, frequency);
#endif
    FinishTrace(HITRACE_TAG_HDF);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::EnableCompositeEffect(
    const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo, const V2_0::HdfCompositeEffect &effect)
{
    HDF_LOGD("%{public}s: Enter the EnableCompositeEffect function.", __func__);

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
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->EnableCompositeEffect(deviceVibratorInfo, compositeEffectVdi);
#else
    int32_t ret = vibratorVdiImplV1_1_->EnableCompositeEffect(compositeEffectVdi);
#endif
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t VibratorIfService::GetEffectInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
    const std::string &effectType, HdfEffectInfo &effectInfo)
{
    HDF_LOGD("%{public}s: Enter the GetEffectInfo function.", __func__);

    HdfEffectInfoVdi effectInfoVdi;
    StartTrace(HITRACE_TAG_HDF, "GetEffectInfo");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->GetEffectInfo(deviceVibratorInfo, effectType, effectInfoVdi);
#else
    int32_t ret = vibratorVdiImplV1_1_->GetEffectInfo(effectType, effectInfoVdi);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    effectInfo.isSupportEffect = effectInfoVdi.isSupportEffect;
    effectInfo.duration = effectInfoVdi.duration;

    return ret;
}

int32_t VibratorIfService::IsVibratorRunning(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                             bool& state)
{
    HDF_LOGD("%{public}s: Enter the IsVibratorRunning function", __func__);

    StartTrace(HITRACE_TAG_HDF, "IsVibratorRunning");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->IsVibratorRunning(deviceVibratorInfo, state);
#else
    int32_t ret = vibratorVdiImplV1_1_->IsVibratorRunning(state);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s IsVibratorRunning failed, error code is %{public}d", __func__, ret);
    }
    HDF_LOGD("%{public}s: state %{public}d", __func__, state);

    return ret;
}

int32_t VibratorIfService::PlayHapticPattern(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                             const HapticPaket& pkg)
{
    HDF_LOGD("%{public}s: Enter the PlayHapticPattern function", __func__);

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
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->PlayHapticPattern(deviceVibratorInfo, hapticPaketVdi);
#else
    int32_t ret = vibratorVdiImplV1_1_->PlayHapticPattern(hapticPaketVdi);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::GetHapticCapacity(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                             V2_0::HapticCapacity& hapticCapacity)
{
    HDF_LOGD("%{public}s: Enter the GetHapticCapacity function", __func__);

    HapticCapacityVdi hapticCapacityVdi;
    StartTrace(HITRACE_TAG_HDF, "GetHapticCapacity");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->GetHapticCapacity(deviceVibratorInfo, hapticCapacityVdi);
#else
    int32_t ret = vibratorVdiImplV1_1_->GetHapticCapacity(hapticCapacityVdi);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }
    hapticCapacity.isSupportHdHaptic = hapticCapacityVdi.isSupportHdHaptic;
    hapticCapacity.isSupportPresetMapping = hapticCapacityVdi.isSupportPresetMapping;
    hapticCapacity.isSupportTimeDelay = hapticCapacityVdi.isSupportTimeDelay;

    return ret;
}

int32_t VibratorIfService::GetHapticStartUpTime(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                                int32_t mode, int32_t& startUpTime)
{
    HDF_LOGD("%{public}s: Enter the GetHapticStartUpTime function", __func__);

    StartTrace(HITRACE_TAG_HDF, "GetHapticStartUpTime");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->GetHapticStartUpTime(deviceVibratorInfo, mode, startUpTime);
#else
    int32_t ret = vibratorVdiImplV1_1_->GetHapticStartUpTime(mode, startUpTime);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::StartByIntensity(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                            const std::string& effectType, uint16_t intensity)
{
    HDF_LOGD("%{public}s: Enter the StartByIntensity function", __func__);

    StartTrace(HITRACE_TAG_HDF, "StartByIntensity");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->StartByIntensity(deviceVibratorInfo, effectType, intensity);
#else
    int32_t ret = vibratorVdiImplV1_1_->StartByIntensity(effectType, intensity);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::GetAllWaveInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                          std::vector<OHOS::HDI::Vibrator::V2_0::HdfWaveInformation> &info)
{
    HDF_LOGD("%{public}s: Enter the GetAllWaveInfo function", __func__);

    StartTrace(HITRACE_TAG_HDF, "GetAllWaveInfo");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->GetAllWaveInfo(deviceVibratorInfo, info);
#else
    std::vector<OHOS::HDI::Vibrator::V1_3::HdfWaveInformation> infoV1_3;
    int32_t ret = vibratorVdiImplV1_1_->GetAllWaveInfo(deviceVibratorInfo.vibratorId, infoV1_3);
    for (const auto &iter : infoV1_3) {
        OHOS::HDI::Vibrator::V2_0::HdfWaveInformation infoV2_0;
        infoV2_0.waveId = iter.waveId;
        infoV2_0.intensity = iter.intensity;
        infoV2_0.frequency = iter.frequency;
        infoV2_0.duration = iter.duration;
        infoV2_0.reserved = iter.reserved;
        info.push_back(std::move(infoV2_0));
    }
#endif

    FinishTrace(HITRACE_TAG_HDF);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
    }

    return ret;
}

int32_t VibratorIfService::GetDeviceVibratorInfo(
    const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
    std::vector<V2_0::HdfVibratorInfo> &vibratorInfo)
{
    HDF_LOGD("%{public}s: Enter the GetDeviceVibratorInfo function.", __func__);

    std::vector<HdfVibratorInfoVdi> vibratorInfoVdi;
    StartTrace(HITRACE_TAG_HDF, "GetDeviceVibratorInfo");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->GetDeviceVibratorInfo(deviceVibratorInfo, vibratorInfoVdi);
#else
    int32_t ret = vibratorVdiImplV1_1_->GetDeviceVibratorInfo(vibratorInfoVdi);
#endif
    FinishTrace(HITRACE_TAG_HDF);

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed, deviceId %{public}d, vibratorId %{public}d, error code is %{public}d",
                 __func__, deviceVibratorInfo.deviceId, deviceVibratorInfo.vibratorId, ret);
        return ret;
    }

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
#ifdef TV_FLAG
        hdfVibratorInfo.deviceId = iter.deviceId;
        hdfVibratorInfo.vibratorId = iter.vibratorId;
        hdfVibratorInfo.position = iter.position;
        hdfVibratorInfo.isLocal = iter.isLocal;
#else
        hdfVibratorInfo.deviceId = DEFAULT_DEVICE_ID;
        hdfVibratorInfo.vibratorId = DEFAULT_VIBRATOR_ID;
        hdfVibratorInfo.position = DEFAULT_POSITION;
        hdfVibratorInfo.isLocal = DEFAULT_IS_LOCAL;
#endif
        vibratorInfo.push_back(std::move(hdfVibratorInfo));
    }

    return HDF_SUCCESS;
}

int32_t VibratorIfService::RegVibratorPlugCallback(const sptr<V2_0::IVibratorPlugCallback> &callbackObj)
{
    HDF_LOGD("%{public}s: Enter the RegVibratorPlugCallback function", __func__);

    StartTrace(HITRACE_TAG_HDF, "RegVibratorPlugCallback");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->RegVibratorPlugCallback(callbackObj);
#else
    int32_t ret = HDF_SUCCESS;
#endif
    FinishTrace(HITRACE_TAG_HDF);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: RegVibratorPlugCallback failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t VibratorIfService::UnRegVibratorPlugCallback(const sptr<V2_0::IVibratorPlugCallback> &callbackObj)
{
    HDF_LOGD("%{public}s: Enter the UnRegVibratorPlugCallback function", __func__);

    StartTrace(HITRACE_TAG_HDF, "UnRegVibratorPlugCallback");
#ifdef TV_FLAG
    int32_t ret = vibratorVdiImplV1_1_->UnRegVibratorPlugCallback(callbackObj);
#else
    int32_t ret = HDF_SUCCESS;
#endif
    FinishTrace(HITRACE_TAG_HDF);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UnRegVibratorPlugCallback failed, error code is %{public}d", __func__, ret);
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
} // V2_0
} // Vibrator
} // HDI
} // OHOS
