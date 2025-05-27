/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_VDI_H
#define OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_VDI_H

#include <stdint.h>
#include <vector>
#include <hdf_base.h>
#include "hdf_load_vdi.h"
#include "v1_3/ivibrator_interface.h"
#include "v2_0/ivibrator_interface.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Vibrator {
namespace V1_1 {
using namespace OHOS::HDI::Vibrator::V1_3;
using namespace OHOS::HDI::Vibrator::V2_0;

enum HdfVibratorStatusVdi {
    VDI_VIBRATOR_SUCCESS            = 0,
    VDI_VIBRATOR_NOT_PERIOD         = -1,
    VDI_VIBRATOR_NOT_INTENSITY      = -2,
    VDI_VIBRATOR_NOT_FREQUENCY      = -3,
};

enum HdfVibratorModeVdi {
    VDI_VIBRATOR_MODE_ONCE   = 0,
    VDI_VIBRATOR_MODE_PRESET = 1,
    VDI_VIBRATOR_MODE_HDHAPTIC = 2,
    VDI_VIBRATOR_MODE_BUTT
};

enum HdfEffectTypeVdi {
    VDI_EFFECT_TYPE_TIME,
    VDI_EFFECT_TYPE_PRIMITIVE,
    VDI_EFFECT_TYPE_BUTT,
};

enum EVENT_TYPEVdi {
    VDI_CONTINUOUS = 0,
    VDI_TRANSIENT = 1,
};

struct HdfVibratorInfoVdi {
    bool isSupportIntensity;
    bool isSupportFrequency;
    uint16_t intensityMaxValue;
    uint16_t intensityMinValue;
    int16_t frequencyMaxValue;
    int16_t frequencyMinValue;
    int32_t deviceId;
    int32_t vibratorId;
    int32_t position;
    int32_t isLocal;
};

struct HdfTimeEffectVdi {
    int32_t delay;
    int32_t time;
    uint16_t intensity;
    int16_t frequency;
};

struct HdfPrimitiveEffectVdi {
    int32_t delay;
    int32_t effectId;
    uint16_t intensity;
};

union HdfEffectVdi {
    struct HdfTimeEffectVdi timeEffect;
    struct HdfPrimitiveEffectVdi primitiveEffect;
};

struct HdfCompositeEffectVdi {
    int32_t type;
    std::vector<HdfEffectVdi> effects;
};

struct HdfEffectInfoVdi {
    int32_t duration;
    bool isSupportEffect;
};

struct CurvePointVdi {
    int32_t time;
    int32_t intensity;
    int32_t frequency;
};

struct HapticEventVdi {
    EVENT_TYPEVdi type;
    int32_t time;
    int32_t duration;
    int32_t intensity;
    int32_t frequency;
    int32_t index;
    int32_t pointNum;
    std::vector<CurvePointVdi> points;
};

struct HapticPaketVdi {
    int32_t time;
    int32_t eventNum;
    std::vector<HapticEventVdi> events;
};

struct HapticCapacityVdi {
    bool isSupportHdHaptic;
    bool isSupportPresetMapping;
    bool isSupportTimeDelay;
    int32_t vibratorId;
    bool reserved0;
    int32_t reserved1;
};

#define HDI_VIBRATOR_VDI_LIBNAME "libhdi_vibrator_impl.z.so"

class IVibratorInterfaceVdi {
public:
    virtual ~IVibratorInterfaceVdi() = default;
    virtual int32_t Init() = 0;
    virtual int32_t StartOnce(uint32_t duration)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Start(const std::string &effectType)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Stop(HdfVibratorModeVdi mode)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetVibratorInfo(std::vector<HdfVibratorInfoVdi> &vibratorInfo)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetDeviceVibratorInfo(std::vector<HdfVibratorInfoVdi> &vibratorInfo)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t EnableVibratorModulation(uint32_t duration, uint16_t intensity, int16_t frequency)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t EnableCompositeEffect(const HdfCompositeEffectVdi& effect)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetEffectInfo(const std::string &effectType, HdfEffectInfoVdi &effectInfo)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t IsVibratorRunning(bool& state)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t PlayHapticPattern(const HapticPaketVdi& pkg)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetHapticCapacity(HapticCapacityVdi& hapticCapacity)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetHapticStartUpTime(int32_t mode, int32_t& startUpTime)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t StartByIntensity(const std::string& effectType, uint16_t intensity)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetAllWaveInfo(int32_t vibratorId, std::vector<OHOS::HDI::Vibrator::V1_3::HdfWaveInformation> &info)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };

//V2_0
    virtual int32_t StartOnce(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                              uint32_t duration)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Start(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                          const std::string &effectType)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Stop(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                         HdfVibratorModeVdi mode)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    int32_t GetVibratorIdSingle(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                std::vector<HdfVibratorInfoVdi> &vibratorInfo)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t EnableVibratorModulation(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                             uint32_t duration, uint16_t intensity, int16_t frequency)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t EnableCompositeEffect(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                          const HdfCompositeEffectVdi& effect)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetEffectInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                  const std::string &effectType, HdfEffectInfoVdi &effectInfo)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t IsVibratorRunning(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                      bool& state)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t PlayHapticPattern(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                      const HapticPaketVdi& pkg)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetHapticCapacity(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                      HapticCapacityVdi& hapticCapacity)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetHapticStartUpTime(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                         int32_t mode, int32_t& startUpTime)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t StartByIntensity(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                     const std::string& effectType, uint16_t intensity)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetAllWaveInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                   std::vector<OHOS::HDI::Vibrator::V2_0::HdfWaveInformation> &info)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetDeviceVibratorInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                          std::vector<HdfVibratorInfoVdi> &vibratorInfo)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t RegVibratorPlugCallback(const sptr<V2_0::IVibratorPlugCallback> &callbackObj)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t UnRegVibratorPlugCallback(const sptr<V2_0::IVibratorPlugCallback> &callbackObj)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
};
struct VdiWrapperVibrator {
    struct HdfVdiBase base;
    IVibratorInterfaceVdi *vibratorModule;
};
} // V1_1
} // Vibrator
} // HDI
} // OHOS

#endif // OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_VDI_H