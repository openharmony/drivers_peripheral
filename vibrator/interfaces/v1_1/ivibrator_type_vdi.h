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

#ifndef IVIBRATOR_TYPE_VDI_H
#define IVIBRATOR_TYPE_VDI_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

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
    bool reserved0;
    int32_t reserved1;
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* IVIBRATOR_TYPE_VDI_H */
/** @} */
