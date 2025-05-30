/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup Vibrator
 * @{
 *
 * @brief Provides unified APIs for vibrator services to access the vibrator driver.
 *
 * After obtaining a driver object or agent, a vibrator service starts or stops the vibrator
 * using the functions provided by the driver object or agent.
 *
 * @version 1.0
 */

/**
 * @file vibrator_type.h
 *
 * @brief Defines the vibrator data structure, including the vibration mode and effect type.
 *
 * @since 2.2
 * @version 1.0
 */

#ifndef VIBRATOR_TYPE_H
#define VIBRATOR_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @brief Enumerates the return values of the vibrator module.
 *
 * @since 3.2
 */
enum VibratorStatus {
    /** The operation is successful. */
    VIBRATOR_SUCCESS            = 0,
    /** The period setting is not supported. */
    VIBRATOR_NOT_PERIOD         = -1,
    /** The intensity setting is not supported. */
    VIBRATOR_NOT_INTENSITY      = -2,
    /** The frequency setting is not supported. */
    VIBRATOR_NOT_FREQUENCY      = -3,
};

/**
 * @brief Enumerates the vibration modes of this vibrator.
 *
 * @since 2.2
 */
enum VibratorMode {
    /**< Indicates the one-shot vibration with the given duration. */
    VIBRATOR_MODE_ONCE   = 0,
    /**< Indicates the periodic vibration with the preset effect. */
    VIBRATOR_MODE_PRESET = 1,
    /**< Indicates the vibration is high-definition. */
    VIBRATOR_MODE_HDHAPTIC = 2,
    /**< Indicates invalid the effect mode. */
    VIBRATOR_MODE_BUTT
};

/**
 * @brief Enumerates the effect types of the composite effects.
 *
 * @since 3.2
 */
enum EffectType {
    /**< Indicates the time effect type of the given time series. */
    EFFECT_TYPE_TIME,
    /**< Indicates primitive vibration effect type for a given primitive vibration sequence. */
    EFFECT_TYPE_PRIMITIVE,
    /**< Indicates invalid the effect type. */
    EFFECT_TYPE_BUTT,
};

/**
 * @brief Enumerates the event types.
 *
 * @since 4.1
 */
enum EVENT_TYPE {
    /**< Indicates that the vibration is continuous. */
    CONTINUOUS = 0,
    /**< Indicates that the vibration is instantaneous. */
    TRANSIENT  = 1,
};

/**
 * @brief Defines the vibration parameters.
 *
 * The parameters include the setting intensity and frequency capability the on and intensity and frequency range.
 *
 * @since 3.2
 */
struct VibratorInfo {
    /**< setting intensity capability. 1 indicates support, 0 indicates not support. */
    bool isSupportIntensity;
    /**< setting frequency capability. 1 indicates support, 0 indicates not support. */
    bool isSupportFrequency;
    /**< Max intensity. */
    uint16_t intensityMaxValue;
    /**< Min intensity. */
    uint16_t intensityMinValue;
    /**< Max frequency(Hz). */
    int16_t frequencyMaxValue;
    /**< Min frequency(Hz). */
    int16_t frequencyMinValue;
};

/**
 * @brief Defines the time effect parameters.
 *
 * The parameters include delay, time, intensity and frequency of vibration.
 *
 * @since 3.2
 */
struct TimeEffect {
    int32_t delay;        /** Waiting time. */
    int32_t time;         /** Vibration time. */
    uint16_t intensity;   /** Vibration intensity. */
    int16_t frequency;    /** Vibration frequency(Hz). */
};

/**
 * @brief Defines the primitive effect parameters.
 *
 * The parameters include delay, effect id and vibration intensity.
 *
 * @since 3.2
 */
struct PrimitiveEffect {
    int32_t delay;         /** Waiting time. */
    int32_t effectId;      /** Effect id. */
    uint16_t intensity;    /** Vibration intensity. */
};

/**
 * @brief Defines two effects for custom composite effects.
 *
 * The parameters include time effect and primitive effect.
 *
 * @since 3.2
 */
union Effect {
    struct TimeEffect timeEffect;              /** Time effect, see {@link TimeEffect}. */
    struct PrimitiveEffect primitiveEffect;    /** Primitive effect, see {@link PrimitiveEffect}. */
};

/**
 * @brief Defines the composite vibration effect parameters.
 *
 * The parameters include type and sequences of composite effects.
 *
 * @since 3.2
 */
struct CompositeEffect {
    /** Type of the composite effect, see {@link union HdfEffectType}. */
    int32_t type;
    /** The sequences of composite effects, see {@link union Effect}. */
    union Effect effects[];
};

/**
 * @brief Defines the vibration effect information.
 *
 * The information include the capability to set the effect and the vibration duration of the effect.
 *
 * @since 3.2
 */
struct EffectInfo {
    /** Vibration duration of the effect, in milliseconds. */
    int32_t duration;
    /**< setting effect capability. 1 indicates support, 0 indicates not support. */
    bool isSupportEffect;
};


/**
 * @brief Defines the vibration point parameters.
 *
 * The information include the time, intensity, and frequency.
 *
 * @since 4.1
 */
struct CurvePoint {
    /** Time of the vibration point. */
    int32_t time;
    /** Intensity of the vibration point. */
    int32_t intensity;
    /** Frequency of the vibration point. */
    int32_t frequency;
};

/**
 * @brief Defines the HD vibration event.
 *
 * The information include the HD vibration event.
 *
 * @since 4.1
 */
struct HapticEvent {
    /** Indicates the vibration type. */
    enum EVENT_TYPE type;
    /** Indicates the vibration time. */
    int32_t time;
    /** Indicates the vibration duration. */
    int32_t duration;
    /** Indicates the vibration intensity. */
    int32_t intensity;
    /** Indicates the vibration frequency. */
    int32_t frequency;
    /** ID of the vibration motor. Indicates the time from command is issued to the time the motor starts. */
    int32_t index;
    /** Indicates the number of vibration points. */
    int32_t pointNum;
    /** Indicates the vibration point array. */
    struct CurvePoint points[];
};

/**
 * @brief Defines the vibration data delivery packet.
 *
 * The information include the different trypes of vibrationsr;
 *
 * @since 4.1
 */
struct HapticPaket {
    /** Indicates the vibration data delivery time. */
    int32_t time;
    /** Indicates the vibration number of data to be delivered. */
    int32_t eventNum;
    /** Indicates the vibration data delivery event array. */
    struct HapticEvent events[];
};

/**
 * @brief Defines the vibration capability data package.
 *
 * The information include the different types of vibrations.
 *
 * @since 4.1
 */
struct HapticCapacity {
    /** Indicates the vibration support HD vibration. */
    bool isSupportHdHaptic;
    /** Indicates the vibration support preset mapping. */
    bool isSupportPresetMapping;
    /** Indicates the vibration support dalay vibration. */
    bool isSupportTimeDelay;
    /** Indicates the vibration Standby parameter. */
    bool reserved0;
    /** Indicates the vibration Standby parameter. */
    int32_t reserved1;
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* VIBRATOR_TYPE_H */
/** @} */
