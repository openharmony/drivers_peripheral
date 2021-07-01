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

/**
 * @addtogroup Vibrator
 * @{
 *
 * @brief Provides unified APIs for vibrator services to access vibrator drivers.
 *
 * A vibrator service can obtain a vibrator driver object or agent and then call APIs provided by this object or
 *  agent to access different types of vibrator devices based on the vibrator.
 *
 * @since 2.2
 */

/**
 * @file vibrator_if.h
 *
 * @brief Declares the APIs provided by the vibrator module to control vibrator.
 *
 * @since 2.2
 * @version 1.0
 */

#ifndef VIBRATOR_IF_H
#define VIBRATOR_IF_H

#include <stdint.h>
#include "vibrator_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

struct VibratorInterface {
    /**
     * @brief Controls this vibrator to perform a one-shot vibration at a given duration.
     *
     * @param duration Indicates the duration that the one-shot vibration lasts, in milliseconds.
     * @return Returns <b>0</b> if the sensor is successfully disabled; returns a negative value otherwise.
     *
     * @since 2.2
     * @version 1.0
     */
    int32_t (*StartOnce)(uint32_t duration);
    /**
     * @brief Controls this vibrator to perform a one-shot vibration with a preset vibration effect.
     *
     * @param effectType Indicates the preset vibration effect.
     * @return Returns <b>0</b> if the sensor is successfully disabled; returns a negative value otherwise.
     *
     * @since 2.2
     * @version 1.0
     */
    int32_t (*Start)(const char *effectType);
    /**
     * @brief Controls this vibrator to stop the vibration.
     *
     * @param mode Indicates the mode of the vibration to stop.The values can be time or
     * preset, respectively representing a one-shot vibration effect, a preset vibration effect.
     * see {@link VibratorMode}.
     * @return Returns <b>0</b> if the sensor is successfully disabled; returns a negative value otherwise.
     *
     * @since 2.2
     * @version 1.0
     */
    int32_t (*Stop)(enum VibratorMode mode);
};

/**
 * @brief Creates a <b>VibratorInterface</b> instance.
 * You can use the instance to obtain vibrator information, controls this vibrator to perform a one-shot vibration
 * with a preset vibration effect or this vibrator to perform a one-shot vibration at a given duration and
 * stops vibrator.
 *
 * @return Returns a non-zero value if the instance is successfully created; returns <b>0</b> otherwise.
 *
 * @since 2.2
 * @version 1.0
 */
const struct VibratorInterface *NewVibratorInterfaceInstance(void);

/**
 * @brief Releases the <b>VibratorInterface</b> instance.
 *
 * @return Returns <b>0</b> if the instance is successfully released; returns a negative value otherwise.
 *
 * @since 2.2
 * @version 1.0
 */
int32_t FreeVibratorInterfaceInstance(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* VIBRATOR_IF_H */
/** @} */