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

/**
 * @addtogroup Light
 * @{
 *
 * @brief Provides unified APIs for light services to access the light driver.
 *
 * After obtaining a driver object or agent, a light service starts or stops the light
 * using the functions provided by the driver object or agent.
 *
 * @version 1.0
 */

/**
 * @file light_type.h
 *
 * @brief Defines the light data structure, including the vibration mode and effect type.
 *
 * @since 2.2
 * @version 1.0
 */

#ifndef LIGHT_TYPE_H
#define LIGHT_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define LIGHT_FLASH_NONE    0
#define LIGHT_FLASH_TIMED   1

/**
 * @brief Enumerates return values of the light module.
 *
 */
enum LightStatus {
    LIGHT_SUCCESS            = 0,    /**< The operation is successful. */
    LIGHT_NOT_SUPPORT        = -1,   /**< The logical not supported. */
    LIGHT_NOT_FLASH          = -2,   /**< The flashing settings are not supported. */
    LIGHT_NOT_BRIGHTNESS     = -3,   /**< The brightness settings are not supported. */
};

/**
 * @brief Enumerates light types.
 *
 */
enum LightType {
    LIGHT_TYPE_NONE                = 0,
    LIGHT_TYPE_BATTERY             = 1,
    LIGHT_TYPE_NOTIFICATIONS       = 2,
    LIGHT_TYPE_ATTENTION           = 3,
    LIGHT_TYPE_BUTT
};

struct LightFlashEffect {
int32_t flashMode; // Flashing mode
int32_t onTime; // enable duration unit: millisecond
int32_t offTime; // enable duration unit: millisecond
};

struct LightEffect {
int32_t lightBrightness; // Brightness value, RGB highest bit represents the color RGB: R:16-31bit、G:8-15bit、B：0-7bit
struct LightFlashEffect flashEffect; // @struct LightFlashEffect
};

/**
 * @brief Defines basic light information.
 *
 * Information about a light includes the light type,  User defined extension information
 *
 */
struct LightInfo {
    uint32_t lightType;    // Light type obtained @enum LightType
    int32_t reserved;    // User defined extension information
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* LIGHT_TYPE_H */
/** @} */
