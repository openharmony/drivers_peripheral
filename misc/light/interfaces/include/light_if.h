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
 * @brief Provides a driver for upper-layer Light services.
 *
 * After obtaining a driver object or agent, a Light service starts or stops the Light
 * using the functions provided by the driver object or agent.
 *
 * @since 2.2
 */

/**
 * @file Light_if.h
 *
 * @brief Declare the generic API in the light module. These APIs can be used to control
 *  light enable, de enable, brightness, and blink modes.
 *
 * @since 2.2
 * @version 1.0
 */

#ifndef LIGHT_IF_H
#define LIGHT_IF_H

#include <stdint.h>
#include "light_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @brief Defines the function of performing basic operations on the light.
 *
 * The operations include obtaining light information, enabling or disabling light,
 * setting light brightness, setting light flicker mode.
 */

struct LightInterface {
    /**
     * @brief Obtains information about all Lights in the system.
     *
     * @param lightInfo basic light information. For details, see {@link LightInfo}.
     *
     * @return Returns <b>0</b> if the information is obtained; returns a negative value otherwise.
     *
     * @since 2.2
     * @version 1.0
     */
    int32_t (*GetLightInfo)(struct LightInfo **lightInfo, uint32_t *count);

    /**
     * @brief Enables the light available in the light list based on the specified slight type.
     *
     * @param type Indicates the light type. For details, see {@link LightTypeTag}.
     * @param effect Sets the information for the light. For details, see {@link LightEffect}.
     *
     * @return Command execution result: 0 succeeded, - 1 logic lamp does not support,
     * - 2 logic lamp does not support flashing setting, - 3 logic lamp does not support brightness setting
     *
     * @since 2.2
     * @version 1.0
     */
    int32_t (*TurnOnLight)(uint32_t type, struct LightEffect *effect);

    /**
     * @brief Disables the lights available in the light list according to the specified light type.
     *
     * @param type Indicates the light type. For details, see {@link LightTypeTag}.
     *
     * @return Returns <b>0</b> if the sensor is successfully disabled; returns a negative value otherwise.
     *
     * @since 2.2
     * @version 1.0
     */
    int32_t (*TurnOffLight)(uint32_t type);
};

/**
 * @brief Creates a <b>LightInterface</b> instance.
 * You can use this instance to obtain light information and perform operations of turning on, turning off,
 * brightness setting and flashing mode setting for the specified type of light.
 *
 * @return the successfully created instance. Returns a non-zero value; Otherwise, return < b > 0 < / b >.
 *
 * @since 2.2
 * @version 1.0
 */
const struct LightInterface *NewLightInterfaceInstance(void);

/**
 * @brief Releases this <b>LightInterface</b> instance to free up related resources.
 *
 * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
 *
 * @since 2.2
 * @version 1.0
 */
int32_t FreeLightInterfaceInstance(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* LIGHT_IF_H */
/** @} */
