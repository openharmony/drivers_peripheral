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
 *  agent to access different types of vibrator devices.
 *
 * @version 1.0
 */

/**
 * @file vibrator_type.h
 *
 * @brief Defines the data used by the vibrator module, including the vibrator types, vibrator effect.
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
 * @brief Enumerates return values of the vibrator mode.
 *
 * @since 2.2
 */
enum VibratorMode {
    VIBRATOR_MODE_ONCE   = 0,    /**< The mode of stopping a one-shot vibration effect. */
    VIBRATOR_MODE_PRESET = 1,    /**< The mode of stopping a preset vibration effect. */
    VIBRATOR_MODE_ABNORMAL       /**< The mode of test abnormal effect. */
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* VIBRATOR_TYPE_H */
/** @} */