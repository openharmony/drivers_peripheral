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

#ifndef HAL_VIBRATOR_CONTROLLER_H
#define HAL_VIBRATOR_CONTROLLER_H

#include "hdf_io_service_if.h"
#include "osal_mutex.h"
#include "vibrator_if.h"
#include "vibrator_type.h"

enum VibratorIoCmd {
    VIBRATOR_IO_START_ONCE                     = 0,
    VIBRATOR_IO_START_EFFECT                   = 1,
    VIBRATOR_IO_STOP                           = 2,
    VIBRATOR_IO_GET_INFO                       = 3,
    VIBRATOR_IO_ENABLE_MODULATION_PARAMETER    = 4,
    VIBRATOR_IO_END,
};

struct VibratorDevice {
    bool initState;
    struct VibratorInfo vibratorInfoEntry;
    struct HdfIoService *ioService;
    struct OsalMutex mutex;
};

struct Map {
    char *effectName;
    bool issupport;
    int  duration;
};

struct Map EffectMap[9] = {
    {.effectName = "haptic.clock.timer", .issupport = true, .duration = 2000},
    {.effectName = "haptic.long_press.heavy", .issupport = true, .duration = 80},
    {.effectName = "haptic.long_press.medium", .issupport = true, .duration = 80},
    {.effectName = "haptic.long_press.light", .issupport = true, .duration = 80},
    {.effectName = "haptic.fail", .issupport = true, .duration = 60},
    {.effectName = "haptic.charging", .issupport = true, .duration = 100},
    {.effectName = "haptic.slide.light", .issupport = true, .duration = 10},
    {.effectName = "haptic.threshold", .issupport = true, .duration = 42},
    {.effectName = "haptic.default.effect", .issupport = false, .duration = 0},
};

#endif /* HAL_VIBRATOR_CONTROLLER_H */