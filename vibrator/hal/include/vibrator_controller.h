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

#define EFFECT_TYPE_MAX 9

#define CHECK_NULL_PTR_RETURN_VALUE(ptr, ret) do { \
    if ((ptr) == NULL) { \
        HDF_LOGE("%s:line:%{public}d pointer is null and return ret", __func__, __LINE__); \
        return (ret); \
    } \
} while (0)

#define CHECK_NULL_PTR_RETURN(ptr) do { \
    if ((ptr) == NULL) { \
        HDF_LOGE("%s:line:%{public}d pointer is null and return", __func__, __LINE__); \
        return; \
    } \
} while (0)

enum VibratorIoCmd {
    VIBRATOR_IO_START_ONCE                     = 0,
    VIBRATOR_IO_START_EFFECT                   = 1,
    VIBRATOR_IO_STOP                           = 2,
    VIBRATOR_IO_GET_INFO                       = 3,
    VIBRATOR_IO_ENABLE_MODULATION_PARAMETER    = 4,
    VIBRATOR_IO_IS_VIBRATOR_RUNNING            = 5,
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

struct Map g_effectmap[EFFECT_TYPE_MAX] = {
    {"haptic.clock.timer", true, 2000},
    {"haptic.long_press.heavy", true, 80},
    {"haptic.long_press.medium", true, 80},
    {"haptic.long_press.light", true, 80},
    {"haptic.fail", true, 60},
    {"haptic.charging", true, 100},
    {"haptic.slide.light", true, 10},
    {"haptic.threshold", true, 42},
    {"haptic.default.effect", false, 0},
};

#endif /* HAL_VIBRATOR_CONTROLLER_H */