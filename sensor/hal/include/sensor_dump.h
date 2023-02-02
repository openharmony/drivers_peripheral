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

#ifndef HDI_SENSOR_DUMP_H
#define HDI_SENSOR_DUMP_H

#include <securec.h>
#include <stdint.h>
#include <string.h>
#include "hdf_sbuf.h"
#include "sensor_if.h"
#include "sensor_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

enum SensorDumpStatus {
    DUMP_SUCCESS = 0,
    DUMP_FAILURE = -1,
    DUMP_NULL_PTR = -2,
};

void SensorDevRegisterDump(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* HDI_SENSOR_DUMP_H */