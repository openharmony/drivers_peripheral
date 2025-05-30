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

#ifndef HDI_SENSOR_COMMON_H
#define HDI_SENSOR_COMMON_H

#include <stdio.h>
#include "sensor_uhdf_log.h"

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

#endif /* HDI_SENSOR_COMMON_H */
