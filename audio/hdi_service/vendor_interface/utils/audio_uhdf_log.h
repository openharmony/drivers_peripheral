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

#ifndef AUDIO_UHDF_LOG_H
#define AUDIO_UHDF_LOG_H

#include <stdio.h>
#include "hdf_log.h"
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD002512

#ifndef AUDIO_HDF_LOG
#define AUDIO_FUNC_LOGD(fmt, arg...) \
    do {                             \
    } while (0)

#define AUDIO_FUNC_LOGI(fmt, arg...) \
    do {                             \
    } while (0)
#else
#define AUDIO_FUNC_LOGD(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGD("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#define AUDIO_FUNC_LOGI(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGI("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)
#endif

#define AUDIO_FUNC_LOGW(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGW("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#define AUDIO_FUNC_LOGE(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGE("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#ifndef CHECK_NULL_PTR_RETURN_DEFAULT
#define CHECK_NULL_PTR_RETURN_DEFAULT(pointer)          \
    do {                                                      \
        if ((pointer) == NULL) {                              \
            AUDIO_FUNC_LOGE("%{public}s is null and return INVALID_PARAM", #pointer); \
            return HDF_ERR_INVALID_PARAM;                                     \
        }                                                     \
    } while (0)
#endif

#ifndef CHECK_NULL_PTR_RETURN_VALUE
#define CHECK_NULL_PTR_RETURN_VALUE(pointer, ret)          \
    do {                                                      \
        if ((pointer) == NULL) {                              \
            AUDIO_FUNC_LOGE("%{public}s is null and return ret=%{public}d", #pointer, ret); \
            return (ret);                                     \
        }                                                     \
    } while (0)
#endif

#ifndef CHECK_NULL_PTR_RETURN
#define CHECK_NULL_PTR_RETURN(pointer)          \
    do {                                                      \
        if ((pointer) == NULL) {                              \
            AUDIO_FUNC_LOGE("pointer is null and return"); \
            return;                                     \
        }                                                     \
    } while (0)
#endif

#ifndef CHECK_VALID_RANGE_RETURN
#define CHECK_VALID_RANGE_RETURN(value, minValue, maxValue, ret)          \
    do {                                                      \
        if ((value) < (minValue) || (value) > (maxValue)) {                              \
            AUDIO_FUNC_LOGE("value is invalid and return ret=%{public}d", ret); \
            return (ret);                                     \
        }                                                     \
    } while (0)
#endif

#ifdef CHECK_TRUE_RETURN_RET_LOG
#undef CHECK_TRUE_RETURN_RET_LOG
#endif
#define CHECK_TRUE_RETURN_RET_LOG(cond, ret, fmt, ...)   \
    do {                                                \
        if ((cond)) {                                   \
            HDF_LOGE(fmt, ##__VA_ARGS__);               \
            return ret;                                 \
        }                                               \
    } while (0)

#endif