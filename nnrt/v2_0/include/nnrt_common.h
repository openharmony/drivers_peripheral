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

#ifndef OHOS_HDI_NNRT_V2_0_COMMON_H
#define OHOS_HDI_NNRT_V2_0_COMMON_H
#include <string.h>
#include <stdint.h>
#include "hilog/log.h"
#include "stdio.h"
#ifdef HDF_LOG_TAG
#undef HDF_LOG_TAG
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#undef LOG_TAG
#undef LOG_DOMAIN
#define LOG_TAG "NNRT"
#define LOG_DOMAIN 0xD002600

#define FILENAME_BASE (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)

#ifndef NNRT_DEBUG_ENABLE
#define NNRT_DEBUG_ENABLE 0
#endif

#ifndef NNRT_LOGD
#define NNRT_LOGD(format, ...)                                                                                     \
    do {                                                                                                              \
        if (NNRT_DEBUG_ENABLE) {                                                                                   \
            HILOG_DEBUG(LOG_CORE, "[%{public}s@%{public}s:%{public}d] " format "\n",                                  \
                __FUNCTION__, FILENAME_BASE, __LINE__,                                                                 \
                ##__VA_ARGS__);                                                                                       \
        }                                                                                                             \
    } while (0)
#endif

#ifndef NNRT_LOGI
#define NNRT_LOGI(format, ...)                                                                                     \
    do {                                                                                                              \
        HILOG_INFO(LOG_CORE, "[%{public}s@%{public}s:%{public}d] " format "\n", __FUNCTION__, FILENAME_BASE, __LINE__, \
            ##__VA_ARGS__);                                                                                           \
    } while (0)
#endif

#ifndef NNRT_LOGW
#define NNRT_LOGW(format, ...)                                                                                     \
    do {                                                                                                              \
        HILOG_WARN(LOG_CORE, "[%{public}s@%{public}s:%{public}d] " format "\n", __FUNCTION__, FILENAME_BASE, __LINE__, \
            ##__VA_ARGS__);                                                                                           \
    } while (0)
#endif

#ifndef NNRT_LOGE
#define NNRT_LOGE(format, ...)                                 \
    do {                                                          \
        HILOG_ERROR(LOG_CORE,                                     \
            "\033[0;32;31m"                                       \
            "[%{public}s@%{public}s:%{public}d] " format "\033[m" \
            "\n",                                                 \
            __FUNCTION__, FILENAME_BASE, __LINE__, ##__VA_ARGS__); \
    } while (0)
#endif

static inline bool checkNullpointer(const void* pointer)
{
    if (pointer == NULL) {
        NNRT_LOGE("pointer is null and return ret\n");
        return false;
    }
    return true;
}

#ifndef NNRT_CHK_RETURN
#define NNRT_CHK_RETURN(val, ret, ...) \
    do {                                  \
        if (val) {                        \
            __VA_ARGS__;                  \
            return (ret);                 \
        }                                 \
    } while (0)
#endif

#ifndef NNRT_CHK_RETURN_NOT_VALUE
#define NNRT_CHK_RETURN_NOT_VALUE(val, ...) \
    do {                                            \
        if (val) {                                  \
            __VA_ARGS__;                            \
            return;                                 \
        }                                           \
    } while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* OHOS_HDI_NNRT_V2_0_COMMON_H */
