/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ENCODE_HEIF_LOG
#define ENCODE_HEIF_LOG

#include "hdf_log.h"
#define HDF_LOG_TAG codec_heif_encoder

#define IF_TRUE_RETURN(cond)  \
    do {                               \
        if (cond) {                    \
            return;                \
        }                              \
    } while (0)

#define IF_TRUE_RETURN_WITH_MSG(cond, msg, ...) \
    do {                                                 \
        if (cond) {                                      \
            HDF_LOGE(msg, ##__VA_ARGS__);                \
            return;                                  \
        }                                                \
    } while (0)

#define IF_TRUE_RETURN_VAL(cond, val)  \
    do {                               \
        if (cond) {                    \
            return val;                \
        }                              \
    } while (0)

#define IF_TRUE_RETURN_VAL_WITH_MSG(cond, val, msg, ...) \
    do {                                                 \
        if (cond) {                                      \
            HDF_LOGE(msg, ##__VA_ARGS__);                \
            return val;                                  \
        }                                                \
    } while (0)

#endif // ENCODE_HEIF_LOG