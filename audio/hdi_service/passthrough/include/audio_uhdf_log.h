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

#endif
