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
#ifndef HDI_DEVICE_INTELL_VOICE_LOG_H
#define HDI_DEVICE_INTELL_VOICE_LOG_H

#include <cstdio>
#include "hdf_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002561

#define INTELLIGENT_VOICE_LOGD(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGD("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#define INTELLIGENT_VOICE_LOGI(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGI("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)


#define INTELLIGENT_VOICE_LOGW(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGW("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#define INTELLIGENT_VOICE_LOGE(fmt, arg...)                                                \
    do {                                                                            \
        HDF_LOGE("[%{public}s][line:%{public}d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#endif