/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef ADAPTOR_LOG_H
#define ADAPTOR_LOG_H

#include "hdf_log.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD002411

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "USER_AUTH_HDI"

#ifndef OHOS_DEBUG
#define DECORATOR_HDFLOG(op, fmt, args...)             \
    do {                                               \
        op("%{public}s() " fmt, __FUNCTION__, ##args); \
    } while (0)
#else
#define DECORATOR_HDFLOG(op, fmt, args...)                                     \
    do {                                                                       \
        op("{%s()-%s:%d} " fmt, __FUNCTION__, __LINE__, ##args); \
    } while (0)
#endif

#define LOG_ERROR(fmt, ...) DECORATOR_HDFLOG(HDF_LOGE, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) DECORATOR_HDFLOG(HDF_LOGI, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // ADAPTOR_LOG_H