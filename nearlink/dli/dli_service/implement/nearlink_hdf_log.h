/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef NARLINK_HDF_LOG_H
#define NARLINK_HDF_LOG_H

#include <hdf_log.h>

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000154

#ifndef HDF_LOG_TAG
#define HDF_LOG_TAG    nearlink_hdf
#endif

#ifdef NL_HDF_CHECK_RETURN
#undef NL_HDF_CHECK_RETURN
#endif

#define NL_HDF_CHECK_RETURN(cond, fmt, ...)            \
    do {                                            \
        if (!(cond)) {                              \
            HDF_LOGE(fmt, ##__VA_ARGS__);             \
            return;                                 \
        }                                           \
    } while (0)

#endif // NARLINK_HDF_LOG_H