/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_CAMERA_LOG_H
#define OHOS_DISTRIBUTED_CAMERA_LOG_H

#include <string>
#include <cinttypes>

#include "hilog/log.h"

namespace OHOS {
namespace DistributedHardware {
#define DCAMERA_FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define _sl_(x) #x
#define _strline_(x) _sl_(x)
#define DCAMERA_STR_LINE _strline_(__LINE__)

#undef LOG_TAG
#define LOG_TAG "DCAMERA"

#define DHLOGD(fmt, ...) HILOG_DEBUG(LOG_CORE, \
    "[%{public}s][%{public}s][%{public}s:%{public}s]:" fmt, \
    DH_LOG_TAG, __FUNCTION__, DCAMERA_FILENAME, DCAMERA_STR_LINE, ##__VA_ARGS__)

#define DHLOGI(fmt, ...) HILOG_INFO(LOG_CORE, \
    "[%{public}s][%{public}s][%{public}s:%{public}s]:" fmt, \
    DH_LOG_TAG, __FUNCTION__, DCAMERA_FILENAME, DCAMERA_STR_LINE, ##__VA_ARGS__)

#define DHLOGW(fmt, ...) HILOG_WARN(LOG_CORE, \
    "[%{public}s][%{public}s][%{public}s:%{public}s]:" fmt, \
    DH_LOG_TAG, __FUNCTION__, DCAMERA_FILENAME, DCAMERA_STR_LINE, ##__VA_ARGS__)

#define DHLOGE(fmt, ...) HILOG_ERROR(LOG_CORE, \
    "[%{public}s][%{public}s][%{public}s:%{public}s]:" fmt, \
    DH_LOG_TAG, __FUNCTION__, DCAMERA_FILENAME, DCAMERA_STR_LINE, ##__VA_ARGS__)
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_CAMERA_LOG_H
