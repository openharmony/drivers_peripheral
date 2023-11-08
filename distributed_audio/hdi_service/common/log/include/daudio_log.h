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

#ifndef OHOS_DAUDIO_LOG_H
#define OHOS_DAUDIO_LOG_H

#include <cstring>

namespace OHOS {
namespace DistributedHardware {
typedef enum {
    DH_LOG_DEBUG,
    DH_LOG_INFO,
    DH_LOG_WARN,
    DH_LOG_ERROR,
} DHLogLevel;

void DHLog(DHLogLevel logLevel, const char *fmt, ...);

#define DHLOGD(fmt, ...) DHLog(DH_LOG_DEBUG, \
    (std::string("[") + DH_LOG_TAG + "][" + __FUNCTION__ + "]:" + fmt).c_str(), ##__VA_ARGS__)

#define DHLOGI(fmt, ...) DHLog(DH_LOG_INFO, \
    (std::string("[") + DH_LOG_TAG + "][" + __FUNCTION__ + "]:" + fmt).c_str(), ##__VA_ARGS__)

#define DHLOGW(fmt, ...) DHLog(DH_LOG_WARN, \
    (std::string("[") + DH_LOG_TAG + "][" + __FUNCTION__ + "]:" + fmt).c_str(), ##__VA_ARGS__)

#define DHLOGE(fmt, ...) DHLog(DH_LOG_ERROR, \
    (std::string("[") + DH_LOG_TAG + "][" + __FUNCTION__ + "]:" + fmt).c_str(), ##__VA_ARGS__)
} // Distributedaudio
} // OHOS
#endif
