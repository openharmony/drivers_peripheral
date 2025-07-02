/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_LPP_BASE_TYPE_H
#define OHOS_HDI_LPP_BASE_TYPE_H

#include <string>
#include <map>

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {

#define CHECK_NULLPOINTER_RETURN_VALUE(pointer, ret) do { \
    if ((pointer) == NULL) { \
        HDF_LOGE("%s: pointer is null", __func__); \
        return (ret); \
    } \
} while (0)

#define CHECK_NULLPOINTER_RETURN(pointer) do { \
    if ((pointer) == NULL) { \
        HDF_LOGE("%s: pointer is null", __func__); \
        return; \
    } \
} while (0)

#define CHECK_TRUE_RETURN_RET_LOG(cond, ret, fmt, ...)   \
    do {                                                \
        if ((cond)) {                                   \
            HDF_LOGE(fmt, ##__VA_ARGS__);               \
            return ret;                                 \
        }                                               \
} while (0)

}
}
}
}
#endif // OHOS_HDI_LPP_V1_0_BASE_TYPE_H