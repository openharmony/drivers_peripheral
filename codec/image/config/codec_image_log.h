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

#ifndef CODEC_IMAGE_LOG_H
#define CODEC_IMAGE_LOG_H
#include "hdf_log.h"
namespace OHOS {
#define HDF_LOG_TAG codec_hdi_image

#define FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define CODEC_LOGE(fmt, ...) HDF_LOGE("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGW(fmt, ...) HDF_LOGW("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGI(fmt, ...) HDF_LOGI("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGD(fmt, ...) HDF_LOGD("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)

#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...) \
do {                                                  \
    if (!(cond)) {                                    \
        CODEC_LOGE(fmt, ##__VA_ARGS__);               \
        return ret;                                   \
    }                                                 \
} while (0)
}  // namespace OHOS
#endif /* CODEC_IMAGE_LOG_H */
