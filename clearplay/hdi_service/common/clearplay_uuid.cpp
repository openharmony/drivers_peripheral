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

#include <hdf_base.h>
#include <hdf_log.h>
#include "clearplay_uuid.h"

#define HDF_LOG_TAG    data_parse

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

bool IsClearPlayUuid(const std::string& uuid) {
    return uuid == CLEARPLAY_NAME;
}

} // V1_0
} // Drm
} // HDI
} // OHOS