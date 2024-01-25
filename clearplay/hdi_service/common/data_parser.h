/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CLEARPLAY_DATAPARSER_H
#define CLEARPLAY_DATAPARSER_H

#include <hdf_base.h>
#include <hdi_base.h>
#include "v1_0/media_key_system_types.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
const size_t KEY_ID_SIZE = 16;
const size_t SYSTEM_ID_SIZE = 16;

int32_t ParsePssh(const std::vector<uint8_t> &initData, std::vector<std::vector<uint8_t>> &keyIds);

int32_t generateRequest(const MediaKeyType keyType, const std::vector<std::vector<uint8_t>> &keyIds,
    std::string *request);

int32_t findSubVector(const std::vector<uint8_t> &main, const std::vector<uint8_t> &sub);
} // V1_0
} // Drm
} // HDI
} // OHOS
#endif // CLEARPLAY_DATAPARSER_H