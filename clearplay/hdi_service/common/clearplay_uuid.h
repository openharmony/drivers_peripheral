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

#ifndef CLEARPLAY_CLEARPLAYUUID_H
#define CLEARPLAY_CLEARPLAYUUID_H

#include <hdf_base.h>
#include <hdi_base.h>

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
const std::string CLEARPLAY_UUID = "47a10ff0ca3c49c69c12a764ffde091f";
const std::string CLEARPLAY_NAME = "com.clearplay.drm";

bool IsClearPlayUuid(const std::string &uuid);
} // V1_0
} // Drm
} // HDI
} // OHOS
#endif // CLEARPLAY_CLEARPLAYUUID_H
