/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_DISPLAY_BUFFER_V1_4_ALLOCATOR_SERVICE_H
#define OHOS_HDI_DISPLAY_BUFFER_V1_4_ALLOCATOR_SERVICE_H

#include "allocator_service.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_4 {
class AllocatorService : public V1_0::AllocatorService {
public:
    AllocatorService() = default;
    ~AllocatorService() = default;
};
} // namespace V1_4
} // namespace Buffer
} // namespace Display
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_DISPLAY_BUFFER_V1_4_ALLOCATOR_SERVICE_H
