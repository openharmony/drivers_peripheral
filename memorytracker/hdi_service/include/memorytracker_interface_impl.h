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

#ifndef OHOS_HDI_MEMTRACK_V1_0_MEMTRACKINTERFACEINTERFACE_H
#define OHOS_HDI_MEMTRACK_V1_0_MEMTRACKINTERFACEINTERFACE_H

#include "v1_0/imemory_tracker_interface.h"

namespace OHOS {
namespace HDI {
namespace Memorytracker {
namespace V1_0 {
class MemoryTrackerInterfaceImpl : public IMemoryTrackerInterface {
public:
    virtual ~MemoryTrackerInterfaceImpl() {}

    int32_t GetDevMem(int32_t pid, MemoryTrackerType type, std::vector<MemoryRecord>& records) override;
};
} // V1_0
} // Memorytracker
} // HDI
} // OHOS

#endif // OHOS_HDI_MEMTRACK_V1_0_MEMTRACKINTERFACEINTERFACE_H