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

#ifndef OHOS_HDI_PARTITIONSLOT_V1_0_PARTITIONSLOTIMPL_H
#define OHOS_HDI_PARTITIONSLOT_V1_0_PARTITIONSLOTIMPL_H

#include "v1_0/ipartition_slot.h"

namespace OHOS {
namespace HDI {
namespace Partitionslot {
namespace V1_0 {
class PartitionSlotImpl : public IPartitionSlot {
public:
    virtual ~PartitionSlotImpl() {}
    int32_t GetCurrentSlot(int32_t& currentSlot, int32_t& numOfSlots) override;
    int32_t GetSlotSuffix(int32_t slot, std::string& suffix) override;
    int32_t SetActiveSlot(int32_t slot) override;
    int32_t SetSlotUnbootable(int32_t slot) override;
};
} // V1_0
} // Partitionslot
} // HDI
} // OHOS

#endif // OHOS_HDI_PARTITIONSLOT_V1_0_PARTITIONSLOTIMPL_H