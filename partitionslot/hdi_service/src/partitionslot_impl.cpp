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

#include "partitionslot_impl.h"

#include <hdf_base.h>
#include <hdf_log.h>
#include "partitionslot_manager.h"

namespace OHOS {
namespace HDI {
namespace Partitionslot {
namespace V1_0 {
#define HDF_LOG_TAG           hdf_partitionslot_impl

extern "C" IPartitionSlot *PartitionSlotImplGetInstance(void)
{
    return new (std::nothrow) PartitionSlotImpl();
}

int32_t PartitionSlotImpl::GetCurrentSlot(int32_t& currentSlot, int32_t& numOfSlots)
{
    HDF_LOGD("%{public}s called!", __func__);
    return PartitionSlotManager::GetInstance()->GetCurrentSlot(currentSlot, numOfSlots);
}

int32_t PartitionSlotImpl::GetSlotSuffix(int32_t slot, std::string& suffix)
{
    HDF_LOGD("%{public}s called!", __func__);
    return PartitionSlotManager::GetInstance()->GetSlotSuffix(slot, suffix);
}

int32_t PartitionSlotImpl::SetActiveSlot(int32_t slot)
{
    HDF_LOGD("%{public}s called!, slot is %{public}d", __func__, slot);
    return PartitionSlotManager::GetInstance()->SetActiveSlot(slot);
}

int32_t PartitionSlotImpl::SetSlotUnbootable(int32_t slot)
{
    HDF_LOGD("%{public}s called!, slot is %{public}d", __func__, slot);
    return PartitionSlotManager::GetInstance()->SetSlotUnbootable(slot);
}
} // V1_0
} // Partitionslot
} // HDI
} // OHOS
