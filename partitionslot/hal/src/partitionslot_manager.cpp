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

#include "partitionslot_manager.h"

#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include "param_wrapper.h"
#include "hilog/log.h"

namespace OHOS {
namespace HDI {
namespace Partitionslot {
namespace V1_0 {
#define  HILOG_LOG_TAG           hdf_partitionslot_manager

constexpr int32_t UPDATE_PARTITION_B = 2;

constexpr off_t MISC_PARTITION_ACTIVE_SLOT_OFFSET = 4096;
constexpr off_t MISC_PARTITION_ACTIVE_SLOT_SIZE = 4;

constexpr off_t MISC_PARTITION_UNBOOT_SLOT_OFFSET = MISC_PARTITION_ACTIVE_SLOT_OFFSET + MISC_PARTITION_ACTIVE_SLOT_SIZE;
constexpr off_t MISC_PARTITION_UNBOOT_SLOT_SIZE = 4;

#define MISC_DEVICE_NODE "/dev/block/by-name/misc"

int32_t PartitionSlotManager::GetCurrentSlot(int32_t& currentSlot, int32_t& numOfSlots)
{
    HILOG_DEBUG(LOG_CORE, "%{public}s called!", __func__);
    numOfSlots = system::GetIntParameter("ohos.boot.bootslots", 1);
    currentSlot = ReadMisc(MISC_PARTITION_ACTIVE_SLOT_OFFSET, MISC_PARTITION_ACTIVE_SLOT_SIZE);
    HILOG_INFO(LOG_CORE, "current slot is %{public}d, numOfSlots is %{public}d", currentSlot, numOfSlots);
    return 0;
}

int32_t PartitionSlotManager::GetSlotSuffix(int32_t slot, std::string& suffix)
{
    HILOG_DEBUG(LOG_CORE, "%{public}s called!", __func__);
    if (slot == UPDATE_PARTITION_B) {
        suffix = "_b";
    } else {
        suffix = "";
    }
    HILOG_INFO(LOG_CORE, "suffix is %{public}s", suffix.c_str());
    return 0;
}

int32_t PartitionSlotManager::SetActiveSlot(int32_t slot)
{
    HILOG_DEBUG(LOG_CORE, "%{public}s called!, slot is %{public}d", __func__, slot);
    return WriteSlotToMisc(slot, MISC_PARTITION_ACTIVE_SLOT_OFFSET, MISC_PARTITION_ACTIVE_SLOT_SIZE);
}

int32_t PartitionSlotManager::SetSlotUnbootable(int32_t slot)
{
    HILOG_DEBUG(LOG_CORE, "%{public}s called!, slot is %{public}d", __func__, slot);
    return WriteSlotToMisc(slot, MISC_PARTITION_UNBOOT_SLOT_OFFSET, MISC_PARTITION_UNBOOT_SLOT_SIZE);
}

int32_t PartitionSlotManager::WriteSlot(int fd, int32_t slot, off_t offset, off_t size)
{
    if (lseek(fd, offset, SEEK_SET) < 0) {
        HILOG_ERROR(LOG_CORE, "Failed lseek slot %{public}d errno %{public}d", slot, errno);
        return -1;
    }

    if (write(fd, &slot, size) != size) {
        HILOG_ERROR(LOG_CORE, "Write slot failed ");
        return -1;
    }
    return 0;
}

int PartitionSlotManager::ReadMisc(off_t offset, off_t size)
{
    int fd = open(MISC_DEVICE_NODE, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        return -1;
    }
    if (lseek(fd, offset, SEEK_SET) < 0) {
        HILOG_ERROR(LOG_CORE, "Failed lseek miscDevice errno %{public}d ", errno);
        close(fd);
        return -1;
    }
    int32_t slot = 0;
    if (read(fd, &slot, size) != size) {
        HILOG_ERROR(LOG_CORE, "Failed read migic miscDevice errno %{public}d ", errno);
        close(fd);
        return -1;
    }
    HILOG_INFO(LOG_CORE, "Read slot %{public}d", slot);
    close(fd);
    return slot;
}

int PartitionSlotManager::WriteSlotToMisc(int32_t slot, off_t offset, off_t size)
{
    if (slot < 0) {
        HILOG_ERROR(LOG_CORE, "Invalid slot : %{public}d", slot);
        return -1;
    }
    int fd = open(MISC_DEVICE_NODE, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        HILOG_ERROR(LOG_CORE, "Failed to open miscDevice errno %{public}d ", errno);
        return -1;
    }

    if (WriteSlot(fd, slot, offset, size) < 0) {
        HILOG_ERROR(LOG_CORE, "Failed to WriteSlot miscDevice %{public}d errno %{public}d ", slot, errno);
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
} // V1_0
} // Partitionslot
} // HDI
} // OHOS
