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

#include <gtest/gtest.h>
#include <osal_mem.h>
#include <unistd.h>
#include "hdf_log.h"
#include "hdi/idevmgr_hdi.h"
#include "v1_0/ipartition_slot.h"

namespace OHOS {
namespace PartitionSlot {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::Partitionslot::V1_0;
using OHOS::HDI::DeviceManager::V1_0::IDeviceManager;

class HDFPartitionSlotTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        auto devmgr = IDeviceManager::Get();
        if (devmgr != nullptr) {
            devmgr->LoadDevice("partition_slot_service");
        } else {
            std::cout << "Get devmgr failed" << std::endl;
        }
    }
    static void TearDownTestCase()
    {
        auto devmgr = IDeviceManager::Get();
        if (devmgr != nullptr) {
            devmgr->UnloadDevice("partition_slot_service");
        } else {
            std::cout << "Get devmgr failed" << std::endl;
        }
    }
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(HDFPartitionSlotTest, HdfPartitionSlotTest_001, TestSize.Level1)
{
    std::cout << "begin get currentslot by service" << std::endl;
    int numOfSlots = 0;
    int currentSlot = -1;
    sptr<IPartitionSlot> partitionslot = IPartitionSlot::Get();
    ASSERT_TRUE(partitionslot != nullptr);
    ASSERT_TRUE(partitionslot->GetCurrentSlot(currentSlot, numOfSlots) == 0);
}

HWTEST_F(HDFPartitionSlotTest, HdfPartitionSlotTest_002, TestSize.Level1)
{
    std::cout << "begin get suffix by service" << std::endl;
    std::string suffix = "";
    int slot = 2;
    sptr<IPartitionSlot> partitionslot = IPartitionSlot::Get();
    ASSERT_TRUE(partitionslot != nullptr);
    ASSERT_TRUE(partitionslot->GetSlotSuffix(slot, suffix) == 0);
}

HWTEST_F(HDFPartitionSlotTest, HdfPartitionSlotTest_003, TestSize.Level1)
{
    std::cout << "begin set active slot by service" << std::endl;
    int numOfSlots = 0;
    int currentSlot = 0;
    sptr<IPartitionSlot> partitionslot = IPartitionSlot::Get();
    ASSERT_TRUE(partitionslot != nullptr);
    partitionslot->GetCurrentSlot(currentSlot, numOfSlots);
    ASSERT_TRUE(partitionslot->SetActiveSlot(2) == 0);
    partitionslot->SetActiveSlot(currentSlot);
}

HWTEST_F(HDFPartitionSlotTest, HdfPartitionSlotTest_004, TestSize.Level1)
{
    std::cout << "begin set unbootable slot by service" << std::endl;
    sptr<IPartitionSlot> partitionslot = IPartitionSlot::Get();
    ASSERT_TRUE(partitionslot != nullptr);
    ASSERT_TRUE(partitionslot->SetSlotUnbootable(2) == 0);
}
} // PartitionSlot
} // OHOS
