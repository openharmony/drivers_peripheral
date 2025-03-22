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

#include "gtest/gtest.h"

#define private public
#define protected public
#include <v1_0/imemory_tracker_interface.h>
#include "hdf_base.h"
#undef private
#undef protected

namespace OHOS {
namespace Memory {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::Memorytracker::V1_0;

class HdfMemoryTrackerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfMemoryTrackerTest::SetUpTestCase()
{
}

void HdfMemoryTrackerTest::TearDownTestCase()
{
}

void HdfMemoryTrackerTest::SetUp()
{
}

void HdfMemoryTrackerTest::TearDown()
{
}

#ifdef HDF_MEMORYTRACKER_IS_IMPLEMENTED
HWTEST_F(HdfMemoryTrackerTest, GetMemoryTest_01, TestSize.Level1)
{
    printf("begin call memtrack by service \n");
    sptr<IMemoryTrackerInterface> memtrack = IMemoryTrackerInterface::Get();
    EXPECT_EQ(memtrack, nullptr);
    if (memtrack == nullptr) {
        printf("memtrack service is null \n");
        return;
    }

    std::vector<MemoryRecord> records;
    int errCode = memtrack->GetDevMem(0, MEMORY_TRACKER_TYPE_GL, records);
    if (errCode == HDF_SUCCESS) {
        printf("memtrack calll GetMemory success, num_records=%zu \n", records.size());
        int i = 0;
        for (auto record : records) {
            printf("memtrack: \trecords[%d], flag=%d, size=%lld \n", i++, record.flags, (long long)record.size);
        }
    }
}

HWTEST_F(HdfMemoryTrackerTest, GetMemoryTest_02, TestSize.Level1)
{
    printf("begin call memtrack passthrough \n");
    sptr<IMemoryTrackerInterface> memtrack = IMemoryTrackerInterface::Get(true);
    EXPECT_NE(memtrack, nullptr);
    if (memtrack == nullptr) {
        printf("memtrack service is null \n");
        return;
    }

    std::vector<MemoryRecord> records;
    int errCode = memtrack->GetDevMem(0, MEMORY_TRACKER_TYPE_GL, records);
    EXPECT_EQ(errCode, HDF_SUCCESS);
    if (errCode == HDF_SUCCESS) {
        printf("memtrack calll GetMemory success, num_records=%zu \n", records.size());
        int i = 0;
        for (auto record : records) {
            printf("memtrack: \trecords[%d], flag=%d, size=%lld \n", i++, record.flags, (long long)record.size);
        }
    }
}
#endif
}
}
