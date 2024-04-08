/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "adaptor_memory_test.h"

#include <gtest/gtest.h>

#include "adaptor_memory.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void AdaptorMemoryTest::SetUpTestCase()
{
}

void AdaptorMemoryTest::TearDownTestCase()
{
}

void AdaptorMemoryTest::SetUp()
{
}

void AdaptorMemoryTest::TearDown()
{
}

/**
 * @tc.name: Malloc and Free test
 * @tc.desc: verify Critical value
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorMemoryTest, Malloc_Free_test, TestSize.Level1)
{
    uint8_t *data1 = (uint8_t *)Malloc(0);
    EXPECT_EQ(data1, nullptr);
    constexpr uint64_t maxSize = 1073741825;
    uint8_t *data2 = (uint8_t *)Malloc(maxSize);
    EXPECT_EQ(data2, nullptr);
    Free(data2);
    uint8_t *data3 = (uint8_t *)Malloc(1);
    EXPECT_NE(data3, nullptr);
    Free(data3);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
