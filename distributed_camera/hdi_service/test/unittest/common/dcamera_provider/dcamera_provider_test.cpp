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

#include <gtest/gtest.h>

#include "dcamera_provider.h"
#include "dcamera_test_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DcameraProviderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

constexpr const char* TEST_DEVICE_ID = "bb536a637105409e904d4da83790a4a7";

void DcameraProviderTest::SetUpTestCase(void)
{
}

void DcameraProviderTest::TearDownTestCase(void)
{
}

void DcameraProviderTest::SetUp(void)
{
}

void DcameraProviderTest::TearDown(void)
{
}

/**
 * @tc.name: UnRegisterCameraHdfListener_001
 * @tc.desc: Verify UnRegisterCameraHdfListener
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DcameraProviderTest, UnRegisterCameraHdfListener_001, TestSize.Level1)
{
    EXPECT_EQ(DCamRetCode::FAILED,
        DCameraProvider::GetInstance()->UnRegisterCameraHdfListener(TEST_DEVICE_ID));
}
}
}