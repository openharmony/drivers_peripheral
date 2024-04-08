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

#include "adaptor_file_test.h"

#include <gtest/gtest.h>

#include "adaptor_file.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void AdaptorFileTest::SetUpTestCase()
{
}

void AdaptorFileTest::TearDownTestCase()
{
}

void AdaptorFileTest::SetUp()
{
}

void AdaptorFileTest::TearDown()
{
}

/**
 * @tc.name: FileOperator is nullptr
 * @tc.desc: verify IsFileOperatorValid
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorFileTest, FileOperator_test0, TestSize.Level1)
{
    bool result = IsFileOperatorValid(nullptr);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: FileOperator is DEFAULT_FILE_OPERATOR
 * @tc.desc: verify GetFileOperator
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AdaptorFileTest, FileOperator_test7, TestSize.Level1)
{
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    EXPECT_NE(fileOp, nullptr);
    bool result = IsFileOperatorValid(fileOp);
    EXPECT_EQ(result, true);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
