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

#include "executor_impl_test.h"

#include <gtest/gtest.h>

#include "executor_impl.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace HDI::PinAuth::V1_0;
using namespace testing::ext;

void ExecutorImplTest::SetUpTestCase()
{
}

void ExecutorImplTest::TearDownTestCase()
{
}

void ExecutorImplTest::SetUp()
{
}

void ExecutorImplTest::TearDown()
{
}

/**
 * @tc.name: Hdi_is_nullptr test
 * @tc.desc: verify Hdi_is_nullptr
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(ExecutorImplTest, Hdi_is_nullptr_test, TestSize.Level1)
{
    ExecutorImpl *impl = new (std::nothrow) ExecutorImpl(nullptr);
    ExecutorInfo info = {};
    int32_t result = impl->GetExecutorInfo(info);
    EXPECT_EQ(result, HDF_FAILURE);

    uint64_t templateId = 0;
    TemplateInfo templateInfo = {};
    result = impl->GetTemplateInfo(templateId, templateInfo);
    EXPECT_EQ(result, HDF_FAILURE);

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey;
    std::vector<uint8_t> extraInfo;
    result = impl->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    EXPECT_EQ(result, HDF_FAILURE);

    uint64_t scheduleId = 0;
    result = impl->Enroll(scheduleId, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Authenticate(scheduleId, templateId, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_FAILURE);

    uint64_t authSubType = 10010;
    std::vector<uint8_t> pinData(32, 1);
    result = impl->OnSetData(scheduleId, authSubType, pinData);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Delete(templateId);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Cancel(scheduleId);
    EXPECT_EQ(result, HDF_FAILURE);

    int32_t commandId = 0;
    result = impl->SendCommand(commandId, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_SUCCESS);
    delete impl;
}

/**
 * @tc.name: Hdi_is_not_nullptr test
 * @tc.desc: verify Hdi_is_not_nullptr
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(ExecutorImplTest, Hdi_is_not_nullptr_test, TestSize.Level1)
{
    std::shared_ptr<PinAuth> pinHdi = std::make_shared<PinAuth>();
    EXPECT_NE(pinHdi, nullptr);
    ExecutorImpl *impl = new (std::nothrow) ExecutorImpl(pinHdi);
    ExecutorInfo info = {};
    int32_t result = impl->GetExecutorInfo(info);
    EXPECT_EQ(result, HDF_SUCCESS);

    uint64_t templateId = 0;
    TemplateInfo templateInfo = {};
    result = impl->GetTemplateInfo(templateId, templateInfo);
    EXPECT_EQ(result, 2);

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey;
    std::vector<uint8_t> extraInfo;
    result = impl->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    EXPECT_EQ(result, HDF_SUCCESS);

    uint64_t scheduleId = 0;
    result = impl->Enroll(scheduleId, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Authenticate(scheduleId, templateId, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_FAILURE);

    uint64_t authSubType = 10010;
    std::vector<uint8_t> pinData(32, 1);
    result = impl->OnSetData(scheduleId, authSubType, pinData);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Delete(templateId);
    EXPECT_EQ(result, 2);

    result = impl->Cancel(scheduleId);
    EXPECT_EQ(result, HDF_FAILURE);
    delete impl;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
