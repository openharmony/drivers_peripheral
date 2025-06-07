/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "all_in_one_impl_test.h"

#include <gtest/gtest.h>

#include "securec.h"

#include "all_in_one_impl.h"
#include "common_impl.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;
using namespace HDI::PinAuth;

void AllInOneImplTest::SetUpTestCase()
{
}

void AllInOneImplTest::TearDownTestCase()
{
}

void AllInOneImplTest::SetUp()
{
}

void AllInOneImplTest::TearDown()
{
}

/**
 * @tc.name: Hdi_is_nullptr test
 * @tc.desc: verify Hdi_is_nullptr
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AllInOneImplTest, Hdi_is_nullptr_test, TestSize.Level1)
{
    AllInOneImpl *impl = new (std::nothrow) AllInOneImpl(nullptr);
    HdiExecutorInfo info = {};
    int32_t result = impl->GetExecutorInfo(info);
    EXPECT_EQ(result, HDF_FAILURE);

    uint64_t templateId = 0;
    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey;
    std::vector<uint8_t> extraInfo;
    result = impl->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    EXPECT_EQ(result, HDF_FAILURE);

    uint64_t scheduleId = 0;
    result = impl->Enroll(scheduleId, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_ERR_INVALID_PARAM);

    result = impl->Authenticate(scheduleId, templateIdList, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_ERR_INVALID_PARAM);

    uint64_t authSubType = 10010;
    uint32_t pinLength = 0;
    std::vector<uint8_t> pinData(32, 1);
    int32_t resultCode = 0;
    result = impl->SetData(scheduleId, authSubType, pinData, pinLength, resultCode);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Delete(templateId);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Cancel(scheduleId);
    EXPECT_EQ(result, HDF_FAILURE);

    std::vector<int32_t> propertyTypes;
    HdiProperty property;
    result = impl->GetProperty(templateIdList, propertyTypes, property);
    EXPECT_EQ(result, HDF_FAILURE);

    delete impl;
}

/**
 * @tc.name: Hdi_is_not_nullptr test
 * @tc.desc: verify Hdi_is_not_nullptr
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(AllInOneImplTest, Hdi_is_not_nullptr_test, TestSize.Level1)
{
    std::shared_ptr<PinAuth> pinHdi = std::make_shared<PinAuth>();
    EXPECT_NE(pinHdi, nullptr);
    pinHdi->Init();
    AllInOneImpl *impl = new (std::nothrow) AllInOneImpl(pinHdi);
    HdiExecutorInfo info = {};
    int32_t result = impl->GetExecutorInfo(info);
    EXPECT_EQ(result, HDF_SUCCESS);

    KeyPair *keyPair = GenerateEd25519KeyPair();
    ASSERT_NE(keyPair, nullptr);

    uint64_t templateId = 0;
    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey(keyPair->pubKey->buf, keyPair->pubKey->buf + keyPair->pubKey->contentSize);
    std::vector<uint8_t> extraInfo;
    result = impl->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
    EXPECT_EQ(result, HDF_SUCCESS);

    uint64_t scheduleId = 0;
    result = impl->Enroll(scheduleId, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_ERR_INVALID_PARAM);

    uint8_t challenge[32] = {0};
    Buffer *fwkExtraInfo = GetAuthFwkExtraInfo(scheduleId, keyPair, challenge, 32);
    ASSERT_NE(fwkExtraInfo, nullptr);

    std::vector<uint8_t> authExtraInfo(fwkExtraInfo->buf, fwkExtraInfo->buf + fwkExtraInfo->contentSize);
    result = impl->Authenticate(scheduleId, templateIdList, extraInfo, nullptr);
    EXPECT_EQ(result, HDF_ERR_INVALID_PARAM);

    uint64_t authSubType = 10010;
    int32_t resultCode = 0;
    uint32_t pinLength = 0;
    std::vector<uint8_t> pinData(32, 1);
    result = impl->SetData(scheduleId, authSubType, pinData, pinLength, resultCode);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Delete(templateId);
    EXPECT_EQ(result, HDF_FAILURE);

    result = impl->Cancel(scheduleId);
    EXPECT_EQ(result, HDF_FAILURE);

    std::vector<int32_t> propertyTypes;
    HdiProperty property;
    result = impl->GetProperty(templateIdList, propertyTypes, property);
    EXPECT_EQ(result, HDF_ERR_INVALID_PARAM);

    templateIdList.push_back(1);
    result = impl->GetProperty(templateIdList, propertyTypes, property);
    EXPECT_EQ(result, HDF_FAILURE);
    delete impl;
    DestroyKeyPair(keyPair);
    DestroyBuffer(fwkExtraInfo);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
