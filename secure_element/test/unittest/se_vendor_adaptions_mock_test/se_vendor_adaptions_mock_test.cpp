/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <thread>
#include <string>
#include <vector>
#include <securec.h>
#include <sstream>
#include <hdf_log.h>

#include "se_impl.h"
#include "se_vendor_adaptions.h"
#include "mock.h"

namespace OHOS {
namespace HDI {
namespace SecureElement {
namespace TEST {
using namespace testing;
using namespace testing::ext;

class SeVendorAdaptionsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    MockTee mockTee_;
};

void SeVendorAdaptionsTest::SetUpTestCase()
{
    HDF_LOGD("SetUpTestCase SeVendorAdaptionsTest");
}

void SeVendorAdaptionsTest::TearDownTestCase()
{
    HDF_LOGD("TearDownTestCase SeVendorAdaptionsTest");
}

void SeVendorAdaptionsTest::SetUp()
{
    MockTee::SetMockTee(mockTee_);
    HDF_LOGD("SetUp SeVendorAdaptionsTest");
}

void SeVendorAdaptionsTest::TearDown()
{
    MockTee::ResetMockTee();
    HDF_LOGD("TearDown SeVendorAdaptionsTest");
}

/**
 * @tc.name: getAtr001
 * @tc.desc: Test SeVendorAdaptionsTest getAtr.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getAtr001, TestSize.Level1)
{
    std::vector<uint8_t> response = {0x01, 0x02, 0x03};
    EXPECT_CALL(mockTee_, VendorSecureElementCaGetAtr(_, _))
        .WillOnce(Return(0));
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    int ret = seVendorAdaptions->getAtr(response);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: openLogicalChannel002
 * @tc.desc: Test SeVendorAdaptionsTest openLogicalChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, openLogicalChannel002, TestSize.Level1)
{
    std::vector<uint8_t> aid = {0x001, 0x002, 0x003};
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    uint8_t channelNumber = 0;
    SecureElementStatus status;
    EXPECT_CALL(mockTee_, VendorSecureElementCaOpenLogicalChannel(_, _, _, _, _, _))
        .WillOnce(Return(0));
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    int ret = seVendorAdaptions->openLogicalChannel(aid, p2, response, channelNumber, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: openBasicChannel002
 * @tc.desc: Test SeVendorAdaptionsTest openBasicChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, openBasicChannel002, TestSize.Level1)
{
    EXPECT_CALL(mockTee_, VendorSecureElementCaOpenBasicChannel(_, _, _, _))
        .WillOnce(Return(0));
    const std::vector<uint8_t> aid = {0x001, 0x002, 0x003};
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    SecureElementStatus status;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    int ret = seVendorAdaptions->openBasicChannel(aid, p2, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: closeChannel001
 * @tc.desc: Test SeVendorAdaptionsTest closeChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, closeChannel001, TestSize.Level1)
{
    EXPECT_CALL(mockTee_, VendorSecureElementCaCloseChannel(_))
        .WillOnce(Return(0));
    EXPECT_CALL(mockTee_, VendorSecureElementCaUninit())
        .WillOnce(Return(0));
    uint8_t channelNumber = 0;
    SecureElementStatus status;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    int ret = seVendorAdaptions->closeChannel(channelNumber, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: transmit001
 * @tc.desc: Test SeVendorAdaptionsTest transmit.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, transmit001, TestSize.Level1)
{
    EXPECT_CALL(mockTee_, VendorSecureElementCaTransmit(_, _, _, _))
        .WillOnce(Return(0));
    const std::vector<uint8_t> command;
    std::vector<uint8_t> response;
    SecureElementStatus status;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    int ret = seVendorAdaptions->transmit(command, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}
}
}
}
}