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
    HDF_LOGD("SetUp SeVendorAdaptionsTest");
}

void SeVendorAdaptionsTest::TearDown()
{
    HDF_LOGD("TearDown SeVendorAdaptionsTest");
}

/**
 * @tc.name: getAtr001
 * @tc.desc: Test SeVendorAdaptionsTest getAtr.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getAtr001, TestSize.Level1)
{
    std::vector<uint8_t> response;
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
    const std::vector<uint8_t> command;
    std::vector<uint8_t> response;
    SecureElementStatus status;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    int ret = seVendorAdaptions->transmit(command, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: reset001
 * @tc.desc: Test SeVendorAdaptionsTest reset.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, reset001, TestSize.Level1)
{
    SecureElementStatus status;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    int ret = seVendorAdaptions->reset(status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: getStatusBySW001
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW001, TestSize.Level1)
{
    uint8_t sw1 = 0x62;
    uint8_t sw2 = 0;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_SUCCESS);
}

/**
 * @tc.name: getStatusBySW002
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW002, TestSize.Level1)
{
    uint8_t sw1 = 0x63;
    uint8_t sw2 = 0;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_SUCCESS);
}

/**
 * @tc.name: getStatusBySW003
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW003, TestSize.Level1)
{
    uint8_t sw1 = 0x90;
    uint8_t sw2 = 0x00;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_SUCCESS);
}

/**
 * @tc.name: getStatusBySW004
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW004, TestSize.Level1)
{
    uint8_t sw1 = 0x6A;
    uint8_t sw2 = 0x82;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_NO_SUCH_ELEMENT_ERROR);
}

/**
 * @tc.name: getStatusBySW005
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW005, TestSize.Level1)
{
    uint8_t sw1 = 0x69;
    uint8_t sw2 = 0x99;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_NO_SUCH_ELEMENT_ERROR);
}

/**
 * @tc.name: getStatusBySW006
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW006, TestSize.Level1)
{
    uint8_t sw1 = 0x69;
    uint8_t sw2 = 0x85;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_NO_SUCH_ELEMENT_ERROR);
}

/**
 * @tc.name: getStatusBySW007
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW007, TestSize.Level1)
{
    uint8_t sw1 = 0x6A;
    uint8_t sw2 = 0x86;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_OPERATION_NOT_SUPPORTED_ERROR);
}

/**
 * @tc.name: getStatusBySW008
 * @tc.desc: Test SeVendorAdaptionsTest getStatusBySW.
 * @tc.type: FUNC
 */
HWTEST_F(SeVendorAdaptionsTest, getStatusBySW008, TestSize.Level1)
{
    uint8_t sw1 = 0;
    uint8_t sw2 = 0;
    std::shared_ptr<SeVendorAdaptions> seVendorAdaptions = std::make_shared<SeVendorAdaptions>();
    SecureElementStatus ret = seVendorAdaptions->getStatusBySW(sw1, sw2);
    ASSERT_TRUE(ret == SecureElementStatus::SE_GENERAL_ERROR);
}
}
}
}
}