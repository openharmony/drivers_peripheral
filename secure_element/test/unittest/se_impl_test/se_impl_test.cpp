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

namespace OHOS {
namespace HDI {
namespace SecureElement {
namespace TEST {
using namespace testing;
using namespace testing::ext;

class SeImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SeImplTest::SetUpTestCase()
{
    HDF_LOGD("SetUpTestCase SeImplTest");
}

void SeImplTest::TearDownTestCase()
{
    HDF_LOGD("TearDownTestCase SeImplTest");
}

void SeImplTest::SetUp()
{
    HDF_LOGD("SetUp SeImplTest");
}

void SeImplTest::TearDown()
{
    HDF_LOGD("TearDown SeImplTest");
}

/**
 * @tc.name: init001
 * @tc.desc: Test SeImplTest init.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, init001, TestSize.Level0)
{
    const sptr<ISecureElementCallback> clientCallback = nullptr;
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->init(clientCallback, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: getAtr001
 * @tc.desc: Test SeImplTest getAtr.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, getAtr001, TestSize.Level1)
{
    std::vector<uint8_t> response;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->getAtr(response);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: isSecureElementPresent001
 * @tc.desc: Test SeImplTest isSecureElementPresent.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, isSecureElementPresent001, TestSize.Level1)
{
    bool present = false;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->isSecureElementPresent(present);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: openLogicalChannel001
 * @tc.desc: Test SeImplTest openLogicalChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openLogicalChannel001, TestSize.Level1)
{
    std::vector<uint8_t> aid;
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    uint8_t channelNumber = 0;
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->openLogicalChannel(aid, p2, response, channelNumber, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: openLogicalChannel002
 * @tc.desc: Test SeImplTest openLogicalChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openLogicalChannel002, TestSize.Level1)
{
    std::vector<uint8_t> aid = {0x001, 0x002, 0x003};
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    uint8_t channelNumber = 0;
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->openLogicalChannel(aid, p2, response, channelNumber, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: openBasicChannel001
 * @tc.desc: Test SeImplTest openBasicChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openBasicChannel001, TestSize.Level1)
{
    const std::vector<uint8_t> aid;
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->openBasicChannel(aid, p2, response, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: openBasicChannel002
 * @tc.desc: Test SeImplTest openBasicChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openBasicChannel002, TestSize.Level1)
{
    const std::vector<uint8_t> aid = {0x001, 0x002, 0x003};
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->openBasicChannel(aid, p2, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: closeChannel001
 * @tc.desc: Test SeImplTest closeChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, closeChannel001, TestSize.Level1)
{
    uint8_t channelNumber = 0;
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->closeChannel(channelNumber, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: transmit001
 * @tc.desc: Test SeImplTest transmit.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, transmit001, TestSize.Level1)
{
    const std::vector<uint8_t> command;
    std::vector<uint8_t> response;
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->transmit(command, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: reset001
 * @tc.desc: Test SeImplTest reset.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, reset001, TestSize.Level1)
{
    SecureElementStatus status;
    std::shared_ptr<SeImpl> seImpl = std::make_shared<SeImpl>();
    int ret = seImpl->reset(status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}
}
}
}
}