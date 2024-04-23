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

#include "se_impl.h"
#include "v1_0/isecure_element_interface.h"
#include "v1_0/secure_element_types.h"
#include "v1_0/isecure_element_callback.h"

namespace OHOS {
namespace HDI {
namespace TEST {
using namespace testing::ext;
using ISeHdiV1_0 = OHOS::HDI::SecureElement::V1_0::ISecureElementInterface;
using OHOS::HDI::SecureElement::V1_0::SecureElementStatus;
using OHOS::HDI::SecureElement::V1_0::ISecureElementCallback;
using namespace OHOS::HDI::SecureElement::V1_0;
class SeImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
public:
    // the max APDU response bytes
    static constexpr const uint16_t MAX_APDU_RESP_BYTES = 512;
    static constexpr const uint8_t HEX_BYTE_LEN = 2;
    void HexStringToBytesArray(const std::string &src, std::vector<uint8_t> &bytes);
};

class SeClientCallback : public ISecureElementCallback {
public:
    explicit SeClientCallback() {
    }

    int32_t OnSeStateChanged(bool connected) override
    {
        return HDF_SUCCESS;
    }
};
void SeImplTest::HexStringToBytesArray(const std::string &src, std::vector<uint8_t> &bytes)
{
    // convert hex string to byte array
    if (src.empty()) {
        return;
    }

    uint32_t bytesLen = src.length() / SeImplTest::HEX_BYTE_LEN;
    std::string strByte;
    unsigned int srcIntValue;
    for (uint32_t i = 0; i < bytesLen; i++) {
        strByte = src.substr(i * SeImplTest::HEX_BYTE_LEN, SeImplTest::HEX_BYTE_LEN);
        if (sscanf_s(strByte.c_str(), "%x", &srcIntValue) <= 0) {
            bytes.clear();
            return;
        }
        bytes.push_back(static_cast<uint8_t>(srcIntValue & 0xFF));
    }
}
void SeImplTest::SetUpTestCase()
{
    std::cout << " SetUpTestCase SeImplTest." << std::endl;
}

void SeImplTest::TearDownTestCase()
{
    std::cout << " TearDownTestCase SeImplTest." << std::endl;
}

void SeImplTest::SetUp()
{
    std::cout << " SetUp SeImplTest." << std::endl;
}

void SeImplTest::TearDown()
{
    std::cout << " TearDown SeImplTest." << std::endl;
}

/**
 * @tc.name: init001
 * @tc.desc: Test SeImplTest init.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, init001, TestSize.Level1)
{
    const sptr<ISecureElementCallback> clientCallback = nullptr;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->init(clientCallback, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: init002
 * @tc.desc: Test SeImplTest init.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, init002, TestSize.Level1)
{
    const sptr<ISecureElementCallback> clientCallback = new SeClientCallback();
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->init(clientCallback, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: getAtr001
 * @tc.desc: Test SeImplTest getAtr.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, getAtr001, TestSize.Level1)
{
    std::vector<uint8_t> vecResponse(MAX_APDU_RESP_BYTES, 0);
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->getAtr(vecResponse);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: getAtr002
 * @tc.desc: Test SeImplTest getAtr.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, getAtr002, TestSize.Level1)
{
    std::vector<uint8_t> vecResponse;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->getAtr(vecResponse);
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
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->isSecureElementPresent(present);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: openLogicalChannel001
 * @tc.desc: Test SeImplTest openLogicalChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openLogicalChannel001, TestSize.Level1)
{
    const std::vector<uint8_t> aid;
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    uint8_t channelNumber = 0;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->openLogicalChannel(aid, p2, response, channelNumber, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: openLogicalChannel002
 * @tc.desc: Test SeImplTest openLogicalChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openLogicalChannel002, TestSize.Level1)
{
    const std::vector<uint8_t> aid = {0x001};
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    uint8_t channelNumber = 0;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->openLogicalChannel(aid, p2, response, channelNumber, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: openLogicalChannel003
 * @tc.desc: Test SeImplTest openLogicalChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openLogicalChannel003, TestSize.Level1)
{
    std::string aidStr = "a000000151000000";
    std::vector<uint8_t> aid;
    HexStringToBytesArray(aidStr, aid);
    uint8_t p2 = 127;
    std::vector<uint8_t> response(MAX_APDU_RESP_BYTES, 0);
    uint8_t channelNumber = 0;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->openLogicalChannel(aid, p2, response, channelNumber, status);
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
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->openBasicChannel(aid, p2, response, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: openBasicChannel002
 * @tc.desc: Test SeImplTest openBasicChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openBasicChannel002, TestSize.Level1)
{
    const std::vector<uint8_t> aid = {0x001};
    uint8_t p2 = 0;
    std::vector<uint8_t> response;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->openBasicChannel(aid, p2, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: openBasicChannel003
 * @tc.desc: Test SeImplTest openBasicChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, openBasicChannel003, TestSize.Level1)
{
    std::string aidStr = "a000000151000000";
    std::vector<uint8_t> aid;
    HexStringToBytesArray(aidStr, aid);
    uint8_t p2 = 127;
    std::vector<uint8_t> response(MAX_APDU_RESP_BYTES, 0);
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->openBasicChannel(aid, p2, response, status);
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
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->closeChannel(channelNumber, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: closeChannel002
 * @tc.desc: Test SeImplTest closeChannel.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, closeChannel002, TestSize.Level1)
{
    uint8_t channelNumber = 1;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->closeChannel(channelNumber, status);
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
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->transmit(command, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: transmit002
 * @tc.desc: Test SeImplTest transmit.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, transmit002, TestSize.Level1)
{
    std::string cmdStr = "80CA9F7F00";
    std::vector<uint8_t> command;
    HexStringToBytesArray(cmdStr, command);
    std::vector<uint8_t> response;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->transmit(command, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: transmit003
 * @tc.desc: Test SeImplTest transmit.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, transmit003, TestSize.Level1)
{
    std::string cmdStr = "81CA9F7F00";
    std::vector<uint8_t> command;
    HexStringToBytesArray(cmdStr, command);
    std::vector<uint8_t> response;
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->transmit(command, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: reset001
 * @tc.desc: Test SeImplTest reset.
 * @tc.type: FUNC
 */
HWTEST_F(SeImplTest, reset001, TestSize.Level1)
{
    SecureElementStatus status = SecureElementStatus::SE_GENERAL_ERROR;
    OHOS::sptr<ISeHdiV1_0> seHdiInterface_ = ISeHdiV1_0::Get();
    int ret = seHdiInterface_->reset(status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}
}
}
}