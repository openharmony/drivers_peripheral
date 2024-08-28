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
#include <hdf_log.h>

#include "nfc_impl.h"
#include "mock.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
namespace V1_1 {
namespace TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::Nfc;
class NfcImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NfcImplTest::SetUpTestCase()
{
    HDF_LOGD("SetUpTestCase NfcImplTest");
}

void NfcImplTest::TearDownTestCase()
{
    HDF_LOGD("TearDownTestCase NfcImplTest");
}

void NfcImplTest::SetUp()
{
    HDF_LOGD("SetUp NfcImplTest");
}

void NfcImplTest::TearDown()
{
    HDF_LOGD("TearDown NfcImplTest");
}

/**
 * @tc.name: Open001
 * @tc.desc: Test NfcImplTest Open.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Open001, TestSize.Level1)
{
    const sptr<INfcCallback> callbackObj = nullptr;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Open(callbackObj, status);
    EXPECT_EQ(ret, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: CoreInitialized001
 * @tc.desc: Test NfcImplTest CoreInitialized.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, CoreInitialized001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->CoreInitialized(data, status);
    EXPECT_EQ(ret, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: CoreInitialized002
 * @tc.desc: Test NfcImplTest CoreInitialized.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, CoreInitialized002, TestSize.Level1)
{
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->CoreInitialized(data, status);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: Prediscover001
 * @tc.desc: Test NfcImplTest Prediscover.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Prediscover001, TestSize.Level1)
{
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Prediscover(status);
    ASSERT_TRUE(ret == HDF_FAILURE);
}

/**
 * @tc.name: Write001
 * @tc.desc: Test NfcImplTest Write.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Write001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Write(data, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: Write002
 * @tc.desc: Test NfcImplTest Write.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Write002, TestSize.Level1)
{
    std::vector<uint8_t> data = {0x001, 0x002, 0x003};
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Write(data, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: ControlGranted001
 * @tc.desc: Test NfcImplTest ControlGranted.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, ControlGranted001, TestSize.Level1)
{
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->ControlGranted(status);
    ASSERT_TRUE(ret == HDF_FAILURE);
}

/**
 * @tc.name: PowerCycle001
 * @tc.desc: Test NfcImplTest PowerCycle.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, PowerCycle001, TestSize.Level1)
{
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->PowerCycle(status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: Close001
 * @tc.desc: Test NfcImplTest Close.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Close001, TestSize.Level1)
{
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Close(status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: Ioctl001
 * @tc.desc: Test NfcImplTest Ioctl.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Ioctl001, TestSize.Level1)
{
    NfcCommand cmd = NfcCommand::CMD_INVALID;
    std::vector<uint8_t> data;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Ioctl(cmd, data, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: Ioctl002
 * @tc.desc: Test NfcImplTest Ioctl.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Ioctl002, TestSize.Level1)
{
    NfcCommand cmd = NfcCommand::CMD_INVALID;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Ioctl(cmd, data, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: IoctlWithResponse001
 * @tc.desc: Test NfcImplTest IoctlWithResponse.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, IoctlWithResponse001, TestSize.Level1)
{
    NfcCommand cmd = NfcCommand::CMD_INVALID;
    std::vector<uint8_t> data;
    std::vector<uint8_t> response;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->IoctlWithResponse(cmd, data, response, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: IoctlWithResponse002
 * @tc.desc: Test NfcImplTest IoctlWithResponse.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, IoctlWithResponse002, TestSize.Level1)
{
    NfcCommand cmd = NfcCommand::CMD_INVALID;
    std::vector<uint8_t> data = {0X001};
    std::vector<uint8_t> response;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->IoctlWithResponse(cmd, data, response, status);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: IoctlWithResponse003
 * @tc.desc: Test NfcImplTest IoctlWithResponse.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, IoctlWithResponse003, TestSize.Level1)
{
    NfcCommand cmd = NfcCommand::CMD_INVALID;
    std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
        57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
        77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
        114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
        131, 132, 133};
    std::vector<uint8_t> response;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->IoctlWithResponse(cmd, data, response, status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

/**
 * @tc.name: GetVendorConfig001
 * @tc.desc: Test NfcImplTest GetVendorConfig.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, GetVendorConfig001, TestSize.Level1)
{
    NfcVendorConfig config;
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->GetVendorConfig(config, status);
    ASSERT_TRUE(ret == HDF_FAILURE);
}

/**
 * @tc.name: DoFactoryReset001
 * @tc.desc: Test NfcImplTest DoFactoryReset.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, DoFactoryReset001, TestSize.Level1)
{
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->DoFactoryReset(status);
    ASSERT_TRUE(ret == HDF_FAILURE);
}

/**
 * @tc.name: Shutdown001
 * @tc.desc: Test NfcImplTest Shutdown.
 * @tc.type: FUNC
 */
HWTEST_F(NfcImplTest, Shutdown001, TestSize.Level1)
{
    NfcStatus status = NfcStatus::OK;
    std::shared_ptr<NfcImpl> nfcImpl = std::make_shared<NfcImpl>();
    int ret = nfcImpl->Shutdown(status);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}
}
}
}
}
}