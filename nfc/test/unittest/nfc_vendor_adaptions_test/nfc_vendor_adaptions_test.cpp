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

#include "nfc_vendor_adaptions.h"
#include "nfc_impl.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
namespace TEST {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::Nfc;
class NfcVendorAdaptionsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NfcVendorAdaptionsTest::SetUpTestCase()
{
    HDF_LOGD("SetUpTestCase NfcVendorAdaptionsTest");
}

void NfcVendorAdaptionsTest::TearDownTestCase()
{
    HDF_LOGD("TearDownTestCase NfcVendorAdaptionsTest");
}

void NfcVendorAdaptionsTest::SetUp()
{
    HDF_LOGD("SetUp NfcVendorAdaptionsTest");
}

void NfcVendorAdaptionsTest::TearDown()
{
    HDF_LOGD("TearDown NfcVendorAdaptionsTest");
}

/**
 * @tc.name: VendorOpen001
 * @tc.desc: Test NfcVendorAdaptionsTest VendorOpen.
 * @tc.type: FUNC
 */
HWTEST_F(NfcVendorAdaptionsTest, VendorOpen001, TestSize.Level1)
{
    NfcStackCallbackT *pCback = nullptr;
    NfcStackDataCallbackT *pDataCback = nullptr;
    std::shared_ptr<NfcVendorAdaptions> nfcVendorAdaptions = std::make_shared<NfcVendorAdaptions>();
    int ret = nfcVendorAdaptions->VendorOpen(pCback, pDataCback);
    EXPECT_EQ(ret, HDF_FAILURE);
}

/**
 * @tc.name: VendorCoreInitialized001
 * @tc.desc: Test NfcVendorAdaptionsTest VendorCoreInitialized.
 * @tc.type: FUNC
 */
HWTEST_F(NfcVendorAdaptionsTest, VendorCoreInitialized001, TestSize.Level1)
{
    uint16_t coreInitRspLen = 0;
    uint8_t *pCoreInitRspParams = nullptr;
    std::shared_ptr<NfcVendorAdaptions> nfcVendorAdaptions = std::make_shared<NfcVendorAdaptions>();
    int ret = nfcVendorAdaptions->VendorCoreInitialized(coreInitRspLen, pCoreInitRspParams);
    EXPECT_EQ(ret, HDF_FAILURE);
}

/**
 * @tc.name: VendorWrite001
 * @tc.desc: Test NfcVendorAdaptionsTest VendorWrite.
 * @tc.type: FUNC
 */
HWTEST_F(NfcVendorAdaptionsTest, VendorWrite001, TestSize.Level1)
{
    uint16_t dataLen = 0;
    uint8_t *pData = nullptr;
    std::shared_ptr<NfcVendorAdaptions> nfcVendorAdaptions = std::make_shared<NfcVendorAdaptions>();
    int ret = nfcVendorAdaptions->VendorWrite(dataLen, pData);
    EXPECT_EQ(ret, HDF_FAILURE);
}

/**
 * @tc.name: VendorIoctl001
 * @tc.desc: Test NfcVendorAdaptionsTest VendorIoctl.
 * @tc.type: FUNC
 */
HWTEST_F(NfcVendorAdaptionsTest, VendorIoctl001, TestSize.Level1)
{
    long arg = 0;
    void *pData = nullptr;
    std::shared_ptr<NfcVendorAdaptions> nfcVendorAdaptions = std::make_shared<NfcVendorAdaptions>();
    int ret = nfcVendorAdaptions->VendorIoctl(arg, pData);
    EXPECT_EQ(ret, HDF_FAILURE);
}

/**
 * @tc.name: VendorIoctlWithResponse001
 * @tc.desc: Test NfcVendorAdaptionsTest VendorIoctlWithResponse.
 * @tc.type: FUNC
 */
HWTEST_F(NfcVendorAdaptionsTest, VendorIoctlWithResponse001, TestSize.Level1)
{
    long arg = 0;
    void *pData = nullptr;
    std::vector<uint8_t> pRetVal;
    std::shared_ptr<NfcVendorAdaptions> nfcVendorAdaptions = std::make_shared<NfcVendorAdaptions>();
    int ret = nfcVendorAdaptions->VendorIoctlWithResponse(arg, pData, 0, pRetVal);
    EXPECT_EQ(ret, HDF_FAILURE);
}

/**
 * @tc.name: VendorShutdownCase001
 * @tc.desc: Test NfcVendorAdaptionsTest VendorShutdownCase.
 * @tc.type: FUNC
 */
HWTEST_F(NfcVendorAdaptionsTest, VendorShutdownCase001, TestSize.Level1)
{
    std::shared_ptr<NfcVendorAdaptions> nfcVendorAdaptions = std::make_shared<NfcVendorAdaptions>();
    int ret = nfcVendorAdaptions->VendorShutdownCase();
    EXPECT_EQ(ret, HDF_SUCCESS);
}
}
}
}
}