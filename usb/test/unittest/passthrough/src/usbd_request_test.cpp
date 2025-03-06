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

#include "usbd_request_test.h"

#include <iostream>
#include <vector>

#include "UsbSubTest.h"
#include "hdf_log.h"
#include "usbd_type.h"
#include "usbd_wrapper.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/iusb_port_interface.h"
#include "v2_0/usb_types.h"

const int SLEEP_TIME = 3;
const uint8_t INDEX_1 = 1;
const uint8_t INDEX_INVALID = 255;
const uint8_t CONFIG_ID_0 = 0;
const uint8_t CONFIG_ID_INVALID = 222;
const uint8_t BUS_NUM_INVALID = 255;
const uint8_t DEV_ADDR_INVALID = 255;
const uint8_t STRING_ID_INVALID = 233;
const uint32_t MAX_BUFFER_LENGTH = 255;
const int TAG_NUM_10 = 10;
const uint8_t INTERFACEID_OK = 1;
const uint8_t INTERFACEID_INVALID = 255;
const uint8_t POINTID_INVALID = 158;
const uint8_t CANCEL_POINTID_INVALID = 255;
// data interface have 2 point : 1->bulk_out 2->bulk_in
const uint8_t POINTID_DIR_IN = USB_ENDPOINT_DIR_IN | 2;
const uint8_t POINTID_DIR_OUT = USB_ENDPOINT_DIR_OUT | 1;
const uint8_t INVALID_NUM = 222;
const uint32_t TIME_WAIT = 10000;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V2_0;

UsbDev UsbdRequestTest::dev_ = {0, 0};
sptr<UsbSubTest> UsbdRequestTest::subscriber_ = nullptr;
namespace {
sptr<IUsbHostInterface> g_usbHostInterface = nullptr;
sptr<IUsbPortInterface> g_usbPortInterface = nullptr;

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdRequestTest::SetUpTestCase(void)
{
    g_usbHostInterface = IUsbHostInterface::Get(true);
    g_usbPortInterface = IUsbPortInterface::Get();
    if (g_usbHostInterface == nullptr || g_usbPortInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    
    auto ret = g_usbPortInterface->SetPortRole(1, 1, 1);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdRequestTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }
    subscriber_ = new UsbSubTest();
    if (g_usbHostInterface->BindUsbdHostSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    printf("bus num = %d, bus addr = %d\n", subscriber_->busNum_, subscriber_->devAddr_);
    ret = g_usbHostInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdRequestTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdRequestTest::TearDownTestCase(void)
{
    g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbHostInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdRequestTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdRequestTest::SetUp(void) {}

void UsbdRequestTest::TearDown(void) {}

/**
 * @tc.name: UsbdConfig001
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig001, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfigConfig001 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdConfig002
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig002, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfig002 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig003
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig003, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfig003 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig004
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig004, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    EXPECT_NE(ret, 0);
    configIndex = INDEX_1;
    ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfig004 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdConfig005
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig005, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfig005 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig006
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig006, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfig006 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig007
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, devAddr && configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig007, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfig007 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig008
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig008, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->SetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdSetConfig008 %{public}d SetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdConfig001
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig001, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->GetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfig001 %{public}d GetConfig=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdConfig002
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig002, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbHostInterface->GetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfig002 %{public}d GetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig003
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig003, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->GetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfig003 %{public}d GetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig004
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig004, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->GetConfig(dev, configIndex);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfig004 %{public}d GetConfig=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface001
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface001, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdClaimInterface002
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface002, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface002 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface003
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface003, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface003 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface004
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface004, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    interfaceId = INTERFACEID_INVALID;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface004 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface005
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface005, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface005 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface006
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface006, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface006 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface007
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface007, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface007 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface008
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface008, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClaimInterface008 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor001 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor002 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor003, TestSize.Level1)
{
    uint8_t devAddr = DEV_ADDR_INVALID;
    struct UsbDev dev = {dev_.busNum, devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor003 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, length error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor004 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor005, TestSize.Level1)
{
    uint8_t busNum = BUS_NUM_INVALID;
    uint8_t devAddr = DEV_ADDR_INVALID;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor005 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && length error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor006, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor006 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr && length error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor007, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor007 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && length error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor008, TestSize.Level1)
{
    uint8_t busNum = BUS_NUM_INVALID;
    uint8_t devAddr = DEV_ADDR_INVALID;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetDeviceDescriptor(dev, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetDeviceDescriptor008 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor001, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor001 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor002, TestSize.Level1)
{
    uint8_t stringId = 1;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor002 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, stringId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor003, TestSize.Level1)
{
    uint8_t stringId = INVALID_NUM;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor003 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor004, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor004 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor005, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor005 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor006, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor006 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr && stringID error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor007, TestSize.Level1)
{
    uint8_t stringId = STRING_ID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor007 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && stringID error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor008, TestSize.Level1)
{
    uint8_t stringId = STRING_ID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetStringDescriptor(dev, stringId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetStringDescriptor008 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor001, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor001 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor002, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor002 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor003, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor003 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor004, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor004 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor005, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor005 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor006, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor006 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor007, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor007 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor008, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbHostInterface->GetConfigDescriptor(dev, configId, devData);
    HDF_LOGI("UsbdRequestTest::UsbdGetConfigDescriptor008 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        devData.size(), sizeof(devData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetRawDescriptor001
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetRawDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> rawData;
    auto ret = g_usbHostInterface->GetRawDescriptor(dev, rawData);
    HDF_LOGI("UsbdRequestTest::UsbdGetRawDescriptor001 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        rawData.size(), sizeof(rawData), ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdGetRawDescriptor002
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetRawDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> rawData;
    auto ret = g_usbHostInterface->GetRawDescriptor(dev, rawData);
    HDF_LOGI("UsbdRequestTest::UsbdGetRawDescriptor002 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        rawData.size(), sizeof(rawData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetRawDescriptor003
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetRawDescriptor003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> rawData;
    auto ret = g_usbHostInterface->GetRawDescriptor(dev, rawData);
    HDF_LOGI("UsbdRequestTest::UsbdGetRawDescriptor003 length=%{public}zu buffer=%{public}zu ret=%{public}d",
        rawData.size(), sizeof(rawData), ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: GetFileDescriptor001
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t fd = 0;
    auto ret = g_usbHostInterface->GetFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetFileDescriptor001 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: GetFileDescriptor002
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    int32_t fd = 0;
    auto ret = g_usbHostInterface->GetFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetFileDescriptor002 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: GetFileDescriptor003
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    int32_t fd = 0;
    auto ret = g_usbHostInterface->GetFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetFileDescriptor003 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: GetFileDescriptor004
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, fd error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t fd = MAX_BUFFER_LENGTH;
    auto ret = g_usbHostInterface->GetFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetFileDescriptor004 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: GetDeviceFileDescriptor001
 * @tc.desc: Test functions to GetDeviceFileDescriptor
 * @tc.desc: int32_t GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetDeviceFileDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t fd = 0;
    auto ret = g_usbHostInterface->GetDeviceFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetDeviceFileDescriptor001 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: GetDeviceFileDescriptor002
 * @tc.desc: Test functions to GetDeviceFileDescriptor
 * @tc.desc: int32_t GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetDeviceFileDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    int32_t fd = 0;
    auto ret = g_usbHostInterface->GetDeviceFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetDeviceFileDescriptor002 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: GetDeviceFileDescriptor003
 * @tc.desc: Test functions to GetDeviceFileDescriptor
 * @tc.desc: int32_t GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetDeviceFileDescriptor003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    int32_t fd = 0;
    auto ret = g_usbHostInterface->GetDeviceFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetDeviceFileDescriptor003 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: GetDeviceFileDescriptor004
 * @tc.desc: Test functions to GetDeviceFileDescriptor
 * @tc.desc: int32_t GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, fd error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetDeviceFileDescriptor004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t fd = MAX_BUFFER_LENGTH;
    auto ret = g_usbHostInterface->GetDeviceFileDescriptor(dev, fd);
    HDF_LOGI("UsbdRequestTest::GetDeviceFileDescriptor004 %{public}d fd=%{public}d ret=%{public}d", __LINE__, fd, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue001 interfaceId=%{public}d pointId=%{public}d ret=%{public}d",
        interfaceId, pointId, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue002 interfaceId=%{public}d pointId=%{public}d ret=%{public}d",
        interfaceId, pointId, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue003, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue003 interfaceId=%{public}d pointId=%{public}d ret=%{public}d",
        interfaceId, pointId, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uin        t8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum && configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    interfaceId = INVALID_NUM;
    dev.busNum = BUS_NUM_INVALID;
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue004 interfaceId=%{public}d pointId=%{public}d ret=%{public}d",
        interfaceId, pointId, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue005 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest006
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceId && pointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    interfaceId = INVALID_NUM;
    pointId = INVALID_NUM;
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue006 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest007
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '7'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue007 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest008
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    interfaceId = INVALID_NUM;
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '8'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue008 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest009
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, interfaceId && pointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue009, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue009 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    interfaceId = INVALID_NUM;
    pointId = INVALID_NUM;
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '9'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestQueue009 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait001 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbHostInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait001 %{public}d RequestWait=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait002, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait002 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbHostInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait002 %{public}d RequestWait=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait003, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait003 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbHostInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait003 %{public}d RequestWait=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, timeout error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait004, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait004 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbHostInterface->RequestWait(dev, waitData, bufferData, -TIME_WAIT);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait004 %{public}d RequestWait=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait005, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait005 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> waitData(TAG_NUM_10);
    dev.devAddr = DEV_ADDR_INVALID;
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbHostInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    HDF_LOGI("UsbdRequestTest::UsbdRequestWait005 %{public}d RequestWait=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel001, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '1'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel001 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel001 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '2'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel002 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel002 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    dev = dev_;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel002 again %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '3'};
    struct UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel003 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel003 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    dev = dev_;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel003 again %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: intfId && endpointId error in pipe but not used
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '4'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel004 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    pipe.intfId = INTERFACEID_INVALID;
    pipe.endpointId = CANCEL_POINTID_INVALID;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel004 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_NQ(0, ret);
    pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel004 %{public}d again RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: call twice
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '5'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel005 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel005 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    dev = dev_;
    pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest006
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error && interfaceid ignore
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '6'};
    struct UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel006 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    pipe.intfId = 224;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel006 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    dev.busNum = dev_.busNum;
    pipe.intfId = INTERFACEID_OK;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest007
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr error && interfaceid ignore
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '7'};;
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel007 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    pipe.intfId = INTERFACEID_INVALID;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel007 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    dev.devAddr = dev_.devAddr;
    pipe.intfId = INTERFACEID_OK;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest008
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error && devAddr error && interfaceid ignore
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '8'};
    ret = g_usbHostInterface->RequestQueue(dev, pipe, clientData, bufferData);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel008 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    pipe.intfId = INTERFACEID_INVALID;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::UsbdRequestCancel008 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    dev = dev_;
    pipe.intfId = INTERFACEID_OK;
    ret = g_usbHostInterface->RequestCancel(dev, pipe);
    EXPECT_EQ(0, ret);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdReleaseInterface001
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);;
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface001 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdReleaseInterface002
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev = {BUS_NUM_INVALID, dev_.devAddr};
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface002 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface003
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev = {dev_.busNum, DEV_ADDR_INVALID};
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface003 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface004
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    interfaceId = INTERFACEID_INVALID;
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface004 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface005
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface005 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface006
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    interfaceId = INTERFACEID_INVALID;
    dev = {DEV_ADDR_INVALID, dev_.devAddr};
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface006 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface007
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    interfaceId = INTERFACEID_INVALID;
    dev = {dev_.busNum, DEV_ADDR_INVALID};
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface007 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface008
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    interfaceId = INTERFACEID_INVALID;
    dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    ret = g_usbHostInterface->ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdRequestTest::UsbdReleaseInterface008 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkCancel001
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    struct UsbPipe pipe = {interfaceId, pointId};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::BulkCancel001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::BulkCancel001 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    ret = g_usbHostInterface->BulkCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::BulkCancel001 %{public}d BulkCancel=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BulkCancel002
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    struct UsbPipe pipe = {interfaceId, pointId};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::BulkCancel002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::BulkCancel002 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbHostInterface->BulkCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::BulkCancel002 %{public}d BulkCancel=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    dev = dev_;
    ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::BulkCancel002 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: BulkCancel003
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    struct UsbPipe pipe = {interfaceId, pointId};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::BulkCancel003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::BulkCancel003 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbHostInterface->BulkCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::BulkCancel003 %{public}d BulkCancel=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    dev = dev_;
    ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::BulkCancel003 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: BulkCancel004
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    struct UsbPipe pipe = {interfaceId, pointId};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::BulkCancel004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::BulkCancel004 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    pipe.intfId = POINTID_INVALID;
    ret = g_usbHostInterface->BulkCancel(dev, pipe);
    HDF_LOGI("UsbdRequestTest::BulkCancel004 %{public}d BulkCancel=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    dev = dev_;
    pipe = {interfaceId, pointId};
    ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::BulkCancel004 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

} // namespace
