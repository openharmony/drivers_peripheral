/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#include <iostream>
#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#include "usbd_type.h"
#include "v1_0/iusbd_subscriber.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

using OHOS::HDI::Usb::V1_0::UsbDev;

namespace {
const uint8_t INDEX_0 = 0;
const uint8_t INDEX_1 = 1;
const uint8_t INDEX_INVALID = 255;
const uint8_t BUS_NUM_INVALID = 255;
const uint8_t DEV_ADDR_INVALID = 255;
const uint8_t INTERFACEID_OK = 1;
const uint8_t INTERFACEID_INVALID = 255;
const int SLEEP_TIME = 3;
class UsbdInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static UsbDev dev_;
    static OHOS::sptr<OHOS::USB::UsbSubscriberTest> subscriber_;
};
UsbDev UsbdInterfaceTest::dev_ = {0, 0};
OHOS::sptr<OHOS::USB::UsbSubscriberTest> UsbdInterfaceTest::subscriber_ = nullptr;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

sptr<IUsbInterface> g_usbInterface = nullptr;

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdInterfaceTest::SetUpTestCase(void)
{
    g_usbInterface = IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->SetPortRole(1, 1, 1);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdInterfaceTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }

    subscriber_ = new UsbSubscriberTest();
    if (g_usbInterface->BindUsbdSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }

    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};

    ret = g_usbInterface->OpenDevice(dev_);
    ASSERT_EQ(0, ret);
    HDF_LOGI("UsbdInterfaceTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ret = g_usbInterface->ClaimInterface(dev_, 1, 1);
    ASSERT_EQ(0, ret);
}

void UsbdInterfaceTest::TearDownTestCase(void)
{
    g_usbInterface->UnbindUsbdSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdInterfaceTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetInterface001
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface001, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_0;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetInterface002
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface002, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_0;
    struct UsbDev dev = dev_;
    ;
    dev.busNum = BUS_NUM_INVALID;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface003
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface003, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    dev.devAddr = DEV_ADDR_INVALID;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface004
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface004, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    uint8_t altIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface005
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface005, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_0;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface006
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface006, TestSize.Level1)
{
    int32_t interfaceId = INTERFACEID_INVALID;
    uint8_t altIndex = INDEX_1;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface007
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface007, TestSize.Level1)
{
    int32_t interfaceId = INTERFACEID_INVALID;
    uint8_t altIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    dev.devAddr = DEV_ADDR_INVALID;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface008
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceTest, UsbdSetInterface008, TestSize.Level1)
{
    uint8_t altIndex = INDEX_INVALID;
    int32_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    auto ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdInterfaceTest::UsbdSetInterface008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}
} // namespace