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
#include "usbd_device_authorize_test.h"

#include <iostream>
#include <vector>

#include "hdf_log.h"
#include "V2_0/iusb_host_interface.h"
#include "V2_0/iusb_device_interface.h"
#include "V2_0/usb_types.h"
#include "usbd_type.h"


using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V2_0;

namespace OHOS {
namespace USB {
namespace UsbDeviceAuthorize {
const uint8_t BUS_NUM_INVALID = 255;
cosnt uint8_t DEV_ADDR_INVALID = 255;
UsbDev dev_ = {0, 0};
sptr<OHOS::USB::UsbSubscriberTest> UsbdDeviceAuthorizeTest::subscriber_ = nullptr;
sptr<HDI::Usb::V2_0::IUsbHostInterface> g_usbHostInterface = nullptr;
sptr<HDI::Usb::V2_0::IUsbDeviceInterface> g_usbDeviceInterface = nullptr;

void UsbdDeviceAuthorizeTest::SetUpTestCase(void)
{
    g_usbHostInterface = HDI::Usb::V2_0::IUsbHostInterface::Get();
    g_usbDeviceInterface = HDI::Usb::V2_0::IUsbHostInterface::Get();
    if (g_usbHostInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbHostInterface::Get() failed.", __func__);
        exit(0);
    }
    if (g_usbDeviceInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbDeviceInterface::Get() failed.", __func__);
        exit(0);
    }

    subscriber_ = new OHOS::USB::UsbSubscriberTest();
    if (g_usbHostInterface->BindUsbdHostSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }

    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        if (c == EOF) {
            HDF_LOGE("%{public}s: getchar() encountered EOF, exiting", __func__);
            break;
        }
    }
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};

    HDF_LOGI("UsbdDeviceAuthorizeTest:: %{public}s", __func__);
}

void UsbdDeviceAuthorizeTest::TearDownTestCase(void)
{
    auto ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdDeviceAuthorizeTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
}

void UsbdDeviceAuthorizeTest::SetUp(void) {}

void UsbdDeviceAuthorizeTest::TearDown(void) {}

/**
 * @tc.name: UsbdDeviceAuthorize001
 * @tc.desc: Test functions to UsbDeviceAuthorize
 * @tc.desc: int32_t UsbDeviceAuthorize(uint8_t devNum, uint8_t devAddr, bool authorized);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceAuthorizeTest, UsbdDeviceAuthorize001, TestSize.Level1)
{
    UsbDev dev = dev_;
    int32_t ret = g_usbDeviceInterface->UsbDeviceAuthorize(dev.busNum, dev.devAddr, false);
    HDF_LOGI(
        "UsbdDeviceAuthorizeTest::UsbdDeviceAuthorize001 %{public}d UsbDeviceAuthorize=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbdDeviceAuthorize002
 * @tc.desc: Test functions to UsbDeviceAuthorize
 * @tc.desc: int32_t UsbDeviceAuthorize(uint8_t devNum, uint8_t devAddr, bool authorized);
 * @tc.desc: Positive test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceAuthorizeTest, UsbdDeviceAuthorize002, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbDeviceAuthorize(dev.busNum, dev.devAddr, false);
    HDF_LOGI(
        "UsbdDeviceAuthorizeTest::UsbdDeviceAuthorize002 %{public}d UsbDeviceAuthorize=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDeviceAuthorize003
 * @tc.desc: Test functions to UsbDeviceAuthorize
 * @tc.desc: int32_t UsbDeviceAuthorize(uint8_t devNum, uint8_t devAddr, bool authorized);
 * @tc.desc: Positive test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceAuthorizeTest, UsbdDeviceAuthorize003, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.devAddr = DEV_ADDR_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbDeviceAuthorize(dev.busNum, dev.devAddr, false);
    HDF_LOGI(
        "UsbdDeviceAuthorizeTest::UsbdDeviceAuthorize003 %{public}d UsbDeviceAuthorize=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDeviceAuthorize004
 * @tc.desc: Test functions to UsbDeviceAuthorize
 * @tc.desc: int32_t UsbDeviceAuthorize(uint8_t devNum, uint8_t devAddr, bool authorized);
 * @tc.desc: Positive test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceAuthorizeTest, UsbdDeviceAuthorize004, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbDeviceAuthorize(dev.busNum, dev.devAddr, false);
    HDF_LOGI(
        "UsbdDeviceAuthorizeTest::UsbdDeviceAuthorize004 %{public}d UsbDeviceAuthorize=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDeviceAuthorize005
 * @tc.desc: Test functions to UsbDeviceAuthorize
 * @tc.desc: int32_t UsbDeviceAuthorize(uint8_t devNum, uint8_t devAddr, bool authorized);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceAuthorizeTest, UsbdDeviceAuthorize005, TestSize.Level1)
{
    UsbDev dev = dev_;
    int32_t ret = g_usbDeviceInterface->UsbDeviceAuthorize(dev.busNum, dev.devAddr, true);
    HDF_LOGI(
        "UsbdDeviceAuthorizeTest::UsbdDeviceAuthorize005 %{public}d UsbDeviceAuthorize=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

} // UsbDeviceAuthorize
} // USB
} // OHOS