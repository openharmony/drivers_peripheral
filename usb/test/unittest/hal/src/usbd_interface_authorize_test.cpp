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
#include "usbd_interface_authorize_test.h"

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
namespace UsbInterfaceAuthorize {
const uint8_t BUS_NUM_INVALID = 255;
cosnt uint8_t DEV_ADDR_INVALID = 255;
cosnt uint8_t CONFIG_ID_OK = 1;
cosnt uint8_t CONFIG_ID_INVALID = 255;
cosnt uint8_t INTERFACEID_OK_NEW = 0;
cosnt uint8_t INTERFACEID_INVALID = 255;
uint8_t g_configId = CONFIG_ID_OK;
uint8_t g_interfaceId = INTERFACEID_OK_NEW;
UsbDev dev_ = {0, 0};
sptr<OHOS::USB::UsbSubscriberTest> UsbdInterfaceAuthorizeTest::subscriber_ = nullptr;
sptr<IUsbHostInterface> g_usbHostInterface = nullptr;
sptr<IUsbDeviceInterface> g_usbDeviceInterface = nullptr;

void UsbdInterfaceAuthorizeTest::SetUpTestCase(void)
{
    g_usbHostInterface = IUsbHostInterface::Get(true);
    g_usbDeviceInterface = IUsbHostInterface::Get();
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

    HDF_LOGI("UsbdInterfaceAuthorizeTest:: %{public}s", __func__);
}

void UsbdInterfaceAuthorizeTest::TearDownTestCase(void)
{
    auto ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdInterfaceAuthorizeTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
}

void UsbdInterfaceAuthorizeTest::SetUp(void) {}

void UsbdInterfaceAuthorizeTest::TearDown(void) {}

/**
 * @tc.name: UsbdInterfaceAuthorize001
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Positive test: parameters correctly, authorized = false
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize001, TestSize.Level1)
{
    UsbDev dev = dev_;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_OK_NEW;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize001 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize002
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize002, TestSize.Level1)
{
    UsbDev dev = dev_;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_OK_NEW;
    dev.busNum = BUS_NUM_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize002 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize003
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize003, TestSize.Level1)
{
    UsbDev dev = dev_;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_OK_NEW;
    dev.devAddr = DEV_ADDR_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize003 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize004
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize004, TestSize.Level1)
{
    UsbDev dev = dev_;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_OK_NEW;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize004 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize005
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize005, TestSize.Level1)
{
    UsbDev dev = dev_;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize005 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize006
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize006, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_OK_NEW;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize006 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize007
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize007, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_OK_NEW;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize007 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize008
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize008, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize008 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize009
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, devAddr && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize009, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.devAddr = DEV_ADDR_INVALID;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_OK_NEW;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize009 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize010
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize010, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.devAddr = DEV_ADDR_INVALID;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize010 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize011
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, configId && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize011, TestSize.Level1)
{
    UsbDev dev = dev_;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize011 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize012
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize012, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_OK_NEW;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize012 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize013
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize013, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize013 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize014
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum && configId && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize014, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize014 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize015
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, devAddr && configId && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize015, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.devAddr = DEV_ADDR_INVALID;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize015 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize016
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && configId && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize016, TestSize.Level1)
{
    UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    g_configId = CONFIG_ID_INVALID;
    g_interfaceId = INTERFACEID_INVALID;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, false);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize016 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbdInterfaceAuthorize017
 * @tc.desc: Test functions to UsbInterfaceAuthorize
 * @tc.desc: int32_t UsbInterfaceAuthorize(const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Negative test: parameters correctly, authorized = true
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterfaceAuthorizeTest, UsbdInterfaceAuthorize017, TestSize.Level1)
{
    UsbDev dev = dev_;
    g_configId = CONFIG_ID_OK;
    g_interfaceId = INTERFACEID_OK_NEW;
    int32_t ret = g_usbDeviceInterface->UsbInterfaceAuthorize(dev, g_configId, g_interfaceId, true);
    HDF_LOGI(
        "UsbdInterfaceAuthorizeTest::UsbdInterfaceAuthorize017 %{public}d UsbInterfaceAuthorize=%{public}d",
        __LINE__, ret);
    EXPECT_NE(0, ret);
}

} // UsbInterfaceAuthorize
} // USB
} // OHOS