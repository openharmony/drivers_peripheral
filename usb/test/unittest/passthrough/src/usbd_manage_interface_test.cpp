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

#include "usbd_manage_interface_test.h"

#include <iostream>
#include <vector>

#include "UsbSubTest.h"
#include "hdf_log.h"
#include "usbd_type.h"
#include "usbd_wrapper.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/iusb_port_interface.h"

const int SLEEP_TIME = 3;
const uint8_t BUS_NUM_INVALID = 255;
const uint8_t DEV_ADDR_INVALID = 255;
const uint8_t INTERFACEID_OK = 1;
const uint8_t INTERFACEID_OK_NEW = 0;
const uint8_t INTERFACEID_INVALID = 255;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V2_0;
namespace OHOS {
namespace USB {
namespace ManageInterface {
UsbDev UsbdManageInterfaceTest::dev_ = {0, 0};
sptr<UsbSubTest> UsbdManageInterfaceTest::subscriber_ = nullptr;
sptr<IUsbHostInterface> g_usbHostInterface = nullptr;
sptr<IUsbPortInterface> g_usbPortInterface = nullptr;

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdManageInterfaceTest::SetUpTestCase(void)
{
    g_usbHostInterface = IUsbHostInterface::Get(true);
    g_usbPortInterface = IUsbPortInterface::Get();
    if (g_usbHostInterface == nullptr || g_usbPortInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    auto ret = g_usbPortInterface->SetPortRole(1, 1, 1);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdManageInterfaceTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
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

    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};

    ret = g_usbHostInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdManageInterfaceTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdManageInterfaceTest::TearDownTestCase(void)
{
    g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbHostInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdManageInterfaceTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdManageInterfaceTest::SetUp(void) {}

void UsbdManageInterfaceTest::TearDown(void) {}

/**
 * @tc.name: UsbdManageInterface001
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface001, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK_NEW;
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    for (; interfaceId < INTERFACEID_INVALID; interfaceId++) {
        ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
        if (ret == 0) {
            break;
        }
    }
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface001 %{public}d ManageInterface=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdManageInterface002
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface002, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    auto ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface002 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdManageInterface003
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface003, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface003 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdManageInterface004
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Negative test: parameters exception, interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface004, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    interfaceId = INTERFACEID_INVALID;
    auto ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface004 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdManageInterface005
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface005, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface005 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdManageInterface006
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface006, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface006 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdManageInterface007
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface007, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface007 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdManageInterface008
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface008, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbHostInterface->ManageInterface(dev, interfaceId, true);
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface008 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdManageInterface009
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t  ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdManageInterfaceTest, UsbdManageInterface009, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK_NEW;
    struct UsbDev dev = dev_;
        int32_t ret = -1;
    for (; interfaceId < INTERFACEID_INVALID; interfaceId++) {
        ret = g_usbHostInterface->ManageInterface(dev, interfaceId, false);
        if (ret == 0) {
            break;
        }
    }
    HDF_LOGI("UsbdManageInterfaceTest::UsbdManageInterface009 %{public}d ManageInterface=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}
} // ManageInterface
} // USB
} // OHOS
