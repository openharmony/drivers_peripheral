/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <climits>
#include <iostream>
#include <vector>

#include "mock_linux_adapter.h"
#include "usb_impl.h"
#include "usbd_dispatcher.h"
#include "UsbSubscriberTest.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

using ::testing::Exactly;
using ::testing::Return;

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

constexpr uint8_t BUS_NUM_INVALID = 255;
constexpr uint8_t DEV_ADDR_INVALID = 255;
constexpr uint8_t BUS_NUM_OK = 6;
constexpr uint8_t DEV_ADDR_OK = 2;

namespace {
class UsbdDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static UsbDev dev_;
};
sptr<IUsbInterface> g_usbInterfaceProxy = nullptr;
sptr<IUsbInterface> g_usbInterface = nullptr;
UsbDev UsbdDeviceTest::dev_ = {0, 0};

void UsbdDeviceTest::SetUpTestCase(void)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();
    g_usbInterface = IUsbInterface::Get(true);
    ASSERT_NE(nullptr, g_usbInterface);
    sptr<UsbImpl> sp = static_cast<UsbImpl *>(g_usbInterface.GetRefPtr());
    osAdapterOps->openDevice = FuncAdapterOpenDevice;
    osAdapterOps->init = FuncAdapterInit;
    osAdapterOps->getConfiguration = FuncAdapterGetConfiguration;
    osAdapterOps->getConfigDescriptor = FuncAdapterGetConfigDescriptor;
    osAdapterOps->urbCompleteHandle = FuncAdapterUrbCompleteHandle;
    osAdapterOps->allocRequest = FuncAdapterAllocRequest;
    osAdapterOps->cancelRequest = FuncAdapterCancelRequest;
    osAdapterOps->submitRequest = FuncAdapterSubmitRequest;
    osAdapterOps->claimInterface = FuncAdapterClaimInterface;
    osAdapterOps->detachKernelDriverAndClaim = FuncAdapterClaimInterface;
    osAdapterOps->freeRequest = FuncAdapterFreeRequest;
    osAdapterOps->closeDevice = FuncAdapterCloseDevice;
    osAdapterOps->releaseInterface = FuncAdapterReleaseInterface;
    auto ret = UsbdDispatcher::UsbdDeviceCreateAndAttach(sp, BUS_NUM_OK, DEV_ADDR_OK);
    dev_ = {BUS_NUM_OK, DEV_ADDR_OK};
    ASSERT_EQ(0, ret);
    g_usbInterfaceProxy = IUsbInterface::Get();
    ASSERT_NE(nullptr, g_usbInterfaceProxy);
}

void UsbdDeviceTest::TearDownTestCase(void)
{
    g_usbInterface->CloseDevice(dev_);
    sptr<UsbImpl> sp = static_cast<UsbImpl *>(g_usbInterface.GetRefPtr());
    UsbdDispatcher::UsbdDeviceDettach(sp, BUS_NUM_OK, DEV_ADDR_OK);
}

/**
 * @tc.name: UnbindUsbdSubscriber001
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UnbindUsbdSubscriber001, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber001 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber001 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber002
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Negative test: no bind first
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UnbindUsbdSubscriber002, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber002 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber003
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: no bind first, unbind failed; then bind, unbind success
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UnbindUsbdSubscriber003, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber003 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber003 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdDeviceTest::UnbindUsbdSubscriber003 %{public}d again UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber004
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Negative test: call twice
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UnbindUsbdSubscriber004, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber004 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdDeviceTest::UnbindUsbdSubscriber004 %{public}d first UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdDeviceTest::UnbindUsbdSubscriber004 %{public}d again UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber005
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: test repeatedly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UnbindUsbdSubscriber005, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber005 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdDeviceTest::UnbindUsbdSubscriber005 %{public}d first UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::UnbindUsbdSubscriber005 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdDeviceTest::UnbindUsbdSubscriber005 %{public}d again UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber001
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, BindUsbdSubscriber001, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber001 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber002
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind different
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, BindUsbdSubscriber002, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber002 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbSubscriberTest> subscriber2 = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber2);
    ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber2);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber002 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber003
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind same
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, BindUsbdSubscriber003, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber003 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber003 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber004
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind and unbind, then bind another
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, BindUsbdSubscriber004, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber004 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::bindUsbdSubscriber005 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbSubscriberTest> subscriber2 = new UsbSubscriberTest();
    ASSERT_NE(subscriber2, subscriber);
    ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber2);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber004 again %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber005
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind again after unbind
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, BindUsbdSubscriber005, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(nullptr, subscriber);
    auto ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::BindUsbdSubscriber005 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::bindUsbdSubscriber005 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterfaceProxy->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdDeviceTest::bindUsbdSubscriber005 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDevice001
 * @tc.desc: Test functions to OpenDevice
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdOpenDevice001, TestSize.Level1)
{
    int32_t ret = g_usbInterface->OpenDevice(dev_);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDevice002
 * @tc.desc: Test functions to OpenDevice
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Negative test
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdOpenDevice002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->OpenDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDevice003
 * @tc.desc: Test functions to OpenDevice
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Negative test
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdOpenDevice003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->OpenDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDevice004
 * @tc.desc: Test functions to OpenDevice
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Negative test
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdOpenDevice004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->OpenDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDevice011
 * @tc.desc: Test functions to CloseDevice
 * @tc.desc: int32_t CloseDevice(const UsbDev &dev);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdCloseDevice001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->OpenDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->CloseDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d Close result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDevice012
 * @tc.desc: Test functions to CloseDevice
 * @tc.desc: int32_t CloseDevice(const UsbDev &dev);
 * @tc.desc: Negative test
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdCloseDevice002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->OpenDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbInterface->CloseDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d Close result=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
    dev = dev_;
    g_usbInterface->CloseDevice(dev);
}

/**
 * @tc.name: UsbdDevice013
 * @tc.desc: Test functions to CloseDevice
 * @tc.desc: int32_t CloseDevice(const UsbDev &dev);
 * @tc.desc: Negative test
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdCloseDevice003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->OpenDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->CloseDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d Close result=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
    dev = dev_;
    g_usbInterface->CloseDevice(dev);
}

/**
 * @tc.name: UsbdDevice014
 * @tc.desc: Test functions to CloseDevice
 * @tc.desc: int32_t CloseDevice(const UsbDev &dev);
 * @tc.desc: Negative test
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceTest, UsbdCloseDevice004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->OpenDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->CloseDevice(dev);
    HDF_LOGI("UsbdDeviceTest:: Line:%{public}d Close result=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
    dev = dev_;
    g_usbInterface->CloseDevice(dev);
}
} // namespace
