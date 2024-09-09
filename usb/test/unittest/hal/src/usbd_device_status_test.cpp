/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "usbd_device_status_test.h"

#include <iostream>
#include <vector>

#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#include "usbd_type.h"
#include "v1_1/iusb_interface.h"

const int SLEEP_TIME = 3;
const uint8_t BUS_NUM_INVALID = 255;
const uint8_t DEV_ADDR_INVALID = 255;
const uint8_t INTERFACEID_OK = 1;
const uint8_t INTERFACEID_OK_NEW = 0;
const uint8_t INTERFACEID_INVALID = 255;
const uint8_t POINTID_DIR_IN = USB_ENDPOINT_DIR_IN | 2;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_1;
namespace OHOS {
namespace USB {
UsbDev UsbdDeviceStatusTest::dev_ = {0, 0};
sptr<UsbSubscriberTest> UsbdDeviceStatusTest::subscriber_ = nullptr;
sptr<OHOS::HDI::Usb::V1_1::IUsbInterface> g_usbInterface = nullptr;

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdDeviceStatusTest::SetUpTestCase(void)
{
    g_usbInterface = OHOS::HDI::Usb::V1_1::IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->SetPortRole(1, 1, 1);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdDeviceStatusTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
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

    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};

    ret = g_usbInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdDeviceStatusTest::%{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdDeviceStatusTest::TearDownTestCase(void)
{
    g_usbInterface->UnbindUsbdSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdDeviceStatusTest::%{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdDeviceStatusTest::SetUp(void) {}

void UsbdDeviceStatusTest::TearDown(void) {}

/**
 * @tc.name: UsbdGetDeviceSpeed001
 * @tc.desc: Test functions to GetDeviceSpeed
 * @tc.desc: int32_t  GetDeviceSpeed(const UsbDev &dev, uint8_t interfaceId, uint8_t speed);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetDeviceSpeed001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t speed = 0;
    ret = g_usbInterface->GetDeviceSpeed(dev, speed);
    HDF_LOGI("UsbdGetDeviceSpeed001 %{public}d GetDeviceSpeed=%{public}d, speed=%{public}d", __LINE__, ret, speed);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdGetDeviceSpeed002
 * @tc.desc: Test functions to GetDeviceSpeed
 * @tc.desc: int32_t  GetDeviceSpeed(const UsbDev &dev, uint8_t interfaceId, uint8_t speed);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetDeviceSpeed002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    uint8_t speed = 0;
    auto ret = g_usbInterface->GetDeviceSpeed(dev, speed);
    HDF_LOGI("UsbdGetDeviceSpeed002 %{public}d ret=%{public}d, speed=%{public}d", __LINE__, ret, speed);
    ASSERT_NE(ret, 0);
}


/**
 * @tc.name: UsbdGetDeviceSpeed003
 * @tc.desc: Test functions to GetDeviceSpeed
 * @tc.desc: int32_t  GetDeviceSpeed(const UsbDev &dev, uint8_t interfaceId, uint8_t speed);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetDeviceSpeed003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    uint8_t speed = 0;
    auto ret = g_usbInterface->GetDeviceSpeed(dev, speed);
    HDF_LOGI("UsbdGetDeviceSpeed003 %{public}d, ret=%{public}d, speed=%{public}d", __LINE__, ret, speed);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetDeviceSpeed004
 * @tc.desc: Test functions to GetDeviceSpeed
 * @tc.desc: int32_t  GetDeviceSpeed(const UsbDev &dev, uint8_t interfaceId, uint8_t speed);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetDeviceSpeed004, TestSize.Level1)
{
    uint8_t speed = 0;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->GetDeviceSpeed(dev, speed);
    HDF_LOGI("UsbdGetDeviceSpeed004 %{public}d, ret=%{public}d, speed=%{public}d", __LINE__, ret, speed);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus001
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus001, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK_NEW;
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    bool unactived = 1;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdDeviceStatusTest::UsbdGetInterfaceActiveStatus %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    for (; interfaceId < INTERFACEID_INVALID; interfaceId++) {
        ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
        if (ret == 0) {
            break;
        }
    }
    HDF_LOGI("UsbdGetInterfaceActiveStatus001 %{public}d GetInterfaceActiveStatus=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus002
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus002, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    bool unactived = 1;
    auto ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
    HDF_LOGI("UsbdGetInterfaceActiveStatus002 %{public}d ret=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus003
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus003, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    bool unactived = 1;
    auto ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
    HDF_LOGI("UsbdGetInterfaceActiveStatus003 %{public}d, ret=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus004
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Negative test: parameters exception, interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus004, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    interfaceId = INTERFACEID_INVALID;
    bool unactived = 1;
    auto ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
    HDF_LOGI("UsbdGetInterfaceActiveStatus004 %{public}d, ret=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus005
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus005, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    bool unactived = 1;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
    HDF_LOGI("UsbdGetInterfaceActiveStatus005 %{public}d, ret=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus006
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus006, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    bool unactived = 1;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
    HDF_LOGI("UsbdGetInterfaceActiveStatus006 %{public}d, ret=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus007
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus007, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    bool unactived = 1;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
    HDF_LOGI("UsbdGetInterfaceActiveStatus007 %{public}d, ret=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetInterfaceActiveStatus008
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t  GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool unactived);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdGetInterfaceActiveStatus008, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    bool unactived = 1;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->GetInterfaceActiveStatus(dev, interfaceId, unactived);
    HDF_LOGI("UsbdGetInterfaceActiveStatus008 %{public}d, ret=%{public}d, unactived=%{public}d",
        __LINE__, ret, unactived);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClearHalt001
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt001 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdClearHalt002
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt002 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UsbdClearHalt003
 * @tc.desc: Test functions to GetInterfaceActiveStatus
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt003 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UsbdClearHalt004
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_INVALID;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt004 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UsbdClearHalt005
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt005 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UsbdClearHalt006
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_INVALID;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt006 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UsbdClearHalt007
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_INVALID;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt005 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UsbdClearHalt008
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdDeviceStatusTest, UsbdClearHalt008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t ret = -1;
    uint8_t interfaceId = INTERFACEID_INVALID;
    uint8_t pointId = POINTID_DIR_IN;
    ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdRequestTest::UsbdClearHalt008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    struct UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->ClearHalt(dev, pipe);
    HDF_LOGI("UsbdClearHalt008 %{public}d ClearHalt=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}
} // USB
} // OHOS
