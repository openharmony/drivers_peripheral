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

#include "usbd_interruptTransfer_test.h"

#include <iostream>
#include <vector>

#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#include "usb_ddk.h"
#include "usb_ddk_interface.h"
#include "securec.h"
#include "usbd_type.h"
#include "v1_2/iusb_interface.h"
#include "v1_2/usb_types.h"

const int SLEEP_TIME = 3;
const uint8_t BUS_NUM_INVALID = 255;
const uint8_t DEV_ADDR_INVALID = 255;
const uint32_t MAX_BUFFER_LENGTH = 255;
const uint8_t INTERFACEID_OK = 1;
const uint8_t INTERFACEID_INTERRUPT = 0;
const uint8_t PIPE_ENDPOINTID_INVALID = 244;
const uint8_t PIPE_INTERFACEID_INVALID = 244;
const uint8_t POINTID_INTERRUPT_IN = 129;
const int32_t DEFAULT_PORT_ID = 1;
const int32_t DEFAULT_ROLE_HOST = 1;
// data interface have 2 point : 1->bulk_out 2->bulk_in
static const uint8_t POINTID_BULK_IN = USB_ENDPOINT_DIR_IN | 2;
static const uint8_t POINTID_BULK_OUT = USB_ENDPOINT_DIR_OUT | 1;
const int32_t TRANSFER_TIME_OUT = 1000;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;
using namespace OHOS::HDI::Usb::V1_2;

namespace OHOS::USB::UsbdInterruptTransfer {
UsbDev UsbdInterruptTransferTest::dev_ = {0, 0};
sptr<UsbSubscriberTest> UsbdInterruptTransferTest::subscriber_ = nullptr;
sptr<OHOS::HDI::Usb::V1_2::IUsbInterface> g_usbInterface = nullptr;

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdInterruptTransferTest::SetUpTestCase(void)
{
    g_usbInterface = OHOS::HDI::Usb::V1_2::IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }

    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_HOST, DEFAULT_ROLE_HOST);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdInterruptTransferTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }

    subscriber_ = new UsbSubscriberTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    if (g_usbInterface->BindUsbdSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }

    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);

    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    ret = g_usbInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdInterruptTransferTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdInterruptTransferTest::TearDownTestCase(void)
{
    g_usbInterface->UnbindUsbdSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdInterruptTransferTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdInterruptTransferTest::SetUp(void) {}

void UsbdInterruptTransferTest::TearDown(void) {}

/**
 * @tc.name: InterruptTransferRead001
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_INTERRUPT;
    uint8_t pointid = POINTID_INTERRUPT_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead001 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead001 %{public}d InterruptTransferRead=%{public}d",
        __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdInterruptTransferRead002
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead002 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead002 %{public}d InterruptTransferRead=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead003
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead003 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead004
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead004 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead004 %{public}d InterruptTransferRead=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead005
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead005 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferRead005 %{public}d InterruptTransferRead=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite002
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite002 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '2'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite002 %{public}d InterruptTransferWrite=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite003
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite003 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '3'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite003 %{public}d InterruptTransferWrite=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite004
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite004 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '4'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI(
        "UsbdInterruptTransferTest::UsbdInterruptTransferWrite004 %{public}d InterruptTransferWrite=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite005
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite005 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '5'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite005 %{public}d InterruptTransferWrite=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite006
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite006 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '6'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite006 %{public}d InterruptTransferWrite=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite007
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, ClaimInterface failed first
 * @tc.type: FUNC
 */
HWTEST_F(UsbdInterruptTransferTest, UsbdInterruptTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = PIPE_ENDPOINTID_INVALID;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite007 %{public}d ClaimInterface=%{public}d",
        __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '7'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdInterruptTransferTest::UsbdInterruptTransferWrite007 %{public}d InterruptTransferWrite=%{public}d",
        __LINE__, ret);
    EXPECT_NE(ret, 0);
}
} // namespace
