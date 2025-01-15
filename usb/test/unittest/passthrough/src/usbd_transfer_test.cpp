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

#include "usbd_transfer_test.h"

#include <iostream>
#include <vector>

#include "UsbSubTest.h"
#include "hdf_log.h"
#include "usb_ddk.h"
#include "usb_ddk_interface.h"
#include "securec.h"
#include "usbd_type.h"
#include "usbd_wrapper.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/iusb_port_interface.h"
#include "v2_0/usb_types.h"

const int SLEEP_TIME = 3;
const uint8_t BUS_NUM_INVALID = 255;
const uint8_t DEV_ADDR_INVALID = 255;
const uint32_t MAX_BUFFER_LENGTH = 255;
const uint8_t INTERFACEID_OK = 1;
const uint8_t PIPE_ENDPOINTID_INVALID = 244;
const uint8_t PIPE_INTERFACEID_INVALID = 244;
// data interface have 2 point : 1->bulk_out 2->bulk_in
static const uint8_t POINTID_BULK_IN = USB_ENDPOINT_DIR_IN | 2;
static const uint8_t POINTID_BULK_OUT = USB_ENDPOINT_DIR_OUT | 1;
const int32_t ASHMEM_MAX_SIZE = 1024;
const uint8_t SAMPLE_DATA_1 = 1;
static const uint8_t SAMPLE_DATA_2 = 2;
static const uint8_t SAMPLE_DATA_3 = 3;
const int32_t TRANSFER_TIME_OUT = 1000;
const int32_t CTL_VALUE = 0x100;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V2_0;

UsbDev UsbdTransferTest::dev_ = {0, 0};
sptr<UsbSubTest> UsbdTransferTest::subscriber_ = nullptr;
namespace {
sptr<OHOS::HDI::Usb::V2_0::IUsbHostInterface> g_usbHostInterface = nullptr;
sptr<OHOS::HDI::Usb::V2_0::IUsbPortInterface> g_usbPortInterface = nullptr;

int32_t InitAshmemOne(sptr<Ashmem> &asmptr, int32_t asmSize, uint8_t rflg)
{
    asmptr = Ashmem::CreateAshmem("ttashmem000", asmSize);
    if (asmptr == nullptr) {
        HDF_LOGE("InitAshmemOne CreateAshmem failed");
        return HDF_FAILURE;
    }

    asmptr->MapReadAndWriteAshmem();

    if (rflg == 0) {
        uint8_t tdata[MAX_BUFFER_LENGTH];
        int32_t offset = 0;
        int32_t tlen = 0;

        int32_t retSafe = memset_s(tdata, sizeof(tdata), 'Y', MAX_BUFFER_LENGTH);
        if (retSafe != EOK) {
            HDF_LOGE("InitAshmemOne memset_s failed");
            return HDF_FAILURE;
        }
        while (offset < asmSize) {
            tlen = (asmSize - offset) < MAX_BUFFER_LENGTH ? (asmSize - offset) : MAX_BUFFER_LENGTH;
            asmptr->WriteToAshmem(tdata, tlen, offset);
            offset += tlen;
        }
    }
    return HDF_SUCCESS;
}

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdTransferTest::SetUpTestCase(void)
{
    g_usbHostInterface = OHOS::HDI::Usb::V2_0::IUsbHostInterface::Get(true);
    g_usbPortInterface = OHOS::HDI::Usb::V2_0::IUsbPortInterface::Get();
    if (g_usbHostInterface == nullptr || g_usbPortInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    const int32_t DEFAULT_PORT_ID = 1;
    const int32_t DEFAULT_ROLE_HOST = 1;
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_HOST, DEFAULT_ROLE_HOST);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdTransferTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }

    subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    if (g_usbHostInterface->BindUsbdHostSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }

    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    ret = g_usbHostInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdTransferTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdTransferTest::TearDownTestCase(void)
{
    HDF_LOGE("%{public}s:hyb TearDownTestCase in.", __func__);
    g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbHostInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdTransferTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdTransferTest::SetUp(void) {}

void UsbdTransferTest::TearDown(void) {}

/**
 * @tc.name: UsbdControlTransferRead001
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead001 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferRead002
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    printf("ret = %d", ret);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead002 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead003
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead003 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead004
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead004 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferRead005
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead005 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead006
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead006, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead006 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead007
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead007 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferRead008
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead008 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead009
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead009, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead009 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead010
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(recipient device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead010, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead010 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferRead011
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead011, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead011 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead012
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead012, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead012 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead013
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead013, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead013 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferRead014
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead014, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead014 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead015
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead015, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead015 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead016
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead016, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead016 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferRead017
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead017, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead017 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead018
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead018, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead018 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead019
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead019, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, USB_DDK_REQ_SYNCH_FRAME,
        0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead019 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferRead020
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead020, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, USB_DDK_REQ_SYNCH_FRAME,
        0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead020 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferRead021
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferRead021, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, USB_DDK_REQ_SYNCH_FRAME,
        0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferRead(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferRead021 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite001
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT,
        USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    printf("devNum = %d, devAddr = %d", dev.busNum, dev.devAddr);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite001 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferWrite002
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite002 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite003
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite003 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite004
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT,
        USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite004 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferWrite005
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite005 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite006
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite006 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite007
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {0, USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite007 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferWrite008
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {0, USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite008 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite009
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite009, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {0, USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite009 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite010
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite010, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT, USB_DDK_REQ_GET_DESCRIPTOR, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite010 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferWrite011
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite011, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite011 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite012
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite012, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite012 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite013
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite013, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT, USB_DDK_REQ_GET_INTERFACE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite013 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferWrite014
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite014, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite014 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite015
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite015, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite015 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite016
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite016, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT, USB_DDK_REQ_GET_CONFIGURATION, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite016 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferWrite017
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite017, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite017 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite018
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite018, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite018 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite019
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite019, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_ENDPOINT, USB_DDK_REQ_SYNCH_FRAME,
        0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite019 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferWrite020
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite020, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_ENDPOINT, USB_DDK_REQ_SYNCH_FRAME,
        0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite020 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferWrite021
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferWrite021, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_ENDPOINT, USB_DDK_REQ_SYNCH_FRAME,
        0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferWrite(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferWrite021 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength001
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {
        USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_CONFIGURATION, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength001 ret=%{public}d", ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength002
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {
        USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_CONFIGURATION, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength002 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength003
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {
        USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_CONFIGURATION, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength003 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength004
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {
        USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength004 ret=%{public}d", ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength005
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {
        USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength005 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength006
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength006, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {
        USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength006 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength007
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength007 ret=%{public}d", ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength008
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength008 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength009
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength009, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    int32_t intercafeidex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, intercafeidex, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength009 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength010
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(recipient device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength010, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN, 0, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength010 ret=%{public}d", ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength011
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength011, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN, 0, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength011 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength012
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength012, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN, 0, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength012 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength013
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength013, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength013 ret=%{public}d", ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength014
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength014, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength014 ret%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength015
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength015, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE, 0, 0, 0,
        0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength015 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength016
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength016, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength016 ret=%{public}d", ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength017
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength017, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength017 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength018
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength018, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT, 0, 0, 0,
        0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength018 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength019
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength019, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_SYNCH_FRAME, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength019 ret=%{public}d", ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength020
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength020, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_SYNCH_FRAME, 0, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength020 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransferReadwithLength021
 * @tc.desc: Test functions to ControlTransferReadwithLength
 * @tc.desc: int32_t ControlTransferReadwithLength(const UsbDev &dev, UsbCtrlTransferParams &ctrl,
 * @tc.desc: std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransferReadwithLength021, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransferParams ctrlparmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_SYNCH_FRAME, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbHostInterface->ControlTransferReadwithLength(dev, ctrlparmas, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransferReadwithLength021 ret=%{public}d", ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferRead001
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdBulkTransferRead002
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferRead003
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferRead004
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferRead005
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferReadwithLength001
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferReadwithLength001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferReadwithLength(dev, pipe, TRANSFER_TIME_OUT, bufferData.size(), bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength001 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdBulkTransferReadwithLength002
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferReadwithLength002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferReadwithLength(dev, pipe, TRANSFER_TIME_OUT, bufferData.size(), bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength002 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferReadwithLength003
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferReadwithLength003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferReadwithLength(dev, pipe, TRANSFER_TIME_OUT, bufferData.size(), bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength003 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferReadwithLength004
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferReadwithLength004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferReadwithLength(dev, pipe, TRANSFER_TIME_OUT, bufferData.size(), bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength004 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferReadwithLength005
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferReadwithLength005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->BulkTransferReadwithLength(dev, pipe, TRANSFER_TIME_OUT, bufferData.size(), bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferReadwithLength005 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite001
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '1'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdBulkTransferWrite002
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '2'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite003
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '3'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite004
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '4'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite005
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '5'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite006
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '6'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite007
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, ClaimInterface failed first
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = PIPE_ENDPOINTID_INVALID;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '7'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite008
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, different in timeout
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '8'};
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, -1, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdIsoTransferRead001
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdIsoTransferRead002
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d interfaceId=%{public}d", __LINE__, interfaceId);
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferRead003
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferRead004
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferRead005
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbHostInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite001
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '1'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdIsoTransferWrite002
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '2'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite003
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '3'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite004
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '4'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite005
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '5'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite006
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '6'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite007
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error, ClaimInterface failed first
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = PIPE_ENDPOINTID_INVALID;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '7'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite008
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, different in timeout
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '8'};
    ret = g_usbHostInterface->IsoTransferWrite(dev, pipe, -1, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: BulkWrite001
 * @tc.desc: Test functions to int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkWrite001, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = ASHMEM_MAX_SIZE;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};

    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);

    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);

    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite001 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: BulkWrite002
 * @tc.desc: Test functions to int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkWrite002, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);

    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);

    dev.busNum = BUS_NUM_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite002 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkWrite003
 * @tc.desc: Test functions to int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkWrite003, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    dev.devAddr = DEV_ADDR_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite003 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkWrite004
 * @tc.desc: Test functions to int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkWrite004, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite004 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkWrite005
 * @tc.desc: Test functions to int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkWrite005, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite005 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkRead001
 * @tc.desc: Test functions to int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkRead001, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead001 %{public}d BulkRead=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: BulkRead002
 * @tc.desc: Test functions to int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkRead002, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    dev.busNum = BUS_NUM_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead002 %{public}d BulkRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkRead003
 * @tc.desc: Test functions to int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkRead003, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    dev.devAddr = DEV_ADDR_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead003 %{public}d BulkRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkRead004
 * @tc.desc: Test functions to int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkRead004, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead004 %{public}d BulkRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: BulkRead005
 * @tc.desc: Test functions to int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BulkRead005, TestSize.Level1)
{
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    struct OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbHostInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead005 %{public}d BulkRead=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    pipe.endpointId = POINTID_BULK_OUT;
}

/**
 * @tc.name: RegBulkCallback001
 * @tc.desc: Test functions to RegBulkCallback
 * @tc.desc: int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe, const sptr<IUsbdBulkCallback> &cb)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, RegBulkCallback001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback001 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: RegBulkCallback002
 * @tc.desc: Test functions to RegBulkCallback
 * @tc.desc: int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe, const sptr<IUsbdBulkCallback> &cb)
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, RegBulkCallback002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_INVALID;
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback002 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: RegBulkCallback003
 * @tc.desc: Test functions to int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe,
 * const sptr<IUsbdBulkCallback> &cb)
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, RegBulkCallback003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    dev.devAddr = DEV_ADDR_INVALID;
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback003 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: RegBulkCallback005
 * @tc.desc: Test functions to int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe,
 * const sptr<IUsbdBulkCallback> &cb)
 * @tc.desc: Negative test: parameters exception, cb error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, RegBulkCallback005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->RegBulkCallback(dev, pipe, nullptr);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback005 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UnRegBulkCallback001
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnRegBulkCallback001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback001 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback001 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UnRegBulkCallback002
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnRegBulkCallback002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback002 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback002 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    dev = dev_;
    ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback002 %{public}d again UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UnRegBulkCallback003
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Positive test: call again
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnRegBulkCallback003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback003 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback003 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UnRegBulkCallback004
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Positive test: no register
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnRegBulkCallback004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V2_0::UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbHostInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback004 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UnbindUsbdSubscriber001
 * @tc.desc: Test functions to int32_t UnbindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber001, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber001 %{public}d first Subscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber001 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber002
 * @tc.desc: Test functions to int32_t UnbindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Negative test: no bind first
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber002, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber002 %{public}d UnbindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber003
 * @tc.desc: Test functions to int32_t UnbindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: no bind first, unbind failed; then bind, unbind success
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber003, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber003 %{public}d UnbindUsbdHostSub=%{public}d", __LINE__, ret);
    EXPECT_NE(0, ret);
    ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber003 %{public}d first BindUsbdHostSub=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber003 %{public}d again UnbindUsbdHostSub=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber004
 * @tc.desc: Test functions to int32_t UnbindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Negative test: call twice
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber004, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber004 %{public}d first BindUsbdHostSub=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber004 %{public}d first UnbindUsbdHostSub=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber004 %{public}d again UnbindUsbdHostSub=%{public}d", __LINE__, ret);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber005
 * @tc.desc: Test functions to int32_t UnbindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: test repeatedly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber005, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d first BindUsbdHostSub=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d first UnbindUsbdHostSub=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d again BindUsbdHostSub=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d again UnbindUsbdHostSub=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber001
 * @tc.desc: Test functions to int32_t BindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber001, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber001 %{public}d BindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber002
 * @tc.desc: Test functions to int32_t BindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: bind different
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber002, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber002 %{public}d BindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    sptr<UsbSubTest> subscriber2 = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber2);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber002 %{public}d again BindUsbdHostSub=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber003
 * @tc.desc: Test functions to int32_t BindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: bind same
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber003, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber003 %{public}d BindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber003 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber004
 * @tc.desc: Test functions to int32_t BindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: bind and unbind, then bind another
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber004, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber004 %{public}d BindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::bindUsbdSubscriber005 %{public}d UnbindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    sptr<UsbSubTest> subscriber2 = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber2);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber004 again %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber005
 * @tc.desc: Test functions to int32_t BindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber_)
 * @tc.desc: Positive test: bind again after unbind
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber005, TestSize.Level1)
{
    sptr<UsbSubTest> subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber005 %{public}d BindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::bindUsbdSubscriber005 %{public}d UnbindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    ret = g_usbHostInterface->BindUsbdHostSubscriber(subscriber_);
    HDF_LOGI("UsbdTransferTest::Subscriber005 %{public}d again BindUsbdHostSubscriber=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}
} // namespace
