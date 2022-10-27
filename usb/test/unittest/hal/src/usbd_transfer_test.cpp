/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#include "securec.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

const int SLEEP_TIME = 3;
const uint8_t BUS_NUM_99 = 99;
const uint8_t BUS_NUM_222 = 222;
const uint8_t BUS_NUM_255 = 255;
const uint8_t DEV_ADDR_99 = 99;
const uint8_t DEV_ADDR_244 = 244;
const uint8_t DEV_ADDR_255 = 255;
const uint32_t LENGTH_NUM_255 = 255;
const uint8_t INTERFACEID_1 = 1;
const uint8_t PIPE_ENDPOINTID_244 = 244;
const uint8_t PIPE_ENDPOINTID_255 = 255;
const uint8_t PIPE_INTERFACEID_244 = 244;
const uint8_t PIPE_INTERFACEID_255 = 255;
const uint8_t POINTID_1 = 1;
const uint8_t POINTID_99 = 99;
const uint8_t POINTID_129 = 130;
const uint8_t POINTID_BULK_IN = 0x82;
const uint8_t POINTID_BULK_OUT = 0x01;
const int32_t ASHMEM_MAX_SIZE = 1024;
UsbDev UsbdTransferTest::dev_ = {0, 0};

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

namespace {
sptr<IUsbInterface> g_usbInterface = nullptr;

int32_t InitAshmemOne(sptr<Ashmem> &asmptr, int32_t asmSize, uint8_t rflg)
{
    asmptr = Ashmem::CreateAshmem("ttashmem000", asmSize);
    if (asmptr == nullptr) {
        HDF_LOGE("InitAshmemOne CreateAshmem failed\n");
        return HDF_FAILURE;
    }

    asmptr->MapReadAndWriteAshmem();

    if (rflg == 0) {
        uint8_t tdata[ASHMEM_MAX_SIZE];
        int32_t offset = 0;
        int32_t tlen = 0;

        int32_t retSafe = memset_s(tdata, sizeof(tdata), 'Y', ASHMEM_MAX_SIZE);
        if (retSafe != EOK) {
            HDF_LOGE("InitAshmemOne memset_s failed\n");
            return HDF_FAILURE;
        }
        while (offset < asmSize) {
            tlen = (asmSize - offset) < ASHMEM_MAX_SIZE ? (asmSize - offset) : ASHMEM_MAX_SIZE;
            asmptr->WriteToAshmem(tdata, tlen, offset);
            offset += tlen;
        }
    }
    return HDF_SUCCESS;
}

void UsbdTransferTest::SetUpTestCase(void)
{
    g_usbInterface = IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->SetPortRole(1, 1, 1);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdTransferTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }

    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber failed\n", __func__);
        exit(0);
    }

    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    dev_ = {subscriber->busNum_, subscriber->devAddr_};
    ret = g_usbInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdTransferTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdTransferTest::TearDownTestCase(void)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber failed\n", __func__);
        exit(0);
    }
    dev_ = {subscriber->busNum_, subscriber->devAddr_};
    auto ret = g_usbInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdTransferTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdTransferTest::SetUp(void) {}

void UsbdTransferTest::TearDown(void) {}

/**
 * @tc.name: UsbdControlTransfer001
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 8, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer001 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransfer002
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_255, dev_.devAddr};
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 8, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer002 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer003
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_255};
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 8, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer003 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer004
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 6, 0x100, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer004 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransfer005
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_255, dev_.devAddr};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 6, 0x100, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer005 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer006
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer006, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_255};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 6, 0x100, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer006 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer007
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t intercafeidex = 0;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0X0A, 0, intercafeidex, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer007 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransfer008
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_255, dev_.devAddr};
    int32_t intercafeidex = 0;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0X0A, 0, intercafeidex, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer008 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer009
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer009, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_255};
    int32_t intercafeidex = 0;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0X0A, 0, intercafeidex, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer009 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer010
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * Positive test: parameters correctly, standard request: get status(recipient device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer010, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer010 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransfer011
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer011, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_255, dev_.devAddr};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer011 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer012
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer012, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_255};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer012 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer013
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * Positive test: parameters correctly, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer013, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer013 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransfer014
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer014, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_255, dev_.devAddr};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer014 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer015
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer015, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_255};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer015 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer016
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer016, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer016 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransfer017
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer017, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_255, dev_.devAddr};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer017 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer018
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer018, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_255};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer018 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer019
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer019, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0X0C, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer019 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdControlTransfer020
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer020, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_255, dev_.devAddr};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0X0C, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer020 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdControlTransfer021
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer021, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_255};
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0X0C, 0, 0, 1000};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer021 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_222;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_244;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint8_t buffer[100] = {0};
    uint32_t length = 100;
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint32_t length = 100;
    uint8_t buffer[100] = {};
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ01";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ02";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_244;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ03";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ04";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ05";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    dev.devAddr = DEV_ADDR_99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ06";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_99;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ07";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ08";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, -1, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: InterruptTransferRead001
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead001 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
        ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdInterruptTransferRead002
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_222;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead002 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
        ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead003
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_244;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, 1000, bufferdata);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead004
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint8_t buffer[100] = {0};
    uint32_t length = 100;
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead004 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
        ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead005
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint32_t length = 100;
    uint8_t buffer[100] = {};
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead005 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
        ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite001
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ01";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite001 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdInterruptTransferWrite002
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ02";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite002 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite003
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_244;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ03";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite003 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite004
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ04";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite004 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite005
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, endpointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ05";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite005 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite006
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    dev.devAddr = DEV_ADDR_99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ06";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite006 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite007
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, ClaimInterface failed first
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_99;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ07";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite007 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite008
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * Positive test: parameters correctly, different in timeout
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ08";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, -1, bufferdata);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite008 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d interfaceId=%{public}d", __LINE__, interfaceId);
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_222;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_244;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint8_t buffer[100] = {0};
    uint32_t length = 100;
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint32_t length = 100;
    uint8_t buffer[100] = {};
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ01";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ02";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_244;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ03";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ04";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ05";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    dev.devAddr = DEV_ADDR_99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ06";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_99;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ07";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ08";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, -1, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite001 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite002 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.devAddr = DEV_ADDR_244;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite003 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_255;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite004 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_255;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkWrite(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkWrite005 %{public}d BulkWrite=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead001 %{public}d BulkRead=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead002 %{public}d BulkRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.devAddr = DEV_ADDR_244;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead003 %{public}d BulkRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_255;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead004 %{public}d BulkRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    int32_t asmSize = LENGTH_NUM_255;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = PIPE_ENDPOINTID_255;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    ret = g_usbInterface->BulkRead(dev, pipe, ashmem);
    HDF_LOGI("UsbdTransferTest::BulkRead005 %{public}d BulkRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_OUT;
    struct UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback001 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_OUT;
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = BUS_NUM_99;
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback002 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_OUT;
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.devAddr = DEV_ADDR_244;
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback003 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: RegBulkCallback004
 * @tc.desc: Test functions to int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe,
 * const sptr<IUsbdBulkCallback> &cb)
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, RegBulkCallback004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_OUT;
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.intfId = PIPE_INTERFACEID_255;
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback004 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_BULK_OUT;
    struct UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, nullptr);
    HDF_LOGI("UsbdTransferTest::RegBulkCallback005 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    struct UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback001 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback001 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
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
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    struct UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback002 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    dev.devAddr = DEV_ADDR_244;
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback002 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
    dev = dev_;
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback002 %{public}d again UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: UnRegBulkCallback003
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnRegBulkCallback003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    struct UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback003 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    pipe.intfId = PIPE_INTERFACEID_244;
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback003 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
    pipe = {interfaceId, pointid};
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback003 %{public}d again UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: UnRegBulkCallback004
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Positive test: call again
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnRegBulkCallback004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    struct UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback004 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback004 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback004 %{public}d again UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: UnRegBulkCallback005
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Positive test: no register
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnRegBulkCallback005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    struct UsbPipe pipe = {interfaceId, pointid};
    auto ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback005 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: UnbindUsbdSubscriber001
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber001, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber001 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber001 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber002
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Negative test: no bind first
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber002, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber002 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber003
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: no bind first, unbind failed; then bind, unbind success
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber003, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber003 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
    ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber003 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber003 %{public}d again UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber004
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Negative test: call twice
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber004, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber004 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber004 %{public}d first UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber004 %{public}d again UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UnbindUsbdSubscriber005
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: test repeatedly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UnbindUsbdSubscriber005, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d first BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d first UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI(
        "UsbdTransferTest::UnbindUsbdSubscriber005 %{public}d again UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber001
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber001, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber001 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber002
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind different
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber002, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber002 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbSubscriberTest> subscriber2 = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    ret = g_usbInterface->BindUsbdSubscriber(subscriber2);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber002 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber003
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind same
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber003, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber003 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber003 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber004
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind and unbind, then bind another
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber004, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber004 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::bindUsbdSubscriber005 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    sptr<UsbSubscriberTest> subscriber2 = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    ret = g_usbInterface->BindUsbdSubscriber(subscriber2);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber004 again %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BindUsbdSubscriber005
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: bind again after unbind
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, BindUsbdSubscriber005, TestSize.Level1)
{
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::BindUsbdSubscriber005 %{public}d BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::bindUsbdSubscriber005 %{public}d UnbindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    HDF_LOGI("UsbdTransferTest::bindUsbdSubscriber005 %{public}d again BindUsbdSubscriber=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}
} // namespace
