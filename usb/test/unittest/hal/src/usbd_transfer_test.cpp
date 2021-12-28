/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "hdf_log.h"
#include "usb_param.h"
#include "usbd_client.h"

const int SLEEP_TIME = 3;

const uint8_t BUS_NUM_1 = 1;
const uint8_t DEV_ADDR_2 = 2;

const uint8_t BUS_NUM_255 = 255;
const uint8_t DEV_ADDR_255 = 255;

const uint8_t BUS_NUM_222 = 222;
const uint8_t DEV_ADDR_222 = 222;

const uint32_t LENGTH_NUM_255 = 255;

const uint32_t TAG_LENGTH_NUM_1000 = 1000;

const int TAG_NUM_10 = 10;
const int TAG_NUM_11 = 11;

const uint8_t INTERFACEID_1 = 1;
const int32_t INT32_INTERFACEID_1 = 1;

const uint8_t POINTID_1 = 1;
const uint8_t POINTID_129 = 129;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;

void UsbdTransferTest::SetUpTestCase(void)
{
    auto ret = UsbdClient::SetPortRole(1, 1, 1);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdFunctionTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    if (ret != 0) {
        exit(0);
    }
    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    ret = UsbdClient::OpenDevice(dev);
    HDF_LOGI("UsbdTransferTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

void UsbdTransferTest::TearDownTestCase(void)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    auto ret = UsbdClient::CloseDevice(dev);
    HDF_LOGI("UsbdTransferTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

void UsbdTransferTest::SetUp(void) {}

void UsbdTransferTest::TearDown(void) {}

/**
 * @tc.name: UsbdControlTransfer001
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 8, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer001 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdControlTransfer002
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 8, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer002 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer003
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 8, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer003 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer004
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 6, 0x100, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer004 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdControlTransfer005
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 6, 0x100, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer005 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer006
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer006, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_255;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 6, 0x100, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer006 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer007
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer007, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    int32_t intercafeidex = 0;
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0X0A, 0, intercafeidex, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer007 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdControlTransfer008
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    int32_t intercafeidex = 0;
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0X0A, 0, intercafeidex, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer008 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer009
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer009, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    int32_t intercafeidex = 0;
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_255;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0X0A, 0, intercafeidex, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer009 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer010
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer010, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer010 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdControlTransfer011
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer011, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer011 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer012
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer012, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_255;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000000, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer012 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer013
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer013, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer013 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdControlTransfer014
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer014, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer014 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer015
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer015, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_255;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000001, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer015 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer016
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer016, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer016 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdControlTransfer017
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer017, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer017 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer018
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer018, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_255;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer018 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer019
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer019, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0X0C, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer019 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdControlTransfer020
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer020, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0X0C, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer020 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdControlTransfer021
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdControlTransfer021, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_255;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbCtrlTransfer ctrlparmas = {0b10000010, 0X0C, 0, 0, 1000};
    auto ret = UsbdClient::ControlTransfer(dev, ctrlparmas, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdControlTransfer021 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferRead001
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdBulkTransferRead002
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_222;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferRead003
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 244;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferRead004
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[100] = {0};
    uint32_t length = 100;
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.interfaceId = 244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferRead005
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint32_t length = 100;
    uint8_t buffer[100] = {};
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = 244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite001
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ01";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite002
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = 99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ02";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite003
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 244;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ03";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite004
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.interfaceId = 255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ04";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite005
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = 255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ05";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite006
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = 99;
    dev.devAddr = 99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ06";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite007
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = 99;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ07";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdBulkTransferWrite008
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdBulkTransferWrite008, TestSize.Level1)
{
    HDF_LOGI("Case Start : UsbdBulkTransferWrite008 : BulkTransferWrite");
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world bulk writ08";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::BulkTransferWrite(dev, pipe, -1, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: InterruptTransferRead001
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead001 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead002
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_222;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead002 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead003
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 244;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferRead(dev, pipe, 1000, bufferdata);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead004
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[100] = {0};
    uint32_t length = 100;
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.interfaceId = 244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead004 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferRead005
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint32_t length = 100;
    uint8_t buffer[100] = {};
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = 244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead005 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite001
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ01";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite001 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite002
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = 99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ02";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite002 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite003
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 244;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ03";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite003 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite004
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.interfaceId = 255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ04";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite004 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite005
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = 255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ05";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite005 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite006
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite006 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = 99;
    dev.devAddr = 99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ06";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite006 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite007
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = 99;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite007 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ07";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite007 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdInterruptTransferWrite008
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdInterruptTransferWrite008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite008 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Interrupt writ08";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::InterruptTransferWrite(dev, pipe, -1, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite008 %{public}d InterruptTransferWrite=%{public}d", __LINE__,
             ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdIsoTransferRead001
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdIsoTransferRead002
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d interfaceId=%{public}d", __LINE__, interfaceId);
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_222;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferRead003
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 244;
    uint32_t length = 100;
    uint8_t buffer[100] = {0};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferRead004
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[100] = {0};
    uint32_t length = 100;
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.interfaceId = 244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferRead005
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_129;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint32_t length = 100;
    uint8_t buffer[100] = {};
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = 244;
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferRead(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite001
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ01";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite002
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = 99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ02";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite003
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 244;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ03";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite004
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.interfaceId = 255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ04";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite005
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    pipe.endpointId = 255;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ05";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite006
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite006, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    dev.busNum = 99;
    dev.devAddr = 99;
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ06";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite007
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite007, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = 99;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ07";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, 1000, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdIsoTransferWrite008
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdIsoTransferWrite008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t pointid = POINTID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint32_t length = 100;
    uint8_t buffer[100] = "hello world Iso writ08";
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::IsoTransferWrite(dev, pipe, -1, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d IsoTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdConfig001
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfigConfig001 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdConfig002
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig002, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfig002 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdConfig003
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 222;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfig003 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdConfig004
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 反向测试：参数异常，configIndex错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig004, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t configIndex = 222;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    ASSERT_TRUE(ret != 0);
    configIndex = 1;
    ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfig004 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdConfig005
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig005, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 222;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfig005 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdConfig006
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 反向测试：参数异常，busNum、configIndex错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig006, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t configIndex = 222;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfig006 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdConfig007
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 反向测试：devAddr、configIndex错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig007, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 222;
    uint8_t configIndex = 222;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfig007 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdConfig008
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: 反向测试：busNum、devAddr、configIndex错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetConfig008, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 222;
    uint8_t configIndex = 222;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::SetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetConfig008 %{public}d SetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdConfig001
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfig001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::GetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfig001 %{public}d GetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdConfig002
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfig002, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::GetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfig002 %{public}d GetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdConfig003
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfig003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 222;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::GetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfig003 %{public}d GetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdConfig004
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfig004, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 222;
    uint8_t configIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::GetConfig(dev, configIndex);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfig004 %{public}d GetConfig=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdClaimInterface001
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdClaimInterface002
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface002, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = 20;
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdClaimInterface003
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = DEV_ADDR_255;
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdClaimInterface004
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface004, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    interfaceId = 255;
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdClaimInterface005
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface005, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_255;
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdClaimInterface006
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，busNum、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface006, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface006 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_255;
    interfaceId = 255;
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdClaimInterface007
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface007, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface007 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = DEV_ADDR_255;
    interfaceId = 255;
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdClaimInterface008
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：busNum、devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdClaimInterface008, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface008 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_255;
    dev.devAddr = DEV_ADDR_255;
    interfaceId = 255;
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdReleaseInterface001
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdReleaseInterface002
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface002, TestSize.Level1)
{
    uint8_t busNum = 25;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdReleaseInterface003
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 25;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdReleaseInterface004
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface004, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = 255;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdReleaseInterface005
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface005, TestSize.Level1)
{
    uint8_t busNum = 25;
    uint8_t devAddr = 25;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdReleaseInterface006
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：参数异常，busNum、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface006, TestSize.Level1)
{
    uint8_t busNum = 255;
    uint8_t devAddr = 2;
    int32_t interfaceId = 255;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdReleaseInterface007
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface007, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 255;
    int32_t interfaceId = 255;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdReleaseInterface008
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: 反向测试：busNum、devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdReleaseInterface008, TestSize.Level1)
{
    uint8_t busNum = 255;
    uint8_t devAddr = 255;
    int32_t interfaceId = 255;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdReleaseInterface008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdSetInterface001
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t altIndex = 0;

    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);

    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdClaimInterface001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdSetInterface002
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface002, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;

    uint8_t altIndex = 0;
    struct UsbDev dev = {busNum, devAddr};

    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);

    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_222;
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdSetInterface003
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t altIndex = 0;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);

    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = DEV_ADDR_222;
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdSetInterface004
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 反向测试：参数异常，interfaceId 错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface004, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t altIndex = 222;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    interfaceId = 222;
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdSetInterface005
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface005, TestSize.Level1)
{
    uint8_t devAddr = 2;
    uint8_t busNum = 1;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t altIndex = 0;

    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);

    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = 233;
    dev.devAddr = 233;
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    ;
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdSetInterface006
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 反向测试：参数异常，busNum、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface006, TestSize.Level1)
{
    uint8_t devAddr = 2;
    int32_t interfaceId = INT32_INTERFACEID_1;
    uint8_t busNum = 1;
    uint8_t altIndex = 1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface006 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = 224;
    interfaceId = 224;
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdSetInterface007
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 反向测试：devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface007, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    int32_t interfaceId = INT32_INTERFACEID_1;
    uint8_t altIndex = 225;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface007 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 225;
    interfaceId = 225;
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdSetInterface008
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: 反向测试：busNum、devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdSetInterface008, TestSize.Level1)
{
    uint8_t altIndex = 225;
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    int32_t interfaceId = INT32_INTERFACEID_1;
    struct UsbDev dev = {busNum, devAddr};
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface008 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = 225;
    dev.devAddr = 225;
    interfaceId = 225;
    ret = UsbdClient::SetInterface(dev, interfaceId, altIndex);
    HDF_LOGI("UsbdTransferTest::UsbdSetInterface008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor001 %{public}d ret=%{public}d", __LINE__, ret);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor001 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor002, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor002 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 233;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor003 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，length错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor004, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = 0;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor004 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor005, TestSize.Level1)
{
    uint8_t busNum = 99;
    uint8_t devAddr = 99;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor005 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum、length错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor006, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = 0;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor006 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：devAddr、length错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor007, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 222;
    uint8_t buffer[] = {};
    uint32_t length = 0;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor007 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：busNum、devAddr、length错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetDeviceDescriptor008, TestSize.Level1)
{
    uint8_t busNum = 233;
    uint8_t devAddr = 234;
    uint8_t buffer[] = {};
    uint32_t length = 0;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetDeviceDescriptor(dev, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor008 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetDeviceDescriptor008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t stringId = 0;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor001 %{public}d ret=%{public}d", __LINE__, ret);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor001 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor002, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t stringId = 1;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor002 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，stringId错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t stringId = 222;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor003 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor004, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 255;
    uint8_t stringId = 0;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = 8;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor004 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor005, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 222;
    uint8_t stringId = 0;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = 8;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor005 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor006, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t stringId = 0;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor006 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：devAddr、stringID错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor007, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 222;
    uint8_t stringId = 233;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor007 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：busNum、devAddr、length错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetStringDescriptor008, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 222;
    uint8_t stringId = 222;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetStringDescriptor(dev, stringId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor008 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetStringDescriptor008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor001, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t configId = 0;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor001 %{public}d ret=%{public}d", __LINE__, ret);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor001 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor002, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t configId = 1;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor002 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor003, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 222;
    uint8_t configId = 1;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor003 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，configId
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor004, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 2;
    uint8_t configId = 1;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor004 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor005, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 222;
    uint8_t configId = 1;
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor005 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：参数异常，busNum、configId错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor006, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 2;
    uint8_t configId = 222;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor006 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：devAddr、configId错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor007, TestSize.Level1)
{
    uint8_t busNum = 1;
    uint8_t devAddr = 222;
    uint8_t configId = 222;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor007 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &decriptor);
 * @tc.desc: 反向测试：busNum、devAddr、configId错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdGetConfigDescriptor008, TestSize.Level1)
{
    uint8_t busNum = 222;
    uint8_t devAddr = 222;
    uint8_t configId = 222;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devdata(buffer, buffer + length);
    auto ret = UsbdClient::GetConfigDescriptor(dev, configId, devdata);
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor008 %{public}d length=%{public}d buffer=%{public}d", __LINE__,
             devdata.size(), sizeof(devdata));
    HDF_LOGI("UsbdTransferTest::UsbdGetConfigDescriptor008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue001, TestSize.Level1)
{
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue001 %{public}d interfaceId=%{public}d pointid=%{public}d", __LINE__,
             interfaceId, pointid);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue001 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.devAddr = DEV_ADDR_2;
    dev.busNum = BUS_NUM_1;
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    dev = {222, 222};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue002 %{public}d interfaceId=%{public}d pointid=%{public}d", __LINE__,
             interfaceId, pointid);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue002 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue003, TestSize.Level1)
{
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    dev.devAddr = DEV_ADDR_222;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue003 %{public}d interfaceId=%{public}d pointid=%{public}d", __LINE__,
             interfaceId, pointid);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue003 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 反向测试：参数异常，busNum、configIndex错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    interfaceId = 222;
    dev.busNum = BUS_NUM_222;
    uint8_t buffer[LENGTH_NUM_255] = {0};
    uint32_t length = LENGTH_NUM_255;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue004 %{public}d interfaceId=%{public}d pointid=%{public}d", __LINE__,
             interfaceId, pointid);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue004 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue005, TestSize.Level1)
{
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    dev.busNum = BUS_NUM_222;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue005 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest006
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 反向测试：参数异常，busNum、interfaceId、pointid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue006, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    uint8_t buffer[LENGTH_NUM_255] = {};
    dev.devAddr = DEV_ADDR_2;
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    uint32_t length = LENGTH_NUM_255;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue006 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    dev.busNum = BUS_NUM_222;
    interfaceId = 222;
    pointid = 222;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue006 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest007
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 正向测试
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue007, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request 007";
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_1;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue007 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue write";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_11};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue007 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdRequest008
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 反向测试：interfaceId错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "reuquest008";
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_1;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue008 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue write";
    interfaceId = 222;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_11};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue008 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest009
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: 反向测试：interfaceId、poinid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestQueue009, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request 009";
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_1;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue009 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue009 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue write";
    interfaceId = 222;
    pointid = 222;
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_11};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestQueue009 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestWait001, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait001 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t *clientObj = new uint8_t[10];
    std::vector<uint8_t> waitdata = {clientObj, clientObj + 10};
    ret = UsbdClient::RequestWait(dev, waitdata, bufferdata, 10000);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait001 %{public}d RequestWait=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    delete[] clientObj;
    clientObj = nullptr;
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: 反向测试：busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestWait002, TestSize.Level1)
{
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbPipe pipe = {interfaceId, pointid};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait002 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_222;
    uint8_t *clientObj = new uint8_t[10];
    std::vector<uint8_t> waitdata = {clientObj, clientObj + 10};
    ret = UsbdClient::RequestWait(dev, waitdata, bufferdata, 10000);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait002 %{public}d RequestWait=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    delete[] clientObj;
    clientObj = nullptr;
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: 反向测试：devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestWait003, TestSize.Level1)
{
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait003 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t *clientObj = new uint8_t[10];
    dev.devAddr = DEV_ADDR_222;
    std::vector<uint8_t> waitdata = {clientObj, clientObj + 10};
    ret = UsbdClient::RequestWait(dev, waitdata, bufferdata, 10000);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait003 %{public}d RequestWait=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    delete[] clientObj;
    clientObj = nullptr;
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: 反向测试：timeout错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestWait004, TestSize.Level1)
{
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t buffer[LENGTH_NUM_255] = {};
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    uint32_t length = LENGTH_NUM_255;
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait004 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t *clientObj = new uint8_t[10];
    std::vector<uint8_t> waitdata = {clientObj, clientObj + 10};
    ret = UsbdClient::RequestWait(dev, waitdata, bufferdata, -10000);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait004 %{public}d RequestWait=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    delete[] clientObj;
    clientObj = nullptr;
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: 反向测试：busNum、devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestWait005, TestSize.Level1)
{
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint32_t length = LENGTH_NUM_255;
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    uint8_t buffer[LENGTH_NUM_255] = {};
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait005 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    uint8_t *clientObj = new uint8_t[10];
    std::vector<uint8_t> waitdata = {clientObj, clientObj + 10};
    dev.devAddr = DEV_ADDR_255;
    dev.busNum = BUS_NUM_255;
    ret = UsbdClient::RequestWait(dev, waitdata, bufferdata, 10000);
    HDF_LOGI("UsbdTransferTest::UsbdRequestWait005 %{public}d RequestWait=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
    delete[] clientObj;
    clientObj = nullptr;
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel001, TestSize.Level1)
{
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request001";
    uint32_t length = LENGTH_NUM_255;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel001 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel001 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel001 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 反向测试：参数异常，busNum错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel002, TestSize.Level1)
{
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    uint8_t buffer[LENGTH_NUM_255] = "request002";
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel002 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ;
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel002 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = BUS_NUM_222;
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel002 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 反向测试：参数异常，devAddr错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel003, TestSize.Level1)
{
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request003";
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel003 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbPipe pipe = {interfaceId, pointid};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel003 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = DEV_ADDR_222;
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel003 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 反向测试：参数异常，interfaceid错误 结果正常？？？
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel004, TestSize.Level1)
{
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue read";
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint32_t length = LENGTH_NUM_255;
    uint8_t buffer[LENGTH_NUM_255] = "request004";
    uint8_t pointid = POINTID_129;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel004 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_10};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel004 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    pipe.interfaceId = 222;
    pipe.endpointId = 222;
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel004 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 正向测试
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request005";
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_1;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel005 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue Write";
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_11};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel005 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel005 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: UsbdRequest006
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 反向测试：参数异常，busNum、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel006, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request006";
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_1;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel006 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue Write";
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_11};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    struct UsbPipe pipe = {interfaceId, pointid};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel006 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.busNum = 224;
    pipe.interfaceId = 224;
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel006 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest007
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 反向测试：参数异常，devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel007, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request007";
    uint32_t length = LENGTH_NUM_255;
    uint8_t pointid = POINTID_1;
    uint8_t interfaceId = INTERFACEID_1;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel007 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    struct UsbPipe pipe = {interfaceId, pointid};
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue Write";
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_11};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel007 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = 224;
    pipe.interfaceId = 224;
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel007 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UsbdRequest008
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: 反向测试：参数异常，busNum、devAddr、interfaceid错误
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, UsbdRequestCancel008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_1, DEV_ADDR_2};
    dev.busNum = BUS_NUM_1;
    dev.devAddr = DEV_ADDR_2;
    uint8_t buffer[LENGTH_NUM_255] = "request008";
    uint8_t pointid = POINTID_1;
    uint8_t interfaceId = INTERFACEID_1;
    uint32_t length = LENGTH_NUM_255;
    auto ret = UsbdClient::ReleaseInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel008 %{public}d interfaceId=%{public}d pointid=%{public}d", __LINE__,
             interfaceId, pointid);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel008 %{public}d ReleaseInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    ret = UsbdClient::ClaimInterface(dev, interfaceId);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    EXPECT_TRUE(ret == 0);
    uint8_t tag[TAG_LENGTH_NUM_1000] = "queue Write";
    struct UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> clientdata = {tag, tag + TAG_NUM_11};
    std::vector<uint8_t> bufferdata = {buffer, buffer + length};
    ret = UsbdClient::RequestQueue(dev, pipe, clientdata, bufferdata);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel008 %{public}d RequestQueue=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret == 0);
    dev.devAddr = DEV_ADDR_222;
    pipe.interfaceId = 222;
    dev.busNum = BUS_NUM_222;
    ret = UsbdClient::RequestCancel(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UsbdRequestCancel008 %{public}d RequestCancel=%{public}d", __LINE__, ret);
    ASSERT_TRUE(ret != 0);
}
