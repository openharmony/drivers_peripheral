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
#include "v1_0/iusbd_bulk_callback.h"
#include "v1_0/usb_types.h"

using ::testing::Exactly;
using ::testing::Return;

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

constexpr uint8_t BUS_NUM_INVALID = 255;;
constexpr uint8_t DEV_ADDR_INVALID = 255;
constexpr uint32_t MAX_BUFFER_LENGTH = 255;
constexpr uint8_t INTERFACEID_OK = 1;
constexpr uint8_t PIPE_ENDPOINTID_INVALID = 244;
constexpr uint8_t PIPE_INTERFACEID_INVALID = 244;
// data interface have 2 point : 1->bulk_out 2->bulk_in
constexpr uint8_t POINTID_DIR_IN = USB_ENDPOINT_DIR_IN | 2;
constexpr uint8_t POINTID_DIR_OUT = USB_ENDPOINT_DIR_OUT | 1;
constexpr int32_t ASHMEM_MAX_SIZE = 1024;
constexpr uint8_t BUS_NUM_OK = 6;
constexpr uint8_t DEV_ADDR_OK = 2;
constexpr int32_t TRANSFER_TIME_OUT = 1000;
constexpr int32_t CTL_VALUE = 0x100;
constexpr int32_t ACM_SET_LINE_CODING_LEN = 7;

namespace {
class UsbdTransferTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static UsbDev dev_;
};
class UsbdBulkCallbackTest : public OHOS::HDI::Usb::V1_0::IUsbdBulkCallback {
public:
    UsbdBulkCallbackTest() = default;
    ~UsbdBulkCallbackTest() = default;
    int32_t OnBulkWriteCallback(int32_t status, int32_t actLength) override
    {
        return 0;
    };
    int32_t OnBulkReadCallback(int32_t status, int32_t actLength) override
    {
        return 0;
    };
};
sptr<IUsbInterface> g_usbInterface = nullptr;
UsbDev UsbdTransferTest::dev_ = {0, 0};

int32_t InitAshmemOne(sptr<Ashmem> &asmptr, int32_t asmSize, uint8_t rflg)
{
    asmptr = Ashmem::CreateAshmem("ttashmem000", asmSize);
    if (asmptr == nullptr) {
        HDF_LOGE("InitAshmemOne CreateAshmem failed");
        return HDF_FAILURE;
    }

    asmptr->MapReadAndWriteAshmem();

    if (rflg == 0) {
        uint8_t tdata[ASHMEM_MAX_SIZE];
        int32_t offset = 0;
        int32_t tlen = 0;

        int32_t retSafe = memset_s(tdata, sizeof(tdata), 'Y', ASHMEM_MAX_SIZE);
        if (retSafe != EOK) {
            HDF_LOGE("InitAshmemOne memset_s failed");
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
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();
    g_usbInterface = IUsbInterface::Get(true);
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed", __func__);
        exit(0);
    }
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
    ASSERT_EQ(0, ret);
    dev_ = {BUS_NUM_OK, DEV_ADDR_OK};
    ret = g_usbInterface->OpenDevice(dev_);
    ASSERT_EQ(0, ret);
}

void UsbdTransferTest::TearDownTestCase(void)
{
    g_usbInterface->CloseDevice(dev_);
    sptr<UsbImpl> sp = static_cast<UsbImpl *>(g_usbInterface.GetRefPtr());
    UsbdDispatcher::UsbdDeviceDettach(sp, BUS_NUM_OK, DEV_ADDR_OK);
}

/**
 * @tc.name: ControlTransferRead001
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get config
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN,
        USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead002
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN,
        USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead002 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead003
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN,
        USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead003 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead004
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN,
        USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead004 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead005
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN,
        USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead005 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead006
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get descriptor(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead006, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN,
        USB_DDK_REQ_GET_DESCRIPTOR, CTL_VALUE, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead006 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead007
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t interfaceIndex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, interfaceIndex, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead007 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead008
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead008, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    int32_t interfaceIndex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, interfaceIndex, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead008 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead009
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get interface
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead009, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    int32_t interfaceIndex = 0;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_INTERFACE, 0, interfaceIndex, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead009 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead010
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * Positive test: parameters correctly, standard request: get status(recipient device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead010, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead010 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead011
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead011, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead011 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead012
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(device)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead012, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead012 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead013
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * Positive test: parameters correctly, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead013, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead013 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead014
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead014, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead014 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead015
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(interface)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead015, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead015 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead016
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead016, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead016 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead017
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead017, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead017 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead018
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get status(endpoint)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead018, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_GET_STATUS, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead018 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead019
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead019, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_SYNCH_FRAME, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead019 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead020
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead020, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_SYNCH_FRAME, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead020 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferRead021
 * @tc.desc: Test functions to ControlTransfer(const UsbDev &dev, UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: sync frame
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferRead021, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_IN | USB_REQUEST_TARGET_ENDPOINT,
        USB_DDK_REQ_SYNCH_FRAME, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferRead(dev, ctrlParmas, bufferData);
    HDF_LOGI("UsbdTransferTest::ControlTransferRead021 %{public}d ControlTransfer=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: ControlTransferWrite001
 * @tc.desc: Test functions to ControlTransferWrite(const UsbDev &dev,
 * UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, set acm btr
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(ACM_SET_LINE_CODING_LEN);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_OUT | USB_DDK_TYPE_CLASS | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_CDC_REQ_SET_LINE_CODING, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferWrite(dev, ctrlParmas, bufferData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferWrite002
 * @tc.desc: Test functions to ControlTransferWrite(const UsbDev &dev,
 * UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, set acm btr
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_OUT | USB_DDK_TYPE_CLASS | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_CDC_REQ_SET_CONTROL_LINE_STATE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferWrite(dev, ctrlParmas, bufferData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferWrite003
 * @tc.desc: Test functions to ControlTransferWrite(const UsbDev &dev,
 * UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, busNum error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferWrite003, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_OUT | USB_DDK_TYPE_CLASS | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_CDC_REQ_SET_CONTROL_LINE_STATE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferWrite(dev, ctrlParmas, bufferData);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: ControlTransferWrite004
 * @tc.desc: Test functions to ControlTransferWrite(const UsbDev &dev,
 * UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr && busNum error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferWrite004, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_OUT | USB_DDK_TYPE_CLASS | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_CDC_REQ_SET_CONTROL_LINE_STATE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferWrite(dev, ctrlParmas, bufferData);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: ControlTransferWrite005
 * @tc.desc: Test functions to ControlTransferWrite(const UsbDev &dev,
 * UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: parameters exception, devAddr error, standard request: get configuration
 * @tc.type: FUNC
 */
HWTEST_F(UsbdTransferTest, ControlTransferWrite005, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlParmas = {USB_ENDPOINT_DIR_OUT | USB_DDK_TYPE_CLASS | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_CDC_REQ_SET_CONTROL_LINE_STATE, 0, 0, TRANSFER_TIME_OUT};
    auto ret = g_usbInterface->ControlTransferWrite(dev, ctrlParmas, bufferData);
    ASSERT_NE(0, ret);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {PIPE_INTERFACEID_INVALID, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, PIPE_ENDPOINTID_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->InterruptTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferRead005 %{public}d UsbdInterruptTransferRead=%{public}d", __LINE__,
        ret);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, PIPE_ENDPOINTID_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferRead005 %{public}d UsbdBulkTransferRead=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d interfaceId=%{public}d", __LINE__, interfaceId);
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {PIPE_INTERFACEID_INVALID, pointId};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, PIPE_ENDPOINTID_INVALID};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->IsoTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferRead005 %{public}d UsbdIsoTransferRead=%{public}d", __LINE__, ret);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '1'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '2'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '3'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '4'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    pipe.endpointId = PIPE_ENDPOINTID_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '5'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '6'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = PIPE_ENDPOINTID_INVALID;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '7'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '8'};
    ret = g_usbInterface->BulkTransferWrite(dev, pipe, -1, bufferData);
    HDF_LOGI("UsbdTransferTest::UsbdBulkTransferWrite008 %{public}d BulkTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '1'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '2'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '3'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {PIPE_INTERFACEID_INVALID, pointId};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '4'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, PIPE_ENDPOINTID_INVALID};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '5'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '6'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = PIPE_ENDPOINTID_INVALID;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '7'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdInterruptTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '8'};
    ret = g_usbInterface->InterruptTransferWrite(dev, pipe, -1, bufferData);
    HDF_LOGI(
        "UsbdTransferTest::UsbdInterruptTransferWrite008 %{public}d InterruptTransferWrite=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '1'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '2'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '3'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {PIPE_INTERFACEID_INVALID, pointId};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '4'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, PIPE_ENDPOINTID_INVALID};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '5'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite006 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '6'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = PIPE_ENDPOINTID_INVALID;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite007 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '7'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::UsbdIsoTransferWrite008 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '8'};
    ret = g_usbInterface->IsoTransferWrite(dev, pipe, -1, bufferData);
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.devAddr = DEV_ADDR_INVALID;
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {PIPE_INTERFACEID_INVALID, pointId};
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkWrite005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, PIPE_ENDPOINTID_INVALID};
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead003 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.devAddr = DEV_ADDR_INVALID;
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead004 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {PIPE_INTERFACEID_INVALID, pointId};
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
    int32_t asmSize = MAX_BUFFER_LENGTH;
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    HDF_LOGI("UsbdTransferTest::BulkRead005 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, PIPE_ENDPOINTID_INVALID};
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.busNum = BUS_NUM_INVALID;
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    dev.devAddr = DEV_ADDR_INVALID;
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
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {PIPE_INTERFACEID_INVALID, POINTID_DIR_OUT};
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback002 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    dev.devAddr = DEV_ADDR_INVALID;
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdBulkCallbackTest new failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback003 %{public}d RegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
    pipe.intfId = PIPE_INTERFACEID_INVALID;
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback003 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
    pipe = {interfaceId, pointId};
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
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
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    auto ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    HDF_LOGI("UsbdTransferTest::UnRegBulkCallback005 %{public}d UnRegBulkCallback=%{public}d", __LINE__, ret);
    ASSERT_EQ(ret, 0);
}
} // namespace
