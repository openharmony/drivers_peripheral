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

#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include <vector>
#include "hdf_log.h"
#include "securec.h"
#include "usbd_port.h"
#include "usbd_function.h"
#include "UsbSubscriberTest.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

using namespace benchmark::internal;
using namespace OHOS;
using namespace std;
using namespace OHOS::USB;
using namespace OHOS::HDI::Usb::V1_0;

namespace {
sptr<IUsbInterface> g_usbInterface = nullptr;
struct UsbDev g_dev = {0, 0};
const int SLEEP_TIME = 3;
const uint8_t INTERFACEID_OK = 1;
const uint32_t MAX_BUFFER_LENGTH = 255;
const int32_t TRANSFER_TIME_OUT = 1000;
const int32_t ASHMEM_MAX_SIZE = 1024;
const uint8_t SAMPLE_DATA_1 = 1;
const uint8_t SAMPLE_DATA_2 = 2;
const uint8_t SAMPLE_DATA_3 = 3;
constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;
constexpr int32_t ITERATION_READ_FREQUENCY = 10;
constexpr int32_t ITERATION_WRITE_FREQUENCY = 20;
// data interface have 2 point : 1->bulk_out 2->bulk_in
const uint8_t POINTID_BULK_IN = USB_ENDPOINT_DIR_IN | 2;
const uint8_t POINTID_BULK_OUT = USB_ENDPOINT_DIR_OUT | 1;

class HdfUsbdBenchmarkTransferTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
    void InitPara(const sptr<UsbSubscriberTest> &subscriber);
    void ReleasePara(const sptr<UsbSubscriberTest> &subscriber);
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

int32_t InitAshmemOne(sptr<Ashmem>& asmptr, int32_t asmSize, uint8_t rflg)
{
    asmptr = Ashmem::CreateAshmem("ttashmem000", asmSize);
    if (asmptr == nullptr) {
        return HDF_FAILURE;
    }

    asmptr->MapReadAndWriteAshmem();

    if (rflg == 0) {
        uint8_t tdata[ASHMEM_MAX_SIZE];
        int32_t offset = 0;
        int32_t tlen = 0;

        int32_t retSafe = memset_s(tdata, sizeof(tdata), 'Y', ASHMEM_MAX_SIZE);
        if (retSafe != EOK) {
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

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void HdfUsbdBenchmarkTransferTest::SetUp(const ::benchmark::State& state)
{
    g_usbInterface = IUsbInterface::Get();
    ASSERT_NE(g_usbInterface, nullptr);
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SOURCE, DATA_ROLE_HOST);
    sleep(SLEEP_TIME);
    ret = SwitchErrCode(ret);
    EXPECT_EQ(0, ret);
}

void HdfUsbdBenchmarkTransferTest::TearDown(const ::benchmark::State& state)
{}

void HdfUsbdBenchmarkTransferTest::InitPara(const sptr<UsbSubscriberTest> &subscriber)
{
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGW("HdfUsbdBenchmarkRequestTest::bind usbdsubscriber fail");
    }
    g_dev = {subscriber->busNum_, subscriber->devAddr_};
    auto ret = g_usbInterface->OpenDevice(g_dev);
    EXPECT_EQ(0, ret);
}

void HdfUsbdBenchmarkTransferTest::ReleasePara(const sptr<UsbSubscriberTest> &subscriber)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    auto ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    EXPECT_EQ(0, ret);
    ret = g_usbInterface->CloseDevice(g_dev);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: ControlTransferRead
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to ControlTransferRead(const UsbDev &dev, UsbCtrlTransfer &ctrl,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, standard request: get configuration
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, ControlTransferRead)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    int32_t ret;
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_IN, USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    for (auto _ : state) {
        ret = g_usbInterface->ControlTransferRead(g_dev, ctrlparmas, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, ControlTransferRead)->
    Iterations(ITERATION_READ_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: ControlTransferWrite
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to ControlTransferWrite(const UsbDev &dev, UsbCtrlTransfer &ctrl,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, ControlTransferWrite)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    int32_t ret;
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    bufferData.push_back(SAMPLE_DATA_1);
    bufferData.push_back(SAMPLE_DATA_2);
    bufferData.push_back(SAMPLE_DATA_3);
    struct UsbCtrlTransfer ctrlparmas = {USB_ENDPOINT_DIR_OUT | USB_REQUEST_TARGET_INTERFACE,
        USB_DDK_REQ_GET_CONFIGURATION, 0, 0, TRANSFER_TIME_OUT};
    for (auto _ : state) {
        ret = g_usbInterface->ControlTransferWrite(g_dev, ctrlparmas, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}
BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, ControlTransferWrite)->
    Iterations(ITERATION_WRITE_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: BulkTransferRead
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, BulkTransferRead)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    for (auto _ : state) {
        ret = g_usbInterface->BulkTransferRead(g_dev, pipe, TRANSFER_TIME_OUT, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, BulkTransferRead)->
    Iterations(ITERATION_READ_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: BulkTransferWrite
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, BulkTransferWrite)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'b', 'u', 'l', 'k', 'w', 'r', 'i', 't', 'e', '0', '1'};
    for (auto _ : state) {
        ret = g_usbInterface->BulkTransferWrite(g_dev, pipe, TRANSFER_TIME_OUT, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, BulkTransferWrite)->
    Iterations(ITERATION_WRITE_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: InterruptTransferRead
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, InterruptTransferRead)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    for (auto _ : state) {
        ret = g_usbInterface->InterruptTransferRead(g_dev, pipe, TRANSFER_TIME_OUT, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, InterruptTransferRead)->
    Iterations(ITERATION_READ_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
/**
 * @tc.name: InterruptTransferWrite
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, InterruptTransferWrite)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 'n', 't', 'w', 'r', 'i', 't', 'e', '0', '1'};
    for (auto _ : state) {
        ret = g_usbInterface->InterruptTransferWrite(g_dev, pipe, TRANSFER_TIME_OUT, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, InterruptTransferWrite)->
    Iterations(ITERATION_WRITE_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
/**
 * @tc.name: IsoTransferRead
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, IsoTransferRead)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    for (auto _ : state) {
        ret = g_usbInterface->IsoTransferRead(g_dev, pipe, TRANSFER_TIME_OUT, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, IsoTransferRead)->
    Iterations(ITERATION_READ_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
/**
 * @tc.name: IsoTransferWrite
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
 * std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, IsoTransferWrite)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData = {'i', 's', 'o', 'w', 'r', 'i', 't', 'e', '0', '1'};
    for (auto _ : state) {
        ret = g_usbInterface->IsoTransferWrite(g_dev, pipe, TRANSFER_TIME_OUT, bufferData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, IsoTransferWrite)->
    Iterations(ITERATION_WRITE_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: BulkRead
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, BulkRead)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    for (auto _ : state) {
        ret = g_usbInterface->BulkRead(g_dev, pipe, ashmem);
    }
    EXPECT_EQ(ret, 0);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, BulkRead)->
    Iterations(ITERATION_READ_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: BulkWrite
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, BulkWrite)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    sptr<Ashmem> ashmem;
    uint8_t rflg = 0;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    for (auto _ : state) {
        ret = g_usbInterface->BulkWrite(g_dev, pipe, ashmem);
    }
    EXPECT_EQ(ret, 0);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, BulkWrite)->
    Iterations(ITERATION_WRITE_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: RegBulkCallback
 * @tc.desc: Benchmark test
 * @tc.desc: int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe, const sptr<IUsbdBulkCallback> &cb)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, RegBulkCallback)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    int32_t ret;
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ASSERT_TRUE(usbdBulkCallback != nullptr);
    for (auto _ : state) {
        ret = g_usbInterface->RegBulkCallback(g_dev, pipe, usbdBulkCallback);
    }
    EXPECT_EQ(ret, 0);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, RegBulkCallback)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: UnRegBulkCallback
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, UnRegBulkCallback)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointid};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ASSERT_TRUE(usbdBulkCallback != nullptr);
    auto ret = g_usbInterface->RegBulkCallback(g_dev, pipe, usbdBulkCallback);
    EXPECT_EQ(ret, 0);
    for (auto _ : state) {
        ret = g_usbInterface->UnRegBulkCallback(g_dev, pipe);
    }
    EXPECT_EQ(ret, 0);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, UnRegBulkCallback)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: BindUsbdSubscriber
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to int32_t BindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, BindUsbdSubscriber)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    int32_t ret;
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    for (auto _ : state) {
        ret = g_usbInterface->BindUsbdSubscriber(subscriber);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, BindUsbdSubscriber)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
/**
 * @tc.name: UnbindUsbdSubscriber
 * @tc.desc: Benchmark test
 * @tc.desc: Test functions to int32_t UnbindUsbdSubscriber(const sptr<IUsbdSubscriber> &subscriber)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkTransferTest, UnbindUsbdSubscriber)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(subscriber, nullptr);
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: bind usbd subscriber failed", __func__);
    }
    g_dev = {subscriber->busNum_, subscriber->devAddr_};
    auto ret = g_usbInterface->OpenDevice(g_dev);
    EXPECT_EQ(ret, 0);
    for (auto _ : state) {
        ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    }
    ret = g_usbInterface->CloseDevice(g_dev);
    EXPECT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkTransferTest, UnbindUsbdSubscriber)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
} // namespace

BENCHMARK_MAIN();
