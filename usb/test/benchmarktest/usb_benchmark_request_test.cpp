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
#include <vector>
#include "hdf_log.h"
#include "usbd_port.h"
#include "UsbSubscriberTest.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/iusbd_bulk_callback.h"
#include "v1_0/usb_types.h"

using namespace benchmark::internal;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;
using namespace OHOS::HDI::Usb::V1_1;

namespace {
sptr<OHOS::HDI::Usb::V1_1::IUsbInterface> g_usbInterface = nullptr;
struct UsbDev g_dev = {0, 0};

const int SLEEP_TIME = 3;
const uint8_t INDEX_0 = 0;
const uint8_t INDEX_1 = 1;
const int TAG_NUM_10 = 10;
const uint8_t CONFIG_ID_0 = 0;
const uint8_t INTERFACEID_OK = 1;
const uint32_t MAX_BUFFER_LENGTH = 255;
constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;
const uint32_t TIME_WAIT = 10000;
// data interface have 2 point : 1->bulk_out 2->bulk_in
const uint8_t POINTID_DIR_IN = USB_ENDPOINT_DIR_IN | 2;

class HdfUsbdBenchmarkRequestTest : public benchmark::Fixture {
public:
    void InitPara(const sptr<UsbSubscriberTest> &subscriber);
    void ReleasePara(const sptr<UsbSubscriberTest> &subscriber);
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
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

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void HdfUsbdBenchmarkRequestTest::SetUp(const ::benchmark::State& state)
{
    g_usbInterface = OHOS::HDI::Usb::V1_1::IUsbInterface::Get();
    ASSERT_TRUE(g_usbInterface != nullptr);
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SOURCE, DATA_ROLE_HOST);
    sleep(SLEEP_TIME);
    ret = SwitchErrCode(ret);
    EXPECT_EQ(0, ret);
}

void HdfUsbdBenchmarkRequestTest::TearDown(const ::benchmark::State& state) {}

void HdfUsbdBenchmarkRequestTest::InitPara(const sptr<UsbSubscriberTest> &subscriber)
{
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGW("HdfUsbdBenchmarkRequestTest::bind usbdsubscriber fail");
    }
    g_dev = {subscriber->busNum_, subscriber->devAddr_};
    auto ret = g_usbInterface->OpenDevice(g_dev);
    EXPECT_EQ(0, ret);
}

void HdfUsbdBenchmarkRequestTest::ReleasePara(const sptr<UsbSubscriberTest> &subscriber)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    auto ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    EXPECT_EQ(0, ret);
    ret = g_usbInterface->CloseDevice(g_dev);
    EXPECT_EQ(0, ret);
}
/**
 * @tc.name: SetConfig
 * @tc.desc: Test functions to SetConfig benchmark test
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, SetConfig)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    uint8_t configIndex = INDEX_1;
    InitPara(subscriber);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->SetConfig(g_dev, configIndex);
    }
    ASSERT_EQ(0, ret);
    ReleasePara(subscriber);
}
BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, SetConfig)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: GetConfig
 * @tc.desc: Test functions to GetConfig benchmark test
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, GetConfig)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    uint8_t configIndex = INDEX_1;
    InitPara(subscriber);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->GetConfig(g_dev, configIndex);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, GetConfig)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: ClaimInterface
 * @tc.desc: Test functions to ClaimInterface benchmark test
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, ClaimInterface)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    uint8_t interfaceId = INTERFACEID_OK;
    InitPara(subscriber);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, ClaimInterface)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: SetInterface
 * @tc.desc: Test functions to SetInterface benchmark test
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, SetInterface)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_0;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    for (auto _ : state) {
        ret = g_usbInterface->SetInterface(g_dev, interfaceId, altIndex);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, SetInterface)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: GetDeviceDescriptor
 * @tc.desc: Test functions to GetDeviceDescriptor benchmark test
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, GetDeviceDescriptor)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->GetDeviceDescriptor(g_dev, devData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, GetDeviceDescriptor)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: GetStringDescriptor
 * @tc.desc: Test functions to GetStringDescriptor benchmark test
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, GetStringDescriptor)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t stringId = 0;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->GetStringDescriptor(g_dev, stringId, devData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, GetStringDescriptor)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: GetConfigDescriptor
 * @tc.desc: Test functions to GetConfigDescriptor benchmark test
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, GetConfigDescriptor)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t configId = CONFIG_ID_0;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->GetConfigDescriptor(g_dev, configId, devData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, GetConfigDescriptor)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: GetRawDescriptor
 * @tc.desc: Test functions to GetRawDescriptor benchmark test
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, GetRawDescriptor)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    std::vector<uint8_t> rawData;
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->GetRawDescriptor(g_dev, rawData);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, GetRawDescriptor)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: GetFileDescriptor
 * @tc.desc: Test functions to GetFileDescriptor benchmark test
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, GetFileDescriptor)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    int32_t fd = 0;
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->GetFileDescriptor(g_dev, fd);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, GetFileDescriptor)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: RequestQueue
 * @tc.desc: Test functions to RequestQueue benchmark test
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, RequestQueue)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    for (auto _ : state) {
        ret = g_usbInterface->RequestQueue(g_dev, pipe, clientData, bufferData);
    }
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, RequestQueue)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: RequestWait
 * @tc.desc: Test functions to RequestWait benchmark test
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */

BENCHMARK_F(HdfUsbdBenchmarkRequestTest, RequestWait)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(g_dev, pipe, clientData, bufferData);
    std::vector<uint8_t> waitData(TAG_NUM_10);
    for (auto _ : state) {
        ret = g_usbInterface->RequestWait(g_dev, waitData, bufferData, TIME_WAIT);
    }
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, RequestWait)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: RequestCancel
 * @tc.desc: Test functions to RequestCancel benchmark test
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, RequestCancel)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '1'};
    ret = g_usbInterface->RequestQueue(g_dev, pipe, clientData, bufferData);
    EXPECT_EQ(0, ret);
    for (auto _ : state) {
        ret = g_usbInterface->RequestCancel(g_dev, pipe);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, RequestCancel)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: ReleaseInterface
 * @tc.desc: Test functions to ReleaseInterface benchmark test
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, ReleaseInterface)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->ReleaseInterface(g_dev, interfaceId);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, ReleaseInterface)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: BulkCancel
 * @tc.desc: Test functions to BulkCancel benchmark test
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, BulkCancel)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    ASSERT_TRUE(ret == 0);
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    ret = g_usbInterface->RegBulkCallback(g_dev, pipe, usbdBulkCallback);
    EXPECT_EQ(ret, 0);
    for (auto _ : state) {
        ret = g_usbInterface->BulkCancel(g_dev, pipe);
    }
    EXPECT_EQ(0, ret);
    ret = g_usbInterface->UnRegBulkCallback(g_dev, pipe);
    EXPECT_EQ(ret, 0);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, BulkCancel)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: ClearHalt
 * @tc.desc: Test functions to ClearHalt benchmark test
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, ClearHalt)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(g_dev, interfaceId, 1);
    EXPECT_EQ(ret, 0);
    uint8_t pointId = POINTID_DIR_IN;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    EXPECT_EQ(0, ret);
    for (auto _ : state) {
        ret = g_usbInterface->ClearHalt(g_dev, pipe);
    }
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, ClearHalt)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: ResetDevice
 * @tc.desc: Test functions to ResetDevice benchmark test
 * @tc.desc: int32_t ResetDevice(const UsbDev &dev);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(HdfUsbdBenchmarkRequestTest, ResetDevice)(benchmark::State& state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_TRUE(subscriber != nullptr);
    InitPara(subscriber);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->ResetDevice(g_dev);
    }
    EXPECT_EQ(0, ret);
    ReleasePara(subscriber);
}

BENCHMARK_REGISTER_F(HdfUsbdBenchmarkRequestTest, ResetDevice)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
} // namespace

BENCHMARK_MAIN();
