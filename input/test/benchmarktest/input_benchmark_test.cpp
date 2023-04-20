/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <benchmark/benchmark.h>
#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include <unistd.h>
#include <vector>
#include "hdf_base.h"
#include "input_callback_impl.h"
#include "input_type.h"
#include "osal_time.h"
#include "v1_0/iinput_interfaces.h"

using namespace OHOS::HDI::Input::V1_0;
using namespace std;
using namespace testing::ext;

namespace  {
    sptr<IInputInterfaces>  g_inputInterfaces = nullptr;
    sptr<IInputCallback> g_callback = nullptr;

    constexpr int32_t INIT_DEFAULT_VALUE = 255;
    constexpr int32_t TOUCH_INDEX = 1;
    constexpr int32_t TEST_RESULT_LEN = 32;

class InputBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void InputBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_inputInterfaces = IInputInterfaces::Get(true);
    if (g_inputInterfaces != nullptr) {
        g_callback = new InputCallbackImpl(g_inputInterfaces, nullptr);
    }
}

void InputBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    g_inputInterfaces = nullptr;
}

/**
  * @tc.name: HdfInput_ScanInputDevice_test
  * @tc.desc: Benchmarktest for interface ScanInputDevice.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_ScanInputDevice_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    std::vector<DevDesc> sta;
    int32_t ret;
    for (auto _ : state) {
        ret = g_inputInterfaces->ScanInputDevice(sta);
    }
    EXPECT_EQ(INPUT_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_ScanInputDevice_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_OpenInputDevice_test
  * @tc.desc: Benchmarktest for interface OpenInputDevice and CloseInputDevice.
  * @tc.type: FUNC
  */

BENCHMARK_F(InputBenchmarkTest, HdfInput_OpenInputDevice_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    for (auto _ : state) {
        ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
        ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    }
    EXPECT_EQ(INPUT_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_OpenInputDevice_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_GetInputDevice_test
  * @tc.desc: Benchmarktest for interface GetInputDevice.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_GetInputDevice_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    struct DeviceInfo dev;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->GetInputDevice(TOUCH_INDEX, dev);
    }
    EXPECT_EQ(INPUT_SUCCESS, ret);
    EXPECT_EQ((uint32_t)TOUCH_INDEX, dev.devIndex);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_GetInputDevice_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_GetInputDeviceList_test
  * @tc.desc: Benchmarktest for interface GetInputDeviceList.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_GetInputDeviceList_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    uint32_t num = 0;
    std::vector<DeviceInfo> dev;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->GetInputDeviceList(num, dev, MAX_INPUT_DEV_NUM);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ASSERT_LE(num, (uint32_t)MAX_INPUT_DEV_NUM);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_GetInputDeviceList_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_GetDeviceType_test
  * @tc.desc: Benchmarktest for interface GetDeviceType.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_GetDeviceType_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    uint32_t devType = INIT_DEFAULT_VALUE;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->GetDeviceType(TOUCH_INDEX, devType);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_GetDeviceType_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_GetChipInfo_test
  * @tc.desc: Benchmarktest for interface GetChipInfo.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_GetChipInfo_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    std::string chipInfo;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->GetChipInfo(TOUCH_INDEX, chipInfo);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_GetChipInfo_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_SetPowerStatus_test
  * @tc.desc: Benchmarktest for interface SetPowerStatus.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_SetPowerStatus_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    uint32_t setStatus = INPUT_LOW_POWER;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->SetPowerStatus(TOUCH_INDEX, setStatus);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_SetPowerStatus_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_GetPowerStatus_test
  * @tc.desc: Benchmarktest for interface GetPowerStatus.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_GetPowerStatus_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    uint32_t getStatus = 0;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->GetPowerStatus(TOUCH_INDEX, getStatus);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_GetPowerStatus_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_GetVendorName_test
  * @tc.desc: Benchmarktest for interface GetVendorName.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_GetVendorName_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    std::string vendorName;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->GetVendorName(TOUCH_INDEX, vendorName);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_GetVendorName_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_GetChipName_test
  * @tc.desc: Benchmarktest for interface GetChipName.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_GetChipName_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    std::string chipName;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->GetChipName(TOUCH_INDEX, chipName);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_GetChipName_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_SetGestureMode_test
  * @tc.desc: Benchmarktest for interface SetGestureMode.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_SetGestureMode_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    uint32_t gestureMode = 1;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->SetGestureMode(TOUCH_INDEX, gestureMode);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_SetGestureMode_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_RunCapacitanceTest_test
  * @tc.desc: Benchmarktest for interface RunCapacitanceTest.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_RunCapacitanceTest_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    uint32_t testType = MMI_TEST;
    std::string result;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->RunCapacitanceTest(TOUCH_INDEX, testType, result, TEST_RESULT_LEN);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_RunCapacitanceTest_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: HdfInput_RunExtraCommand_test
  * @tc.desc: Benchmarktest for interface RunExtraCommand.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_RunExtraCommand_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->RunExtraCommand(TOUCH_INDEX, extraCmd);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_RunExtraCommand_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();


/**
  * @tc.name: HdfInput_RegisterReportCallback_test
  * @tc.desc: Benchmarktest for interface RegisterReportCallback and UnregisterReportCallback.
  * @tc.type: FUNC
  */
BENCHMARK_F(InputBenchmarkTest, HdfInput_RegisterReportCallback_test)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_inputInterfaces);

    int32_t ret;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_inputInterfaces->RegisterReportCallback(TOUCH_INDEX, g_callback);
        ret = g_inputInterfaces->UnregisterReportCallback(TOUCH_INDEX);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(INPUT_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(InputBenchmarkTest, HdfInput_RegisterReportCallback_test)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();
} // namespace

BENCHMARK_MAIN();
