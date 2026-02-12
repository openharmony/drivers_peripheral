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

#include <cmath>
#include <cstdio>
#include <unistd.h>
#include <cstdlib>
#include <gtest/gtest.h>
#include <securec.h>
#include <iostream>
#include <string>
#include <thread>
#include <future>
#include <chrono>
#include <functional>
#include <stdexcept>
#include "hdf_base.h"
#include "osal_time.h"
#include "v3_0/isensor_interface.h"
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"

using namespace OHOS::HDI::Sensor::V3_0;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;
int32_t SensorCallbackImpl::sensorDataCount = 0;
int32_t SensorCallbackImpl::sensorDataCountOld = 0;
bool SensorCallbackImpl::printDataFlag = false;

namespace {
    sptr<V3_0::ISensorInterface>  g_sensorInterface = nullptr;
    sptr<V3_0::ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    DeviceSensorInfo g_deviceSensorInfo = {-1, 1, 0, 1};
    int64_t g_samplingInterval = 10000000; // 10ms
    int64_t g_testTime = 5000; // 5s
    int64_t g_testTime2 = 120000; // 120s
    constexpr int32_t DECIMAL_NOTATION = 10;

    class SensorSetBatchTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
        static std::string ExecShellCommand(const std::string& command);
        static std::string ExecShellCommandTenTimes(const std::string& command);
    };

    void SensorSetBatchTest::SetUpTestCase()
    {
        SENSOR_TRACE;
        g_sensorInterface = V3_0::ISensorInterface::Get();
        const char* testSensorType = std::getenv("testSensorType");
        if (testSensorType) {
            printf("testSensorType=%s\n", testSensorType);
            g_deviceSensorInfo.sensorType = std::atoi(testSensorType);
        }
        const char* testSamplingInterval = std::getenv("testSamplingInterval");
        if (testSamplingInterval) {
            printf("testSamplingInterval=%s\n", testSamplingInterval);
            g_samplingInterval = strtoll(testSamplingInterval, nullptr, DECIMAL_NOTATION);
        }
        const char* testPrintDataFlag = std::getenv("testPrintDataFlag");
        if (testPrintDataFlag) {
            printf("testPrintDataFlag=%s\n", testPrintDataFlag);
            if (std::strcmp(testPrintDataFlag, "true") == 0) {
                SensorCallbackImpl::printDataFlag = true;
            } else {
                SensorCallbackImpl::printDataFlag = false;
            }
        }
        const char* testTestTime = std::getenv("testTestTime");
        if (testTestTime) {
            printf("testTestTime=%s\n", testTestTime);
            g_testTime = std::atoi(testTestTime);
        }
        const char* testTestTime2 = std::getenv("testTestTime2");
        if (testTestTime2) {
            printf("testTestTime2=%s\n", testTestTime2);
            g_testTime2 = std::atoi(testTestTime2);
        }
    }

    std::string SensorSetBatchTest::ExecShellCommand(const std::string& command)
    {
        SENSOR_TRACE;
        std::string result = "";
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) {
            std::cerr << "Error: Failed to execute command: " << command << std::endl;
            return "";
        }

        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }

        int return_code = pclose(pipe);
        if (return_code != 0) {
            std::cerr << "Warning: Command '" << command << "' returned non-zero exit code: " << return_code << std::endl;
        }
        result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
        result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());

        printf("now execute %s result = %s\n", command.c_str(), result.c_str());

        return result;
    }

    std::string SensorSetBatchTest::ExecShellCommandTenTimes(const std::string& command)
    {
        SENSOR_TRACE;
        for (int i = 0; i < 10; ++i) {
            std::string result = ExecShellCommand(command);
        }

        return "";
    }

    void SensorSetBatchTest::TearDownTestCase()
    {
    }

    void SensorSetBatchTest::SetUp()
    {
    }

    void SensorSetBatchTest::TearDown()
    {
    }

    /**
     * @tc.name: SensorSetBatchTest1
     * @tc.desc: Get a client and check whether the client is empty.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, SensorSetBatchTest1, TestSize.Level1)
    {
        SENSOR_TRACE;
        int32_t ret = g_sensorInterface->Register(0, g_traditionalCallback);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->SetBatch(g_deviceSensorInfo, g_samplingInterval, 0);
        printf("SetBatch({%s}, %s, 0)\n", SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo),
            std::to_string(g_samplingInterval).c_str());
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->Enable(g_deviceSensorInfo);
        EXPECT_EQ(ret, HDF_SUCCESS);

        int32_t expectedMinCount = 1000 / (g_samplingInterval / 1000000) / 2;
        int32_t expectedMaxCount = 1000 / (g_samplingInterval / 1000000) * 3 / 2;

        printf("expectedMinCount is %s, expectedMaxCount is %s\n", std::to_string(expectedMinCount).c_str(),
               std::to_string(expectedMaxCount).c_str());

        for (int i = 0; i < g_testTime / 1000; i++) {
            OsalMSleep(1000);
            int32_t countPerSecond = SensorCallbackImpl::sensorDataCount - SensorCallbackImpl::sensorDataCountOld;
            SensorCallbackImpl::sensorDataCountOld = SensorCallbackImpl::sensorDataCount;
            if (countPerSecond > expectedMinCount && countPerSecond < expectedMaxCount) {
                printf("\033[32mas expected, 1000ms get sensor data count is %d, sensorDataCount is %d\033[0m ",
                    countPerSecond, SensorCallbackImpl::sensorDataCount);
            } else {
                printf("\033[31m[ERROR] 1000ms get sensor data count is %d, sensorDataCount is %d\033[0m ",
                    countPerSecond, SensorCallbackImpl::sensorDataCount);
            }
            printf("please execute sensorhub dump.bat within %ld seconds\n", (g_testTime / 1000 - i));
            fflush(stdout);
        }
        printf("now execute cat /sys/class/sensors/sensorhub_dump\n");
        auto future = std::async(std::launch::async, ExecShellCommandTenTimes, "cat /sys/class/sensors/sensorhub_dump");
        OsalMSleep(1100);
        {
            HITRACE_METER_FMT(HITRACE_TAG_HDF, "Disable %s", __func__, SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo));
            printf("now execute g_sensorInterface->Disable\n");
            ret = g_sensorInterface->Disable(g_deviceSensorInfo);
            printf("now execute g_sensorInterface->Disable ret = %d\n", ret);
        }
        OsalMSleep(1000);
        ret = g_sensorInterface->SetBatch(g_deviceSensorInfo, g_samplingInterval, 0);
        printf("SetBatch({%s}, %s, 0)\n", SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo),
            std::to_string(g_samplingInterval).c_str());
        EXPECT_EQ(ret, HDF_SUCCESS);
        for (int i = 0; i < g_testTime2 / 1000; i++) {
            OsalMSleep(1000);
            int32_t countPerSecond = SensorCallbackImpl::sensorDataCount - SensorCallbackImpl::sensorDataCountOld;
            SensorCallbackImpl::sensorDataCountOld = SensorCallbackImpl::sensorDataCount;
            if (countPerSecond > expectedMinCount && countPerSecond < expectedMaxCount) {
                printf("\033[32mas expected, 1000ms get sensor data count is %d, sensorDataCount is %d\033[0m ",
                    countPerSecond, SensorCallbackImpl::sensorDataCount);
            } else {
                printf("\033[31m[ERROR] 1000ms get sensor data count is %d, sensorDataCount is %d\033[0m ",
                    countPerSecond, SensorCallbackImpl::sensorDataCount);
            }
            printf("The script will end in %ld seconds.\n", (g_testTime2 / 1000 - i));
            fflush(stdout);
        }
        ret = g_sensorInterface->Unregister(0, g_traditionalCallback);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}