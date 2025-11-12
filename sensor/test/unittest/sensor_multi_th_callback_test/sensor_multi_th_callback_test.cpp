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
#include "hdf_base.h"
#include "osal_time.h"
#include "v3_0/isensor_interface.h"
#include "v3_1/isensor_interface.h"
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_callback_impl2.h"
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"
#include <thread>

using namespace OHOS::HDI::Sensor::V3_1;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;
int32_t SensorCallbackImpl::sensorDataCount = 0;
int32_t SensorCallbackImpl::sensorDataCountOld = 0;
bool SensorCallbackImpl::printDataFlag = false;
int32_t SensorCallbackImpl2::sensorDataCount = 0;
int32_t SensorCallbackImpl2::sensorDataCountOld = 0;
bool SensorCallbackImpl2::printDataFlag = false;

namespace {
    DeviceSensorInfo g_deviceSensorInfo = {-1, 1, 0, 1};
    DeviceSensorInfo g_deviceSensorInfo2 = {-1, 2, 0, 1};
    int64_t g_samplingInterval = 10000000; // 10ms
    int64_t g_samplingInterval2 = 20000000; // 20ms
    int64_t g_testTime = 5000; // 5s
    int64_t g_oneSecond = 1000; // 1s
    int64_t g_oneMillion = 1000000;
    int32_t g_two = 2;

    class SensorSetBatchTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
        static void CallbackTest1();
        static void CallbackTestPerSecond1();
        static void CallbackTest2();
        static void CallbackTestPerSecond2();
    };

    void SensorSetBatchTest::SetUpTestCase()
    {
        const char* testSensorType = std::getenv("testSensorType");
        const char* testSensorType2 = std::getenv("testSensorType2");
        if (testSensorType && testSensorType2) {
            printf("testSensorType=%s\r\n", testSensorType);
            printf("testSensorType2=%s\r\n", testSensorType2);
            g_deviceSensorInfo.sensorType = std::atoi(testSensorType);
            g_deviceSensorInfo2.sensorType = std::atoi(testSensorType2);
        }
        const char* testSamplingInterval = std::getenv("testSamplingInterval");
        if (testSamplingInterval) {
            printf("testSamplingInterval=%s\r\n", testSamplingInterval);
            g_samplingInterval = std::atoi(testSamplingInterval);
            g_samplingInterval2 = g_samplingInterval * g_two;
        }
        const char* testPrintDataFlag = std::getenv("testPrintDataFlag");
        if (testPrintDataFlag) {
            printf("testPrintDataFlag=%s\r\n", testPrintDataFlag);
            if (std::strcmp(testPrintDataFlag, "true") == 0) {
                SensorCallbackImpl::printDataFlag = true;
                SensorCallbackImpl2::printDataFlag = true;
            } else {
                SensorCallbackImpl::printDataFlag = false;
                SensorCallbackImpl2::printDataFlag = false;
            }
        }
        const char* testTestTime = std::getenv("testTestTime");
        if (testTestTime) {
            printf("testTestTime=%s\r\n", testTestTime);
            g_testTime = std::atoi(testTestTime);
        }
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

    void SensorSetBatchTest::CallbackTestPerSecond1()
    {
        int32_t expectedMinCount = g_oneSecond / (g_samplingInterval / g_oneMillion) / 2;
        int32_t expectedMaxCount = g_oneSecond / (g_samplingInterval / g_oneMillion) * 3 / 2;
        printf("\033[92mCallback1 expectedMinCount is %s, expectedMaxCount is %s\033[0m\r\n",
            std::to_string(expectedMinCount).c_str(), std::to_string(expectedMaxCount).c_str());

        for (int i = 0; i < g_testTime / g_oneSecond; i++) {
            OsalMSleep(g_oneSecond);
            int32_t countPerSecond = SensorCallbackImpl::sensorDataCount - SensorCallbackImpl::sensorDataCountOld;
            SensorCallbackImpl::sensorDataCountOld = SensorCallbackImpl::sensorDataCount;
            if (countPerSecond > expectedMinCount && countPerSecond < expectedMaxCount) {
                printf("\033[92mCallback1, as expected, 1000ms get sensor %s data count is %d, sensorDataCount is "
                    "%d\033[0m\r\n",
                    SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo), countPerSecond, SensorCallbackImpl::sensorDataCount);
            } else {
                printf("\033[91mCallback1, [ERROR] 1000ms get sensor %s data count is %d, sensorDataCount is "
                    "%d\033[0m\r\n",
                    SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo), countPerSecond, SensorCallbackImpl::sensorDataCount);
            }
            fflush(stdout);
        }
    }

    void SensorSetBatchTest::CallbackTest1()
    {
        sptr<V3_1::ISensorInterface>  g_sensorInterface = V3_1::ISensorInterface::Get();
        sptr<V3_0::ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
        int32_t callbackId1 = GPS_CALLBACK_ID_BEGIN;
        int32_t ret = g_sensorInterface->RegisterWithCallbackId(0, g_traditionalCallback, callbackId1);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->SetBatchWithCallbackId(g_deviceSensorInfo, callbackId1, g_samplingInterval, 0);
        printf("\033[92mCallback1 SetBatch({%s}, %s, 0)\033[0m\r\n", SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo),
            std::to_string(g_samplingInterval).c_str());
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->EnableWithCallbackId(g_deviceSensorInfo, callbackId1);
        EXPECT_EQ(ret, HDF_SUCCESS);
        CallbackTestPerSecond1();

        ret = g_sensorInterface->DisableWithCallbackId(g_deviceSensorInfo, callbackId1);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->UnregisterWithCallbackId(0, g_traditionalCallback, callbackId1);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }

    void SensorSetBatchTest::CallbackTestPerSecond2()
    {
        int32_t expectedMinCount2 = g_oneSecond / (g_samplingInterval2 / g_oneMillion) / 2;
        int32_t expectedMaxCount2 = g_oneSecond / (g_samplingInterval2 / g_oneMillion) * 3 / 2;
        printf("\033[94mexpectedMinCount2 is %s, expectedMaxCount2 is %s\033[0m\r\n",
            std::to_string(expectedMinCount2).c_str(), std::to_string(expectedMaxCount2).c_str());

        for (int i = 0; i < g_testTime / g_oneSecond; i++) {
            OsalMSleep(g_oneSecond);
            int32_t countPerSecond2 = SensorCallbackImpl2::sensorDataCount - SensorCallbackImpl2::sensorDataCountOld;
            SensorCallbackImpl2::sensorDataCountOld = SensorCallbackImpl2::sensorDataCount;
            if (countPerSecond2 > expectedMinCount2 && countPerSecond2 < expectedMaxCount2) {
                printf("\033[94mCallback2, as expected, 1000ms get sensor data %s count is %d, sensorDataCount is "
                    "%d\033[0m\r\n",
                    SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo), countPerSecond2, SensorCallbackImpl2::sensorDataCount);
            } else {
                printf("\033[91mCallback2, [ERROR] 1000ms get sensor data %s count is %d, sensorDataCount is "
                    "%d\033[0m\r\n",
                    SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo), countPerSecond2, SensorCallbackImpl2::sensorDataCount);
            }
            fflush(stdout);
        }
    }

    void SensorSetBatchTest::CallbackTest2()
    {
        sptr<V3_1::ISensorInterface>  g_sensorInterface = V3_1::ISensorInterface::Get();
        sptr<V3_0::ISensorCallback> g_traditionalCallback2 = new SensorCallbackImpl2();
        int32_t callbackId2 = GPS_CALLBACK_ID_BEGIN + 1;
        int32_t ret = g_sensorInterface->RegisterWithCallbackId(0, g_traditionalCallback2, callbackId2);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->SetBatchWithCallbackId(g_deviceSensorInfo, callbackId2, g_samplingInterval2, 0);
        printf("\033[94mCallback2 SetBatch({%s}, %s, 0)\033[0m\r\n", SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo),
            std::to_string(g_samplingInterval2).c_str());
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->EnableWithCallbackId(g_deviceSensorInfo, callbackId2);
        EXPECT_EQ(ret, HDF_SUCCESS);
        CallbackTestPerSecond2();

        ret = g_sensorInterface->DisableWithCallbackId(g_deviceSensorInfo, callbackId2);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->UnregisterWithCallbackId(0, g_traditionalCallback2, callbackId2);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    
    /**
     * @tc.name: SensorSetBatchTest1
     * @tc.desc: Get a client and check whether the client is empty.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, SensorSetBatchTest1, TestSize.Level1)
    {
        std::thread t1(CallbackTest1);
        std::thread t2(CallbackTest2);

        t1.join();
        t2.join();
    }
}