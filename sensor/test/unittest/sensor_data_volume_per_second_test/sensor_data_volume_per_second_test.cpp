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
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"

using namespace OHOS::HDI::Sensor::V3_0;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;
int32_t SensorCallbackImpl::sensorDataCount = 0;
bool SensorCallbackImpl::printDataFlag = false;

namespace {
    sptr<V3_0::ISensorInterface>  g_sensorInterface = nullptr;
    sptr<V3_0::ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    DeviceSensorInfo g_deviceSensorInfo = {-1, 1, 0, 1};
    int64_t g_samplingInterval = 10000000; // 10ms
    int64_t g_testTime = 5; // 5s

    class SensorSetBatchTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void SensorSetBatchTest::SetUpTestCase()
    {
        g_sensorInterface = V3_0::ISensorInterface::Get();
        const char* testSensorType = std::getenv("testSensorType");
        if (testSensorType) {
            printf("testSensorType=%s\r\n", testSensorType);
            g_deviceSensorInfo.sensorType = std::atoi(testSensorType);
        }
        const char* testSamplingInterval = std::getenv("testSamplingInterval");
        if (testSamplingInterval) {
            printf("testSamplingInterval=%s\r\n", testSamplingInterval);
            g_samplingInterval = std::atoi(testSamplingInterval);
        }
        const char* testPrintDataFlag = std::getenv("testPrintDataFlag");
        if (testPrintDataFlag) {
            printf("testPrintDataFlag=%s\r\n", testPrintDataFlag);
            SensorCallbackImpl::printDataFlag = std::atoi(testPrintDataFlag);
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

    /**
     * @tc.name: SensorSetBatchTest1
     * @tc.desc: Get a client and check whether the client is empty.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, SensorSetBatchTest1, TestSize.Level1)
    {
        int32_t ret = g_sensorInterface->Register(0, g_traditionalCallback);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->SetBatch(g_deviceSensorInfo, g_samplingInterval, 0);
        printf("SetBatch({%s}, 100000000, 0)\r\n", SENSOR_HANDLE_TO_C_STR(g_deviceSensorInfo));
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->Enable(g_deviceSensorInfo);
        EXPECT_EQ(ret, HDF_SUCCESS);

        for (int i = 0; i < g_testTime / 1000; i++) {
            OsalMSleep(1000);
            if (SensorCallbackImpl::sensorDataCount > 10 && SensorCallbackImpl::sensorDataCount < 30) {
                printf("\033[32mas expected, 2000ms get sensor data count is %d\033[0m\r\n",
                    SensorCallbackImpl::sensorDataCount);
            } else {
                printf("\033[31m[ERROR] 2000ms get sensor data count is %d\033[0m\r\n",
                    SensorCallbackImpl::sensorDataCount);
            }
        }

        ret = g_sensorInterface->Disable(g_deviceSensorInfo);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->Unregister(0, g_traditionalCallback);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}