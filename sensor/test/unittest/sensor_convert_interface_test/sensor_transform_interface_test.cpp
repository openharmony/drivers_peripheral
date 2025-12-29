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
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"
#include <thread>

using namespace OHOS::HDI::Sensor::V3_1;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;

#ifdef COMMUNITY_TEST
#define TEST_MULTIPLE 4
#define TEST_SENSOR_TYPE HDF_SENSOR_TYPE_ACCELEROMETER
#else
#define TEST_MULTIPLE 1
#define TEST_SENSOR_TYPE HDF_SENSOR_TYPE_ORIENTATION
#endif

namespace {
    std::vector<std::vector<SubscribedSensor>> g_subscribedSensors{
        {
            {
                {DEFAULT_DEVICE_ID, TEST_SENSOR_TYPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION*TEST_MULTIPLE, 0}
            },
        },
    };

    int32_t g_oneSecond = 1000;
    int32_t g_testTime = 10000;
    float g_minMultiple = 0.5f;
    float g_maxMultiple = 1.5f;
    sptr<V3_1::ISensorInterface> g_sensorInterface = nullptr;
    std::vector<HdfSensorInformation> g_info;

    class SensorSetBatchTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
        static void TestGetSensorDatas(std::vector<std::vector<SubscribedSensor>> subscribedSensors);
        static void TestGetSensorData(int threadId, std::vector<SubscribedSensor> subscribedSensors);
        static void PerSecond(sptr<SensorCallbackImpl> sensorCallbackImpl);

        static bool IsSuppprtedSensor(DeviceSensorInfo deviceSensorInfo)
        {
            for (auto iter : g_info) {
                if (iter.deviceSensorInfo.deviceId == deviceSensorInfo.deviceId &&
                    iter.deviceSensorInfo.sensorType == deviceSensorInfo.sensorType &&
                    iter.deviceSensorInfo.sensorId == deviceSensorInfo.sensorId &&
                    iter.deviceSensorInfo.location == deviceSensorInfo.location) {
                    return true;
                }
            }
            return false;
        }
    };

    void SensorSetBatchTest::SetUpTestCase()
    {
        g_sensorInterface = V3_1::ISensorInterface::Get();
        if (g_sensorInterface != nullptr) {
            g_sensorInterface->GetAllSensorInfo(g_info);
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

    void SensorSetBatchTest::PerSecond(sptr<SensorCallbackImpl> sensorCallbackImpl)
    {
        for (auto& it : sensorCallbackImpl->subscribedSensors) {
            it.expectedMinCount = g_oneSecond / (it.sensorInterval.samplingInterval / ONE_MILLION) * g_minMultiple;
            it.expectedMaxCount = g_oneSecond / (it.sensorInterval.samplingInterval / ONE_MILLION) * g_maxMultiple;
        }
        for (int i = 0; i < g_testTime / g_oneSecond; i++) {
            OsalMSleep(g_oneSecond);
            for (auto& it : sensorCallbackImpl->subscribedSensors) {
                if (!IsSuppprtedSensor(it.deviceSensorInfo)) {
                    printf("\033[96m[  SKIPED  ] mcurrent device not support this sensor(%s, %d)\033[0m\n",
                        SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), sensorCallbackImpl->callbackId);
                    continue;
                }
                int32_t countPerSecond = it.sensorDataCount - it.sensorDataCountOld;
                it.sensorDataCountOld = it.sensorDataCount;
                if (countPerSecond >= it.expectedMinCount && countPerSecond <= it.expectedMaxCount) {
                    printf("\033[92m[       OK ] CallbackId %d, as expected, 1000ms get sensor %s data count is %d,"
                        " between (%d~%d) samplingInterval is %d, sensorDataCount is %d\033[0m\n",
                        sensorCallbackImpl->callbackId,
                        SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), countPerSecond,
                        it.expectedMinCount, it.expectedMaxCount,
                        (int32_t)(it.sensorInterval.samplingInterval / ONE_MILLION), it.sensorDataCount);
                } else {
                    printf("\033[91m[  FAILED  ] CallbackId %d, [ERROR] 1000ms get sensor %s data count is %d,"
                        " between (%d~%d) samplingInterval is %d, sensorDataCount is %d\033[0m\n",
                        sensorCallbackImpl->callbackId,
                        SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), countPerSecond,
                        it.expectedMinCount, it.expectedMaxCount,
                        (int32_t)(it.sensorInterval.samplingInterval / ONE_MILLION), it.sensorDataCount);
                }
                fflush(stdout);
            }
        }
    }

    void SensorSetBatchTest::TestGetSensorData(int threadId, std::vector<SubscribedSensor> subscribedSensors)
    {
        ASSERT_NE(nullptr, g_sensorInterface);
        sptr<SensorCallbackImpl> sensorCallbackImpl = new SensorCallbackImpl();
        sensorCallbackImpl->subscribedSensors = subscribedSensors;

        int32_t callbackId = GPS_CALLBACK_ID_BEGIN + threadId;
        sensorCallbackImpl->callbackId = callbackId;
        sensorCallbackImpl->sensorConvertInterfaces =
            OHOS::HDI::Sensor::Convert::V1_0::ISensorConvertInterfaces::Get(true);
        if (sensorCallbackImpl->sensorConvertInterfaces == nullptr) {
            printf("\033[96m[  SKIPED  ] sensorConvertInterfaces == nullptr\033[0m\n");
        }
        printf("RegisterWithCallbackId(sensorCallbackImpl, %d)\n", callbackId);
        int32_t ret = g_sensorInterface->RegisterWithCallbackId(0, sensorCallbackImpl, callbackId);
        EXPECT_EQ(ret, HDF_SUCCESS);
        for (auto it : subscribedSensors) {
            if (!IsSuppprtedSensor(it.deviceSensorInfo)) {
                printf("\033[96m[  SKIPED  ] mcurrent device not support this sensor(%s, %d)\033[0m\n",
                    SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId);
                continue;
            }
            printf("SetBatchWithCallbackId(%s, %d, %s, %s)\n",
                SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId,
                std::to_string(it.sensorInterval.samplingInterval / ONE_MILLION).c_str(),
                std::to_string(it.sensorInterval.reportInterval / ONE_MILLION).c_str());
            ret = g_sensorInterface->SetBatchWithCallbackId(it.deviceSensorInfo, callbackId,
                it.sensorInterval.samplingInterval, it.sensorInterval.reportInterval);
            EXPECT_EQ(ret, HDF_SUCCESS);
            printf("EnableWithCallbackId(%s, %d)\n",
                SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId);
            ret = g_sensorInterface->EnableWithCallbackId(it.deviceSensorInfo, callbackId);
            EXPECT_EQ(ret, HDF_SUCCESS);
        }
        PerSecond(sensorCallbackImpl);
        for (auto it : subscribedSensors) {
            if (!IsSuppprtedSensor(it.deviceSensorInfo)) {
                printf("\033[96m[  SKIPED  ] mcurrent device not support this sensor(%s, %d)\033[0m\n",
                    SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId);
                continue;
            }
            printf("DisableWithCallbackId(%s, %d)\n",
                SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId);
            ret = g_sensorInterface->DisableWithCallbackId(it.deviceSensorInfo, callbackId);
            EXPECT_EQ(ret, HDF_SUCCESS);
        }
        printf("UnregisterWithCallbackId(sensorCallbackImpl, %d)\n", callbackId);
        ret = g_sensorInterface->UnregisterWithCallbackId(0, sensorCallbackImpl, callbackId);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }

    void SensorSetBatchTest::TestGetSensorDatas(std::vector<std::vector<SubscribedSensor>> subscribedSensors)
    {
        std::vector<std::thread> threads;
        for (int i = 0; i < subscribedSensors.size(); i++) {
            std::thread t(TestGetSensorData, i, subscribedSensors[i]);
            threads.push_back(std::move(t));
        }
        for (int i = 0; i < threads.size(); i++) {
            threads[i].join();
        }
    }

    /**
     * @tc.name: TestGetSensorDataCase
     * @tc.desc: 2个线程，每个线程分别1个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase, TestSize.Level1)
    {
        TestGetSensorDatas(g_subscribedSensors);
    }
}