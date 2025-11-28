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
namespace {
    int32_t g_oneSecond = 1000;
    int32_t g_testTime = 10000;
    class SensorSetBatchTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
        static void TestGetSensorData(int threadId, std::vector<SubscribedSensor> subscribedSensors);
        static void PerSecond(sptr<SensorCallbackImpl> sensorCallbackImpl);
    };

    void SensorSetBatchTest::SetUpTestCase()
    {
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
            it.expectedMinCount = g_oneSecond / (it.sensorInterval.samplingInterval / ONE_MILLION) / 2;
            it.expectedMaxCount = g_oneSecond / (it.sensorInterval.samplingInterval / ONE_MILLION) * 3 / 2;
            printf("\033[92mcallbackId %d {%s} expectedMinCount is %s, expectedMaxCount is %s\033[0m\r\n",
                sensorCallbackImpl->callbackId, SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo),
                std::to_string(it.expectedMinCount).c_str(), std::to_string(it.expectedMaxCount).c_str());
        }
        for (int i = 0; i < g_testTime / g_oneSecond; i++) {
            OsalMSleep(g_oneSecond);
            for (auto& it : sensorCallbackImpl->subscribedSensors) {
                int32_t countPerSecond = it.sensorDataCount - it.sensorDataCountOld;
                it.sensorDataCountOld = it.sensorDataCount;
                if (countPerSecond > it.expectedMinCount && countPerSecond < it.expectedMaxCount) {
                    printf("\033[92mCallbackId %d, as expected, 1000ms get sensor %s data count is %d, sensorDataCount is "
                        "%d\033[0m\r\n", sensorCallbackImpl->callbackId,
                        SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), countPerSecond, it.sensorDataCount);
                } else {
                    printf("\033[91mCallbackId %d, [ERROR] 1000ms get sensor %s data count is %d, sensorDataCount is "
                        "%d\033[0m\r\n", sensorCallbackImpl->callbackId,
                        SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), countPerSecond, it.sensorDataCount);
                }
                fflush(stdout);
            }
        }
    }

    void SensorSetBatchTest::TestGetSensorData(int threadId, std::vector<SubscribedSensor> subscribedSensors)
    {
        sptr<V3_1::ISensorInterface>  sensorInterface = V3_1::ISensorInterface::Get();
        sptr<SensorCallbackImpl> sensorCallbackImpl = new SensorCallbackImpl();
        sensorCallbackImpl->subscribedSensors = subscribedSensors;

        int32_t callbackId = GPS_CALLBACK_ID_BEGIN + threadId;
        sensorCallbackImpl->callbackId = callbackId;
        printf("RegisterWithCallbackId(sensorCallbackImpl, %d)\r\n", callbackId);
        int32_t ret = sensorInterface->RegisterWithCallbackId(0, sensorCallbackImpl, callbackId);
        EXPECT_EQ(ret, HDF_SUCCESS);
        for (auto it : subscribedSensors) {
            printf("SetBatchWithCallbackId({%s}, %d, %s, %s)\r\n",
                SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId,
                std::to_string(it.sensorInterval.samplingInterval / ONE_MILLION).c_str(),
                std::to_string(it.sensorInterval.reportInterval / ONE_MILLION).c_str());
            ret = sensorInterface->SetBatchWithCallbackId(it.deviceSensorInfo, callbackId,
                it.sensorInterval.samplingInterval, it.sensorInterval.reportInterval);
            EXPECT_EQ(ret, HDF_SUCCESS);
            printf("EnableWithCallbackId({%s}, %d)\r\n",
                SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId);
            ret = sensorInterface->EnableWithCallbackId(it.deviceSensorInfo, callbackId);
            EXPECT_EQ(ret, HDF_SUCCESS);
        }
        PerSecond(sensorCallbackImpl);
        for (auto it : subscribedSensors) {
            printf("DisableWithCallbackId({%s}, %d)\r\n",
                SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), callbackId);
            ret = sensorInterface->DisableWithCallbackId(it.deviceSensorInfo, callbackId);
            EXPECT_EQ(ret, HDF_SUCCESS);
        }
        printf("UnregisterWithCallbackId(sensorCallbackImpl, %d)\r\n", callbackId);
        ret = sensorInterface->UnregisterWithCallbackId(0, sensorCallbackImpl, callbackId);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }

    /**
     * @tc.name: TestGetSensorDataCase
     * @tc.desc: 2个线程，每个线程分别1个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase, TestSize.Level1)
    {
        std::vector<SubscribedSensor> subscribedSensors{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors1{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        };

        std::thread t(TestGetSensorData, 0, subscribedSensors);
        std::thread t1(TestGetSensorData, 1, subscribedSensors1);

        t.join();
        t1.join();
    }

    /**
     * @tc.name: TestGetSensorDataCase1
     * @tc.desc:2个线程，每个线程分别2个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase1, TestSize.Level1)
    {
        std::vector<SubscribedSensor> subscribedSensors{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors1{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        };

        std::thread t(TestGetSensorData, 0, subscribedSensors);
        std::thread t1(TestGetSensorData, 1, subscribedSensors1);

        t.join();
        t1.join();
    }

    /**
     * @tc.name: TestGetSensorDataCase2
     * @tc.desc: 5个线程，不重复传感器：每个线程调用2个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase2, TestSize.Level1)
    {
        std::vector<SubscribedSensor> subscribedSensors{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors1{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors2{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors3{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors4{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
        };

        std::thread t(TestGetSensorData, 0, subscribedSensors);
        std::thread t1(TestGetSensorData, 1, subscribedSensors1);
        std::thread t2(TestGetSensorData, 2, subscribedSensors2);
        std::thread t3(TestGetSensorData, 3, subscribedSensors3);
        std::thread t4(TestGetSensorData, 4, subscribedSensors4);

        t.join();
        t1.join();
        t2.join();
        t3.join();
        t4.join();
    }

    /**
     * @tc.name: TestGetSensorDataCase3
     * @tc.desc: 10个线程，多重复传感器，每个线程调用4个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase3, TestSize.Level1)
    {
        std::vector<SubscribedSensor> subscribedSensors{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors1{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors2{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors3{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors4{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors5{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {60*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {60*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {60*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {60*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors6{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {70*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {70*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {70*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {70*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors7{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {80*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {80*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {80*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {80*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors8{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {90*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {90*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {90*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {90*ONE_MILLION, 0}
            },
        };
        std::vector<SubscribedSensor> subscribedSensors9{
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {100*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {100*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {100*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {100*ONE_MILLION, 0}
            },
        };

        std::thread t(TestGetSensorData, 0, subscribedSensors);
        std::thread t1(TestGetSensorData, 1, subscribedSensors1);
        std::thread t2(TestGetSensorData, 2, subscribedSensors2);
        std::thread t3(TestGetSensorData, 3, subscribedSensors3);
        std::thread t4(TestGetSensorData, 4, subscribedSensors4);
        std::thread t5(TestGetSensorData, 5, subscribedSensors5);
        std::thread t6(TestGetSensorData, 6, subscribedSensors6);
        std::thread t7(TestGetSensorData, 7, subscribedSensors7);
        std::thread t8(TestGetSensorData, 8, subscribedSensors8);
        std::thread t9(TestGetSensorData, 9, subscribedSensors9);

        t.join();
        t1.join();
        t2.join();
        t3.join();
        t4.join();
        t5.join();
        t6.join();
        t7.join();
        t8.join();
        t9.join();
    }
}