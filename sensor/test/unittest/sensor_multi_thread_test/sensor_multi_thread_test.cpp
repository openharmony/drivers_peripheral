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
    std::vector<std::vector<SubscribedSensor>> g_subscribedSensors{
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        },
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        },
    };

    std::vector<std::vector<SubscribedSensor>> g_subscribedSensors1{
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        },
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        },
    };

    std::vector<std::vector<SubscribedSensor>> g_subscribedSensors2{
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        },
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        },
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
        },
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
        },
        {
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
            {
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
        },
    };

    std::vector<std::vector<SubscribedSensor>> g_subscribedSensors3{
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {10*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {20*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {30*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {40*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {50*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {60*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {70*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {80*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {90*ONE_MILLION, 0}
            },
        },
        {
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
                {DEFAULT_DEVICE_ID, HDF_SENSOR_TYPE_GRAVITY, DEFAULT_SENSOR_ID, DEFAULT_LOCATION},
                {100*ONE_MILLION, 0}
            },
        },
    };

    int32_t g_oneSecond = 1000;
    int32_t g_testTime = 10000;
    float g_minMultiple = 0.5f;
    float g_maxMultiple = 1.5f;
    class SensorSetBatchTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
        static void TestGetSensorDatas(std::vector<std::vector<SubscribedSensor>> subscribedSensors);
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
            it.expectedMinCount = g_oneSecond / (it.sensorInterval.samplingInterval / ONE_MILLION) * g_minMultiple;
            it.expectedMaxCount = g_oneSecond / (it.sensorInterval.samplingInterval / ONE_MILLION) * g_maxMultiple;
        }
        for (int i = 0; i < g_testTime / g_oneSecond; i++) {
            OsalMSleep(g_oneSecond);
            for (auto& it : sensorCallbackImpl->subscribedSensors) {
                int32_t countPerSecond = it.sensorDataCount - it.sensorDataCountOld;
                it.sensorDataCountOld = it.sensorDataCount;
                if (countPerSecond > it.expectedMinCount && countPerSecond < it.expectedMaxCount) {
                    printf("\033[92mCallbackId %d, as expected, 1000ms get sensor %s data count is %d,"
                        " between (%d~%d) samplingInterval is %d, sensorDataCount is %d\033[0m\r\n",
                        sensorCallbackImpl->callbackId,
                        SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), countPerSecond,
                        it.expectedMinCount, it.expectedMaxCount,
                        (int32_t)(it.sensorInterval.samplingInterval / ONE_MILLION), it.sensorDataCount);
                } else {
                    printf("\033[91mCallbackId %d, [ERROR] 1000ms get sensor %s data count is %d,"
                        " between (%d~%d) samplingInterval is %d, sensorDataCount is %d\033[0m\r\n",
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

    /**
     * @tc.name: TestGetSensorDataCase1
     * @tc.desc:2个线程，每个线程分别2个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase1, TestSize.Level1)
    {
        TestGetSensorDatas(g_subscribedSensors1);
    }

    /**
     * @tc.name: TestGetSensorDataCase2
     * @tc.desc: 5个线程，不重复传感器：每个线程调用2个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase2, TestSize.Level1)
    {
        TestGetSensorDatas(g_subscribedSensors2);
    }

    /**
     * @tc.name: TestGetSensorDataCase3
     * @tc.desc: 10个线程，多重复传感器，每个线程调用4个传感器.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, TestGetSensorDataCase3, TestSize.Level1)
    {
        TestGetSensorDatas(g_subscribedSensors3);
    }
}