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
#include <gtest/gtest.h>
#include <securec.h>
#include "hdf_base.h"
#include "osal_time.h"
#include "v3_0/isensor_interface.h"
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_callback_impl_test.h"
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"

using namespace OHOS::HDI::Sensor::V3_0;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;

namespace {
    class HdfSensorHdiTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void HdfSensorHdiTest::SetUpTestCase()
    {
    }

    void HdfSensorHdiTest::TearDownTestCase()
    {
    }

    void HdfSensorHdiTest::SetUp()
    {
    }

    void HdfSensorHdiTest::TearDown()
    {
    }

    /**
     * @tc.name: TestSensorInterface
     * @tc.desc: Get a client and check whether the client is empty.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, TestSensorInterface, TestSize.Level1)
    {
        sptr<V3_0::ISensorInterface>  sensorInterface = V3_0::ISensorInterface::Get();
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_ACCELEROMETER
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_ACCELEROMETER, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_ACCELEROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_GYROSCOPE
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_GYROSCOPE, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_GYROSCOPE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_PHOTOPLETHYSMOGRAPH
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_PHOTOPLETHYSMOGRAPH, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_PHOTOPLETHYSMOGRAPH, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_ELECTROCARDIOGRAPH
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_ELECTROCARDIOGRAPH, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_ELECTROCARDIOGRAPH, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_AMBIENT_LIGHT
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_AMBIENT_LIGHT, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_AMBIENT_LIGHT, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_MAGNETIC_FIELD
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_MAGNETIC_FIELD, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_MAGNETIC_FIELD, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_CAPACITIVE
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_CAPACITIVE, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_CAPACITIVE, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
    
    /**
     * @tc.name: EnableSensor_HDF_SENSOR_TYPE_BAROMETER
     * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(HdfSensorHdiTest, EnableSensor_HDF_SENSOR_TYPE_BAROMETER, TestSize.Level1)
    {
        if (g_sensorInterface == nullptr) {
            ASSERT_NE(nullptr, g_sensorInterface);
            return;
        }
        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        DeviceSensorInfo deviceSensorInfo = {DEFAULT_DEVICE_ID,
            HDF_SENSOR_TYPE_BAROMETER, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(0, ret);
        EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
        SensorCallbackImpl::sensorDataFlag = 1;
    }
}