/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "sensor_if.h"
#include "sensor_type.h"

using namespace testing::ext;

namespace {
    int32_t g_sensorDataFlag = 0;
    const int32_t SENSOR_ID = 0;
    const int32_t SENSOR_INTERVAL = 200000000;
    const int32_t SENSOR_POLL_TIME = 1;
    const int32_t SENSOR_WAIT_TIME = 400;
    const int32_t SENSOR_AXISZ = 2;
    const struct SensorInterface *g_sensorDev = nullptr;

    int SensorTestDataCallback(const struct SensorEvents *event)
    {
        if (event == nullptr || event->data == nullptr) {
            return -1;
        }

        float *data = (float*)event->data;
        int32_t *hallData = (int32_t*)event->data;
        if (event->sensorId == 0) {
            printf("sensor id [%d] data [%f]\n\r", event->sensorId, *(data));
            if (fabs(*data) > 1e-5) {
                g_sensorDataFlag = 1;
            }
        } else if (event->sensorId == 1) {
            printf("sensor id [%d] x-[%f] y-[%f] z-[%f]\n\r",
                event->sensorId, (*data), *(data + 1), *(data + SENSOR_AXISZ));
            if (fabs(*data) > 1e-5) {
                g_sensorDataFlag = 1;
            }
        } else if (event->sensorId == SENSOR_TYPE_BAROMETER) {
            printf("sensor id [%d] barometer[%f] temperature[%f] \n\r",
                event->sensorId, (*data), *(data + 1));
            if (fabs(*data) > 1e-5) {
                g_sensorDataFlag = 1;
            }
        } else if (event->sensorId == SENSOR_TYPE_HALL) {
            printf("sensor id [%d] hall-[%d] \n\r",
                event->sensorId, (*hallData));
            if (*hallData == 0 || *hallData == 1) {
                g_sensorDataFlag = 1;
            }
        }

        return 0;
    }
}

class HdfSensorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfSensorTest::SetUpTestCase()
{
    g_sensorDev = NewSensorInterfaceInstance();
    if (g_sensorDev == nullptr) {
        printf("test sensorHdi get Module instance failed\n\r");
    }
}

void HdfSensorTest::TearDownTestCase()
{
    if (g_sensorDev != nullptr) {
        FreeSensorInterfaceInstance();
        g_sensorDev = nullptr;
    }
}

void HdfSensorTest::SetUp()
{
}

void HdfSensorTest::TearDown()
{
}

/**
  * @tc.name: GetSensorInstance001
  * @tc.desc: Create a sensor instance and check whether the instance is empty.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869N, AR000F8QNL
  */
HWTEST_F(HdfSensorTest, GetSensorInstance001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_sensorDev);
    const struct SensorInterface *sensorDev = NewSensorInterfaceInstance();
    EXPECT_EQ(sensorDev, g_sensorDev);
}

/**
  * @tc.name: RemoveSensorInstance001
  * @tc.desc: The sensor instance is successfully removed.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869O, AR000F8QNL
  */
HWTEST_F(HdfSensorTest, RemoveSensorInstance001, TestSize.Level1)
{
    int32_t ret = FreeSensorInterfaceInstance();
    ASSERT_EQ(0, ret);
    ret = FreeSensorInterfaceInstance();
    EXPECT_EQ(0, ret);
    g_sensorDev = NewSensorInterfaceInstance();
    if (g_sensorDev == nullptr) {
        printf("test sensorHdi get Module instance failed\n\r");
        ASSERT_EQ(0, ret);
    }
}

/**
  * @tc.name: RegisterDataCb001
  * @tc.desc: Returns 0 if the callback is successfully registered; returns a negative value otherwise.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869P, AR000F8QNL
  */
HWTEST_F(HdfSensorTest, RegisterSensorDataCb001, TestSize.Level1)
{
    int32_t ret = g_sensorDev->Register(SensorTestDataCallback);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Unregister();
    EXPECT_EQ(0, ret); 
}

/**
  * @tc.name: RegisterDataCb002
  * @tc.desc: Returns 0 if the callback is successfully registered; returns a negative value otherwise.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869P
  */
HWTEST_F(HdfSensorTest, RegisterSensorDataCb002, TestSize.Level1)
{
    int32_t ret = g_sensorDev->Register(nullptr);
    EXPECT_EQ(SENSOR_NULL_PTR, ret);
    ret = g_sensorDev->Unregister();
    EXPECT_EQ(0, ret);
}

/**
  * @tc.name: GetSensorList001
  * @tc.desc: Obtains information about all sensors in the system. Validity check of input parameters.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869Q
  */
HWTEST_F(HdfSensorTest, GetSensorList001, TestSize.Level1)
{   
    struct SensorInformation *sensorInfo = nullptr;
    struct SensorInformation *info = nullptr;
    struct SensorInformation *testSensorInfo = nullptr;
    struct SensorInformation *accelSensorInfo = nullptr;
    struct SensorInformation *barometerSensorInfo = nullptr;
    struct SensorInformation *hallSensorInfo = nullptr;
    int32_t count = 0;
    
    int32_t ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);

    if (sensorInfo == nullptr) {
        EXPECT_NE(nullptr, sensorInfo);
        return;
    }
    printf("get sensor list num[%d]\n\r", count);
    info = sensorInfo;
    testSensorInfo = sensorInfo;
    accelSensorInfo = sensorInfo;
    barometerSensorInfo = sensorInfo;
    hallSensorInfo = sensorInfo;

    for (int i = 0; i < count; i++) {
        printf("get sensoriId[%d], info name[%s], power[%f]\n\r", info->sensorId, info->sensorName, info->power);
        if (info->sensorId == 0) {
            testSensorInfo = info;
        } else if (info->sensorId == 1) {
            accelSensorInfo = info;
        } else if (info->sensorId == SENSOR_TYPE_BAROMETER) {
            barometerSensorInfo = info;
        } else if (info->sensorId == SENSOR_TYPE_HALL) {
            hallSensorInfo = info;
        }
        info++;
        if (testSensorInfo->sensorTypeId == 0) {
            EXPECT_STREQ("sensor_test", testSensorInfo->sensorName);
            EXPECT_STREQ("default", testSensorInfo->vendorName);
        }
        if (accelSensorInfo->sensorTypeId == 1) {
            EXPECT_STREQ("accelerometer", accelSensorInfo->sensorName);
        }
        if (barometerSensorInfo->sensorTypeId == SENSOR_TYPE_BAROMETER) {
            EXPECT_STREQ("barometer", barometerSensorInfo->sensorName);
        }
        if (hallSensorInfo->sensorTypeId == SENSOR_TYPE_HALL) {
            EXPECT_STREQ("hallrometer", hallSensorInfo->sensorName);
        }
    }
}

/**
  * @tc.name: GetSensorList002
  * @tc.desc: Obtains information about all sensors in the system. The operations include obtaining sensor information,
  * subscribing to or unsubscribing from sensor data, enabling or disabling a sensor,
  * setting the sensor data reporting mode, and setting sensor options such as the accuracy and measurement range.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869Q
  */
HWTEST_F(HdfSensorTest, GetSensorList002, TestSize.Level1)
{
    struct SensorInformation *sensorInfo = nullptr;
    int32_t count = 0;
    
    int32_t ret = g_sensorDev->GetAllSensors(nullptr, &count);
    EXPECT_EQ(SENSOR_NULL_PTR, ret);
    ret = g_sensorDev->GetAllSensors(&sensorInfo, nullptr);
    EXPECT_EQ(SENSOR_NULL_PTR, ret);
    ret = g_sensorDev->GetAllSensors(nullptr, nullptr);
    EXPECT_EQ(SENSOR_NULL_PTR, ret); 
}

/**
  * @tc.name: EnableSensor001
  * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869R, AR000F8QNL
  */
HWTEST_F(HdfSensorTest, EnableSensor001, TestSize.Level1)
{
    int32_t ret = g_sensorDev->Register(SensorTestDataCallback);
    EXPECT_EQ(0, ret);

    struct SensorInformation *sensorInfo = nullptr;
    struct SensorInformation *info = nullptr;
    int32_t count = 0;

    ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);

    if (sensorInfo == nullptr) {
        EXPECT_NE(nullptr, sensorInfo);
        return;
    }

    info = sensorInfo;
    for (int i = 0; i < count; i++) {
        ret = g_sensorDev->SetBatch(SENSOR_ID, SENSOR_INTERVAL, SENSOR_POLL_TIME);
        EXPECT_EQ(0, ret);
        ret = g_sensorDev->Enable(info->sensorId);
        EXPECT_EQ(0, ret);
        OsalSleep(SENSOR_POLL_TIME);
        ret = g_sensorDev->Disable(info->sensorId);
        EXPECT_EQ(0, ret);
        info++;
    }
    ret = g_sensorDev->Unregister();
    EXPECT_EQ(0, ret);
}

/**
  * @tc.name: EnableSensor002
  * @tc.desc: Enables the sensor available in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869R
  */
HWTEST_F(HdfSensorTest, EnableSensor002, TestSize.Level1)
{  
    struct SensorInformation *sensorInfo = nullptr;
    int32_t count = 0;
    int32_t ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Enable(-1);
    EXPECT_EQ(-2, ret);
    ret = g_sensorDev->Disable(-1);
    EXPECT_EQ(-2, ret);
}

/**
  * @tc.name: SetSensorBatch001
  * @tc.desc: Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869T
  */
HWTEST_F(HdfSensorTest, SetSensorBatch001, TestSize.Level1)
{
    struct SensorInformation *sensorInfo = nullptr;
    int32_t count = 0;
    
    int32_t ret = g_sensorDev->Register(SensorTestDataCallback);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->SetBatch(SENSOR_ID, SENSOR_INTERVAL, SENSOR_POLL_TIME);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Enable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    OsalMSleep(SENSOR_WAIT_TIME);
    ret = g_sensorDev->Disable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Unregister();
    EXPECT_EQ(0, ret);
}

/** @tc.name: SetSensorBatch002
    @tc.desc: Sets the sampling time and data report interval for sensors in batches.
    @tc.type: FUNC
    @tc.requrire: SR000F869M, AR000F869U
    */
HWTEST_F(HdfSensorTest, SetSensorBatch002, TestSize.Level1)
{
    struct SensorInformation *sensorInfo = nullptr;
    int32_t count = 0;
    
    int32_t ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->SetBatch(-1, 0, 0);
    EXPECT_EQ(-2, ret);   
}

/**
  * @tc.name: SetSensorMode001
  * @tc.desc: Sets the data reporting mode for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869U, AR000F8QNL
  */
HWTEST_F(HdfSensorTest, SetSensorMode001, TestSize.Level1)
{
    struct SensorInformation *sensorInfo = nullptr;
    int32_t count = 0;

    int32_t ret = g_sensorDev->Register(SensorTestDataCallback);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->SetBatch(SENSOR_ID, SENSOR_INTERVAL, SENSOR_POLL_TIME);
    EXPECT_EQ(0, ret);
    if (SENSOR_ID == SENSOR_TYPE_HALL) {
        ret = g_sensorDev->SetMode(SENSOR_ID, SENSOR_MODE_ON_CHANGE);
        EXPECT_EQ(0, ret);
    } else {
        ret = g_sensorDev->SetMode(SENSOR_ID, SENSOR_MODE_REALTIME);
        EXPECT_EQ(0, ret);
    }
    ret = g_sensorDev->Enable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    OsalMSleep(SENSOR_WAIT_TIME);
    ret = g_sensorDev->Disable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Unregister();
    EXPECT_EQ(0, ret);
}

/**
  * @tc.name: SetSensorMode002
  * @tc.desc: Sets the data reporting mode for the specified sensor.The current real-time polling mode is valid.
  * Other values are invalid.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869U
  */
HWTEST_F(HdfSensorTest, SetSensorMode002, TestSize.Level1)
{
    struct SensorInformation *sensorInfo = nullptr;
    int32_t count = 0;

    int32_t ret = g_sensorDev->Register(SensorTestDataCallback);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->SetBatch(SENSOR_ID, SENSOR_INTERVAL, SENSOR_POLL_TIME);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->SetMode(SENSOR_ID, SENSOR_MODE_DEFAULT);
    EXPECT_EQ(-1, ret);
    ret = g_sensorDev->Enable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    OsalMSleep(SENSOR_WAIT_TIME);
    ret = g_sensorDev->Disable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Unregister();
    EXPECT_EQ(0, ret);
}

/**
  * @tc.name: SetSensorOption001
  * @tc.desc: Sets options for the specified sensor, including its measurement range and accuracy.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869U
  */
HWTEST_F(HdfSensorTest, SetSensorOption001, TestSize.Level1)
{
    struct SensorInformation *sensorInfo = nullptr;
    int32_t count = 0;

    int32_t ret = g_sensorDev->Register(SensorTestDataCallback);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->GetAllSensors(&sensorInfo, &count);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->SetBatch(SENSOR_ID, SENSOR_INTERVAL, SENSOR_POLL_TIME);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->SetOption(SENSOR_ID, 0);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Enable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    OsalMSleep(SENSOR_WAIT_TIME);
    ret = g_sensorDev->Disable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    ret = g_sensorDev->Unregister();
    EXPECT_EQ(0, ret);
}