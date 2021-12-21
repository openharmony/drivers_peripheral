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
#include "sensor_interface_proxy.h"
#include "sensor_type.h"
#include "sensor_callback_service.h"

using namespace hdi::sensor::v1_0;
using namespace testing::ext;

namespace {
    sptr<ISensorInterface>  g_sensorInterface = nullptr;
    sptr<ISensorCallback> g_callback = new SensorCallbackService();
    struct SensorValueRange {
        float highThreshold;
        float lowThreshold;
    };

    struct SensorDevelopmentList {
        int32_t sensorTypeId;
        char sensorName[SENSOR_NAME_MAX_LEN];
        int32_t dataForm;    // 0: fixed, 1: range
        int32_t dataDimension;
        struct SensorValueRange *valueRange;
    };

    static struct SensorValueRange g_testRange[] = {{1e5, 0}};
    static struct SensorValueRange g_accelRange[] = {{78, -78}, {78, -78}, {78, -78}};
    static struct SensorValueRange g_alsRange[] = {{10000, 0}, {10000, 0}, {10000, 0}, {10000, 0}};
    static struct SensorValueRange g_proximityRange[] = {{5, 0}};
    static struct SensorValueRange g_hallRange[] = {{1, 0}};
    static struct SensorValueRange g_barometerRange[] = {{1100, -1100}, {1100, -1100}};
    static struct SensorValueRange g_magneticRange[] = {{35, -35}, {35, -35}, {35, -35}};
    static struct SensorValueRange g_gyroscopeRange[] = {{2000, -2000}, {2000, -2000}, {2000, -2000}};
    static struct SensorValueRange g_gravityRange[] = {{78, -78}, {78, -78}, {78, -78}};

    static struct SensorDevelopmentList g_sensorList[] = {
        {SENSOR_TYPE_NONE, "sensor_test",  1, 1, g_testRange},
        {SENSOR_TYPE_ACCELEROMETER, "accelerometer",  1, 3, g_accelRange},
        {SENSOR_TYPE_PROXIMITY, "proximity",  0, 1, g_proximityRange},
        {SENSOR_TYPE_HALL, "hallrometer",  0, 1, g_hallRange},
        {SENSOR_TYPE_BAROMETER, "barometer",  1, 2, g_barometerRange},
        {SENSOR_TYPE_AMBIENT_LIGHT, "als", 1, 4, g_alsRange},
        {SENSOR_TYPE_MAGNETIC_FIELD, "magnetometer",  1, 3, g_magneticRange},
        {SENSOR_TYPE_GYROSCOPE, "gyroscope", 1, 3, g_gyroscopeRange},
        {SENSOR_TYPE_GRAVITY, "gravity", 1, 3, g_gravityRange}
    };

    static int g_listNum = sizeof(g_sensorList) / sizeof(g_sensorList[0]);
    const int32_t SENSOR_ID = 0;
    const int32_t SENSOR_INTERVAL = 200000000;
    const int32_t SENSOR_POLL_TIME = 1;
    const int32_t SENSOR_WAIT_TIME = 400;
}

class HdfSensorHdiTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfSensorHdiTest::SetUpTestCase()
{
    g_sensorInterface = ISensorInterface::Get();
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
  * @tc.name: GetSensorClient0001
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, GetSensorClient0001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_sensorInterface);
}

/**
  * @tc.name: GetSensorList0001
  * @tc.desc: Obtains information about all sensors in the system.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, GetSensorList0001, TestSize.Level1)
{
    std::vector<HdfSensorInformation> info;
    int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);

    printf("get sensor list num[%d]\n\r", info.size());

    for (auto iter : info) {
        int j =0;
        printf("get sensoriId[%d], info name[%s], power[%f]\n\r", iter.sensorId, iter.sensorName.c_str(), iter.power);
        for (; j < g_listNum; ++j) {
            if (iter.sensorId == g_sensorList[j].sensorTypeId) {
                EXPECT_STREQ(g_sensorList[j].sensorName, iter.sensorName.c_str());
                break;
            }
        }

        if (j == g_listNum) {
            EXPECT_NE(g_listNum, j);
            printf("%s: The sensor ID[%d] does not match. Please check the use case or the reported sensor ID",
            __func__, iter.sensorId);
        }
    }
}

/**
  * @tc.name: EnableSensor0001
  * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, EnableSensor0001, TestSize.Level1)
{
    int32_t ret = g_sensorInterface->Register(0, g_callback);
    EXPECT_EQ(0, ret);

    std::vector<HdfSensorInformation> info;
    ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);

    if (info.size()==0) {
        return;
    }

    for (auto iter : info) {
        ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL, SENSOR_POLL_TIME);
        EXPECT_EQ(0, ret);
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(0, ret);
        OsalSleep(SENSOR_POLL_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(0, ret);
    }
    ret = g_sensorInterface->Unregister(0);
    EXPECT_EQ(0, ret);
}

/**
  * @tc.name: EnableSensor0002
  * @tc.desc: Enables the sensor available in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, EnableSensor0002, TestSize.Level1)
{
    std::vector<HdfSensorInformation> info;
    int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);
    ret = g_sensorInterface->Enable(-1);
    EXPECT_EQ(-2, ret);
    ret = g_sensorInterface->Disable(-1);
    EXPECT_EQ(-2, ret);
}

/**
  * @tc.name: SetSensorBatch0001
  * @tc.desc: Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorBatch0001, TestSize.Level1)
{
    std::vector<HdfSensorInformation> info;
    int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);

    for (auto iter : info) {
        ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL, SENSOR_POLL_TIME);
        EXPECT_EQ(0, ret);
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(0, ret);
        OsalSleep(SENSOR_POLL_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(0, ret);
    }
}

/** @tc.name: SetSensorBatch0002
    @tc.desc: Sets the sampling time and data report interval for sensors in batches.
    @tc.type: FUNC
    @tc.requrire: #I4L3LF
    */
HWTEST_F(HdfSensorHdiTest, SetSensorBatch0002, TestSize.Level1)
{
    std::vector<HdfSensorInformation> info;
    int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);
    ret = g_sensorInterface->SetBatch(-1, 0, 0);
    EXPECT_EQ(-2, ret);
}

/**
  * @tc.name: SetSensorMode0001
  * @tc.desc: Sets the data reporting mode for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorMode0001, TestSize.Level1)
{
    std::vector<HdfSensorInformation> info;
    int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);
    for (auto iter : info)
    {
        ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL, SENSOR_POLL_TIME);
        EXPECT_EQ(0, ret);
        if (iter.sensorId == SENSOR_TYPE_HALL) {
            ret = g_sensorInterface->SetMode(iter.sensorId, SENSOR_MODE_ON_CHANGE);
            EXPECT_EQ(0, ret);
        } else {
            ret = g_sensorInterface->SetMode(iter.sensorId, SENSOR_MODE_REALTIME);
            EXPECT_EQ(0, ret);
        }
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(0, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(0, ret);
    }
}

/**
  * @tc.name: SetSensorMode0002
  * @tc.desc: Sets the data reporting mode for the specified sensor.The current real-time polling mode is valid.
  * Other values are invalid.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorMode0002, TestSize.Level1)
{
    std::vector<HdfSensorInformation> info;
    int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);
    for (auto iter : info)
    {
        ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL, SENSOR_POLL_TIME);
        EXPECT_EQ(0, ret);
        ret = g_sensorInterface->SetMode(iter.sensorId, SENSOR_MODE_DEFAULT);
        EXPECT_EQ(-1, ret);
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(0, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(0, ret);
    }
}

/**
  * @tc.name: SetSensorOption0001
  * @tc.desc: Sets options for the specified sensor, including its measurement range and accuracy.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorOption0001, TestSize.Level1)
{
    std::vector<HdfSensorInformation> info;
    int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
    EXPECT_EQ(0, ret);
    ret = g_sensorInterface->SetBatch(SENSOR_ID, SENSOR_INTERVAL, SENSOR_POLL_TIME);
    EXPECT_EQ(0, ret);
    ret = g_sensorInterface->SetOption(SENSOR_ID, 0);
    EXPECT_EQ(0, ret);
    ret = g_sensorInterface->Enable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    OsalMSleep(SENSOR_WAIT_TIME);
    ret = g_sensorInterface->Disable(SENSOR_ID);
    EXPECT_EQ(0, ret);
    ret = g_sensorInterface->Unregister();
    EXPECT_EQ(0, ret);
}
