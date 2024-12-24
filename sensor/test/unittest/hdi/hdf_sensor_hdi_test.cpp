/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "v2_0/isensor_interface.h"
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_callback_impl_test.h"
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"

using namespace OHOS::HDI::Sensor::V2_0;
using namespace testing::ext;

namespace {
    sptr<ISensorInterface>  g_sensorInterface = nullptr;
    sptr<V2_0::ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    sptr<V2_0::ISensorCallback> g_traditionalCallbackTest = new SensorCallbackImplTest();
    sptr<V2_0::ISensorCallback> g_medicalCallback = new SensorCallbackImpl();
    std::vector<HdfSensorInformation> g_info;
    std::vector<HdfSensorEvents> g_events;
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

    struct SensorValueRange g_testRange[] = {{1e5, 0}};
    struct SensorValueRange g_accelRange[] = {{78, -78}, {78, -78}, {78, -78}};
    struct SensorValueRange g_alsRange[] = {{10000000, 0}};
    struct SensorValueRange g_pedometerRange[] = {{10000, 0}};
    struct SensorValueRange g_proximityRange[] = {{5, 0}};
    struct SensorValueRange g_hallRange[] = {{2, 0}};
    struct SensorValueRange g_barometerRange[] = {{1100, -1100}, {1100, -1100}};
    struct SensorValueRange g_magneticRange[] = {{2000, -2000}, {2000, -2000}, {2000, -2000}};
    struct SensorValueRange g_gyroscopeRange[] = {{35, -35}, {35, -35}, {35, -35}};
    struct SensorValueRange g_gravityRange[] = {{78, -78}, {78, -78}, {78, -78}};
    struct SensorValueRange g_humidityRange[] = {{100, 0}};
    struct SensorValueRange g_temperatureRange[] = {{125, -40}};

    struct SensorDevelopmentList g_sensorList[] = {
        {SENSOR_TYPE_NONE, "sensor_test",  1, 1, g_testRange},
        {SENSOR_TYPE_ACCELEROMETER, "accelerometer",  1, 3, g_accelRange},
        {SENSOR_TYPE_PEDOMETER, "pedometer", 1, 1, g_pedometerRange},
        {SENSOR_TYPE_PROXIMITY, "proximity",  0, 1, g_proximityRange},
        {SENSOR_TYPE_HALL, "hallrometer",  1, 1, g_hallRange},
        {SENSOR_TYPE_BAROMETER, "barometer",  1, 2, g_barometerRange},
        {SENSOR_TYPE_AMBIENT_LIGHT, "als", 1, 1, g_alsRange},
        {SENSOR_TYPE_MAGNETIC_FIELD, "magnetometer",  1, 3, g_magneticRange},
        {SENSOR_TYPE_GYROSCOPE, "gyroscope", 1, 3, g_gyroscopeRange},
        {SENSOR_TYPE_GRAVITY, "gravity", 1, 3, g_gravityRange},
        {SENSOR_TYPE_HUMIDITY, "humidity", 1, 1, g_humidityRange},
        {SENSOR_TYPE_TEMPERATURE, "tenperature", 1, 1, g_temperatureRange}
    };

    constexpr int g_listNum = sizeof(g_sensorList) / sizeof(g_sensorList[0]);
    constexpr int64_t SENSOR_INTERVAL1 = 200000000;
    constexpr int64_t SENSOR_INTERVAL2 = 20000000;
    constexpr int64_t SENSOR_INTERVAL3 = 40000000;
    constexpr int64_t SENSOR_INTERVAL4 = 20000000;
    constexpr int32_t SENSOR_POLL_TIME = 1;
    constexpr int32_t SENSOR_WAIT_TIME = 100;
    constexpr int32_t SENSOR_WAIT_TIME2 = 1000;
    constexpr int32_t ABNORMAL_SENSORID = -1;
    constexpr int32_t RATE_LEVEL = 50;
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
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->GetAllSensorInfo(g_info);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    EXPECT_GT(g_info.size(), 0);
    printf("get sensor list num[%zu]\n\r", g_info.size());

    for (auto iter : g_info) {
        printf("get sensoriId[%d], info name[%s], power[%f]\n\r", iter.sensorId, iter.sensorName.c_str(), iter.power);
        for (int j =0; j < g_listNum; ++j) {
            if (iter.sensorId == g_sensorList[j].sensorTypeId) {
                EXPECT_GT(iter.sensorName.size(), 0);
                break;
            }
        }
    }
}

/**
  * @tc.name: RegisterSensorDataCb0001
  * @tc.desc: Returns 0 if the callback is successfully registered; returns a negative value otherwise.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869P, AR000F8QNL
  */
HWTEST_F(HdfSensorHdiTest, RegisterSensorDataCb0001, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

/**
  * @tc.name: RegisterSensorDataCb0002
  * @tc.desc: Returns 0 if the callback is successfully registered; returns a negative value otherwise.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869P, AR000F8QNL
  */
HWTEST_F(HdfSensorHdiTest, RegisterSensorDataCb0002, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->Register(MEDICAL_SENSOR_TYPE, g_medicalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Unregister(MEDICAL_SENSOR_TYPE, g_medicalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

/**
  * @tc.name: RegisterDataCb001
  * @tc.desc: Returns 0 if the callback is successfully registered; returns a negative value otherwise.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869P, AR000F8QNL
  */
HWTEST_F(HdfSensorHdiTest, RegisterSensorDataCb0003, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->Register(SENSOR_GROUP_TYPE_MAX, g_medicalCallback);
    EXPECT_EQ(SENSOR_INVALID_PARAM, ret);
    ret = g_sensorInterface->Unregister(SENSOR_GROUP_TYPE_MAX, g_medicalCallback);
    EXPECT_EQ(SENSOR_INVALID_PARAM, ret);
}

/**
  * @tc.name: EnableSensor0001
  * @tc.desc: Enables the sensor unavailable in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, EnableSensor0001, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_GT(g_info.size(), 0);

    for (auto iter : g_info) {
        ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

/**
  * @tc.name: EnableSensor0002
  * @tc.desc: Enables the sensor available in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF #I8FJ2I
  */
HWTEST_F(HdfSensorHdiTest, EnableSensor0002, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->Enable(ABNORMAL_SENSORID);
    EXPECT_EQ(SENSOR_NOT_SUPPORT, ret);
    ret = g_sensorInterface->Disable(ABNORMAL_SENSORID);
    EXPECT_EQ(SENSOR_NOT_SUPPORT, ret);
}

/**
  * @tc.name: SetSensorBatch0001
  * @tc.desc: Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorBatch0001, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    for (auto iter : g_info) {
        ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL2, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

/** @tc.name: SetSensorBatch0002
    @tc.desc: Sets the sampling time and data report interval for sensors in batches.
    @tc.type: FUNC
    @tc.requrire: #I4L3LF
    */
HWTEST_F(HdfSensorHdiTest, SetSensorBatch0002, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->SetBatch(ABNORMAL_SENSORID, 0, 0);
    EXPECT_EQ(SENSOR_NOT_SUPPORT, ret);
}

/**
  * @tc.name: SetSensorBatch0003
  * @tc.desc: Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorBatch0003, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->SetBatch(iter.sensorId, -1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_INVALID_PARAM, ret);
    }
}

/**
  * @tc.name: SetSensorMode0001
  * @tc.desc: Sets the data reporting mode for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorMode0001, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        if (iter.sensorId == SENSOR_TYPE_HALL) {
            ret = g_sensorInterface->SetMode(iter.sensorId, SENSOR_MODE_ON_CHANGE);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        } else {
            ret = g_sensorInterface->SetMode(iter.sensorId, SENSOR_MODE_REALTIME);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
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
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->SetMode(ABNORMAL_SENSORID, SENSOR_MODE_REALTIME);
    EXPECT_EQ(SENSOR_NOT_SUPPORT, ret);
}

/**
  * @tc.name: SetSensorMode0003
  * @tc.desc: Sets the data reporting mode for the specified sensor.The current real-time polling mode is valid.
  * Other values are invalid.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorMode0003, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->SetBatch(iter.sensorId, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->SetMode(iter.sensorId, SENSOR_MODE_DEFAULT);
        EXPECT_EQ(SENSOR_FAILURE, ret);
        ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
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
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->SetOption(iter.sensorId, 0);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
}

/**
  * @tc.name: SetSensorOption0002
  * @tc.desc: Sets options for the specified sensor, including its measurement range and accuracy.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSensorOption0002, TestSize.Level1)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret = g_sensorInterface->SetOption(ABNORMAL_SENSORID, 0);
    EXPECT_EQ(SENSOR_NOT_SUPPORT, ret);
}

/**
  * @tc.name: ReadSensorData0001
  * @tc.desc: Read event data for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, ReadSensorData0001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_sensorInterface);

    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->ReadData(iter.sensorId, g_events);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
}

/**
  * @tc.name: SetSdcSensor
  * @tc.desc: Read event data for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSdcSensor, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_sensorInterface);

    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->SetSdcSensor(iter.sensorId, true, RATE_LEVEL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        OsalMSleep(SENSOR_WAIT_TIME);
        ret = g_sensorInterface->SetSdcSensor(iter.sensorId, false, RATE_LEVEL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
}

/**
  * @tc.name: GetSdcSensorInfo
  * @tc.desc: Read event data for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, GetSdcSensorInfo, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_sensorInterface);

    EXPECT_GT(g_info.size(), 0);
    std::vector<OHOS::HDI::Sensor::V2_0::SdcSensorInfo> sdcSensorInfo;
    int32_t ret = g_sensorInterface->GetSdcSensorInfo(sdcSensorInfo);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    std::string infoMsg = "[";
    for (auto it : sdcSensorInfo) {
        if (infoMsg != "[") {
            infoMsg += ", ";
        }
        infoMsg += "{";
        infoMsg += "offset = " + std::to_string(it.offset) + ", ";
        infoMsg += "sensorId = " + std::to_string(it.sensorId) + ", ";
        infoMsg += "ddrSize = " + std::to_string(it.ddrSize) + ", ";
        infoMsg += "minRateLevel = " + std::to_string(it.minRateLevel) + ", ";
        infoMsg += "maxRateLevel = " + std::to_string(it.maxRateLevel) + ", ";
        infoMsg += "memAddr = " + std::to_string(it.memAddr) + ", ";
        infoMsg += "reserved = " + std::to_string(it.reserved);
        infoMsg += "}";
    }
    infoMsg += "]";
    HDF_LOGI("%{public}s: sdcSensorInfo = %{public}s", __func__, infoMsg.c_str());
}

/**
  * @tc.name: ReportFrequencyTest0001
  * @tc.desc: Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, ReportFrequencyTest0001, TestSize.Level1)
{
    HDF_LOGI("enter the ReportFrequencyTest0001 function");
    ASSERT_NE(nullptr, g_sensorInterface);

    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_GT(g_info.size(), 0);
    int32_t sensorId = g_info[0].sensorId;
    HDF_LOGI("sensorId is %{public}d", sensorId);

    ret = g_sensorInterface->SetBatch(sensorId, SENSOR_INTERVAL1, SENSOR_INTERVAL1);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorInterface->Enable(sensorId);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    OsalMSleep(SENSOR_WAIT_TIME2);

    ret = g_sensorInterface->Disable(sensorId);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

/**
  * @tc.name: ReportFrequencyTest0002
  * @tc.desc: Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, ReportFrequencyTest0002, TestSize.Level1)
{
    HDF_LOGI("enter the ReportFrequencyTest0002 function");
    ASSERT_NE(nullptr, g_sensorInterface);

    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_GT(g_info.size(), 0);
    int32_t sensorId = g_info[0].sensorId;
    HDF_LOGI("sensorId is %{public}d", sensorId);

    ret = g_sensorInterface->SetBatch(sensorId, SENSOR_INTERVAL3, SENSOR_INTERVAL1);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorInterface->Enable(sensorId);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    OsalMSleep(SENSOR_WAIT_TIME2);

    ret = g_sensorInterface->Disable(sensorId);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

/**
  * @tc.name: ReportFrequencyTest0003
  * @tc.desc: Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, ReportFrequencyTest0003, TestSize.Level1)
{
    HDF_LOGI("enter the ReportFrequencyTest0003 function");
    ASSERT_NE(nullptr, g_sensorInterface);

    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_GT(g_info.size(), 0);
    int32_t sensorId = g_info[0].sensorId;
    HDF_LOGI("sensorId is %{public}d", sensorId);

    ret = g_sensorInterface->SetBatch(sensorId, SENSOR_INTERVAL4, SENSOR_INTERVAL1);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorInterface->Enable(sensorId);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    OsalMSleep(SENSOR_WAIT_TIME2);

    ret = g_sensorInterface->Disable(sensorId);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

/**
  * @tc.name: SetSdcSensor_001
  * @tc.desc: Read event data for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SetSdcSensor_001, TestSize.Level1)
{
    SENSOR_TRACE;
    HDF_LOGI("enter the SetSdcSensor_001 function");
    ASSERT_NE(nullptr, g_sensorInterface);
    int32_t ret;
    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        ret = g_sensorInterface->SetSdcSensor(iter.sensorId, true, RATE_LEVEL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->SetSdcSensor(iter.sensorId, false, RATE_LEVEL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
}

/**
  * @tc.name: EnableButUnregisterTest
  * @tc.desc: Read event data for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, EnableButUnregisterTest, TestSize.Level1)
{
    SENSOR_TRACE;
    ASSERT_NE(nullptr, g_sensorInterface);
    HDF_LOGI("enter the EnableButUnregisterTest function");

    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    OsalMSleep(SENSOR_WAIT_TIME2);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
}

/**
  * @tc.name: SensorCallbackImplFailureTest
  * @tc.desc: Read event data for the specified sensor.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorHdiTest, SensorCallbackImplFailureTest, TestSize.Level1)
{
    SENSOR_TRACE;
    ASSERT_NE(nullptr, g_sensorInterface);
    HDF_LOGI("enter the SensorCallbackImplFailureTest function");

    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallbackTest);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    EXPECT_GT(g_info.size(), 0);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->Enable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
    OsalMSleep(SENSOR_WAIT_TIME2);
    for (auto iter : g_info) {
        int32_t ret = g_sensorInterface->Disable(iter.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }
    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}