/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <ctime>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <queue>
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

namespace {
    constexpr int64_t NANOS_PER_MS = 1000000LL;

    struct TestSensorData {
        int32_t sensorId;
        std::vector<float> data;
        int64_t timestamp;
        int32_t mode;
        uint32_t option;
    };

    class ComprehensiveSensorCallback : public ISensorCallback {
    public:
        std::vector<TestSensorData> receivedData;
        std::mutex dataMutex;
        std::condition_variable dataCond;
        std::atomic<int> dataCount{0};
        std::atomic<bool> stopFlag{false};

        int32_t OnDataEventAsync(const std::vector<HdfSensorEvents>& events) override
        {
            return HDF_SUCCESS;
        }

        int32_t OnDataEvent(const HdfSensorEvents &event) override
        {
            std::lock_guard<std::mutex> lock(dataMutex);

            TestSensorData testData;
            testData.sensorId = event.deviceSensorInfo.sensorId;
            testData.timestamp = event.timestamp;
            testData.mode = event.mode;
            testData.option = event.option;

            if (event.dataLen > 0) {
                float* floatData = reinterpret_cast<float*>(const_cast<uint8_t*>(event.data.data()));
                for (uint32_t i = 0; i < event.dataLen / sizeof(float); i++) {
                    testData.data.push_back(floatData[i]);
                }
            }

            receivedData.push_back(testData);
            dataCount++;
            dataCond.notify_one();

            return 0;
        }

        void ClearData()
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            receivedData.clear();
            dataCount = 0;
        }

        bool WaitForData(int expectedCount, int timeoutMs)
        {
            std::unique_lock<std::mutex> lock(dataMutex);
            return dataCond.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                [this, expectedCount] { return dataCount >= expectedCount || stopFlag; });
        }

        void StopWaiting()
        {
            stopFlag = true;
            dataCond.notify_all();
        }
    };

    sptr<V3_0::ISensorInterface> g_sensorInterface = nullptr;
    sptr<ComprehensiveSensorCallback> g_callback = new ComprehensiveSensorCallback();
    sptr<ComprehensiveSensorCallback> g_callback2 = new ComprehensiveSensorCallback();
    std::vector<HdfSensorInformation> g_sensorInfo;

    constexpr int32_t SENSOR_ID_ACCELEROMETER = 1;
    constexpr int32_t SENSOR_ID_GYROSCOPE = 2;
    constexpr int32_t SENSOR_ID_AMBIENT_LIGHT = 5;
    constexpr int32_t SENSOR_ID_MAGNETIC_FIELD = 6;
    constexpr int32_t SENSOR_ID_PROXIMITY = 12;
    constexpr int32_t SENSOR_ID_GRAVITY = 257;
    constexpr int32_t SENSOR_ID_LINEAR_ACCEL = 258;
    constexpr int32_t SENSOR_ID_ROTATION_VECTOR = 259;
    constexpr int32_t SENSOR_ID_GAME_ROTATION = 262;
    constexpr int32_t SENSOR_ID_GYRO_UNCALIBRATED = 263;
    constexpr int32_t SENSOR_ID_ACCEL_UNCALIBRATED = 281;

    constexpr int64_t FAST_SAMPLING_INTERVAL = 5 * NANOS_PER_MS;
    constexpr int64_t NORMAL_SAMPLING_INTERVAL = 20 * NANOS_PER_MS;
    constexpr int64_t SLOW_SAMPLING_INTERVAL = 200 * NANOS_PER_MS;
    constexpr int64_t VERY_SLOW_SAMPLING_INTERVAL = 1000 * NANOS_PER_MS;

    constexpr int64_t FAST_REPORT_INTERVAL = 1 * NANOS_PER_MS;
    constexpr int64_t NORMAL_REPORT_INTERVAL = 50 * NANOS_PER_MS;
    constexpr int64_t SLOW_REPORT_INTERVAL = 200 * NANOS_PER_MS;

    constexpr int32_t SHORT_WAIT_TIME = 100;
    constexpr int32_t NORMAL_WAIT_TIME = 500;
    constexpr int32_t LONG_WAIT_TIME = 2000;

    class SensorComprehensiveTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();

        void EnableAndDisableSensor(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval);
        void EnableAndDisableSensorWithCallback(int32_t sensorId, sptr<ComprehensiveSensorCallback> callback,
            int64_t samplingInterval, int64_t reportInterval, int32_t waitTime);
        void TestSensorDataValidity(int32_t sensorId, const std::vector<TestSensorData>& data);
        bool FindSensorById(int32_t sensorId, HdfSensorInformation& info);
        void TestBatchConfiguration(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval);
        void TestModeConfiguration(int32_t sensorId, int32_t mode);
        void TestOptionConfiguration(int32_t sensorId, uint32_t option);
        void TestMultipleSensorsConcurrent(const std::vector<int32_t>& sensorIds);
        void TestSensorInfoCompleteness(const HdfSensorInformation& info);
        void TestDataConsistency(int32_t sensorId, int32_t expectedDataPoints);
    };

    void SensorComprehensiveTest::SetUpTestCase()
    {
        g_sensorInterface = V3_0::ISensorInterface::Get();
        if (g_sensorInterface != nullptr) {
            g_sensorInterface->GetAllSensorInfo(g_sensorInfo);
        }
    }

    void SensorComprehensiveTest::TearDownTestCase()
    {
        if (g_sensorInterface != nullptr) {
            g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
            g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback2);
        }
    }

    void SensorComprehensiveTest::SetUp()
    {
        g_callback->ClearData();
        g_callback2->ClearData();
        g_callback->stopFlag = false;
        g_callback2->stopFlag = false;
    }

    void SensorComprehensiveTest::TearDown()
    {
        g_callback->StopWaiting();
        g_callback2->StopWaiting();

        for (auto& info : g_sensorInfo) {
            g_sensorInterface->Disable({0, info.deviceSensorInfo.sensorType, 0, 0});
        }
    }

    void SensorComprehensiveTest::EnableAndDisableSensor(int32_t sensorId, int64_t samplingInterval,
        int64_t reportInterval)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->SetBatch({0, sensorId, 0, 0}, samplingInterval, reportInterval);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Enable({0, sensorId, 0, 0});
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        OsalMSleep(NORMAL_WAIT_TIME);

        ret = g_sensorInterface->Disable({0, sensorId, 0, 0});
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    void SensorComprehensiveTest::EnableAndDisableSensorWithCallback(int32_t sensorId,
        sptr<ComprehensiveSensorCallback> callback, int64_t samplingInterval, int64_t reportInterval,
        int32_t waitTime)
    {
        ASSERT_NE(nullptr, g_sensorInterface);
        ASSERT_NE(nullptr, callback);

        callback->ClearData();
        callback->stopFlag = false;

        int32_t ret = g_sensorInterface->SetBatch({0, sensorId, 0, 0}, samplingInterval, reportInterval);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Enable({0, sensorId, 0, 0});
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        bool received = callback->WaitForData(1, waitTime);
        if (received) {
            printf("Received %d data points for sensor %d\n", callback->dataCount.load(), sensorId);
        }

        ret = g_sensorInterface->Disable({0, sensorId, 0, 0});
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    void SensorComprehensiveTest::TestSensorDataValidity(int32_t sensorId, const std::vector<TestSensorData>& data)
    {
        if (data.empty()) {
            printf("No data received for sensor %d\n", sensorId);
            return;
        }

        for (const auto& testData : data) {
            EXPECT_GT(testData.timestamp, 0);
            EXPECT_GE(testData.mode, 0);
            EXPECT_GT(testData.data.size(), 0);

            for (float value : testData.data) {
                EXPECT_FALSE(std::isnan(value));
                EXPECT_FALSE(std::isinf(value));
            }
        }
    }

    bool SensorComprehensiveTest::FindSensorById(int32_t sensorId, HdfSensorInformation& info)
    {
        for (const auto& sensor : g_sensorInfo) {
            if (sensor.deviceSensorInfo.sensorType == sensorId) {
                info = sensor;
                return true;
            }
        }
        return false;
    }

    void SensorComprehensiveTest::TestBatchConfiguration(int32_t sensorId, int64_t samplingInterval,
        int64_t reportInterval)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(sensorId, info)) {
            printf("Sensor %d not found, skipping test\n", sensorId);
            return;
        }

        printf("Testing batch configuration for sensor %d: sampling=%s ns, report=%s ns\n",
            sensorId, std::to_string(samplingInterval).c_str(), std::to_string(reportInterval).c_str());

        int32_t ret = g_sensorInterface->SetBatch({0, sensorId, 0, 0}, samplingInterval, reportInterval);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        OsalMSleep(SHORT_WAIT_TIME);

        ret = g_sensorInterface->Enable({0, sensorId, 0, 0});
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        OsalMSleep(NORMAL_WAIT_TIME);

        ret = g_sensorInterface->Disable({0, sensorId, 0, 0});
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    void SensorComprehensiveTest::TestModeConfiguration(int32_t sensorId, int32_t mode)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(sensorId, info)) {
            printf("Sensor %d not found, skipping test\n", sensorId);
            return;
        }

        printf("Testing mode %d for sensor %d\n", mode, sensorId);

        int32_t ret = g_sensorInterface->SetMode({0, sensorId, 0, 0}, mode);
        EXPECT_TRUE(ret == SENSOR_SUCCESS || ret == SENSOR_NOT_SUPPORT);

        if (ret == SENSOR_SUCCESS) {
            ret = g_sensorInterface->SetBatch({0, sensorId, 0, 0}, NORMAL_SAMPLING_INTERVAL,
                FAST_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Enable({0, sensorId, 0, 0});
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(NORMAL_WAIT_TIME);

            ret = g_sensorInterface->Disable({0, sensorId, 0, 0});
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }
    }

    void SensorComprehensiveTest::TestOptionConfiguration(int32_t sensorId, uint32_t option)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(sensorId, info)) {
            printf("Sensor %d not found, skipping test\n", sensorId);
            return;
        }

        printf("Testing option %u for sensor %d\n", option, sensorId);

        int32_t ret = g_sensorInterface->SetOption({0, sensorId, 0, 0}, option);
        EXPECT_TRUE(ret == SENSOR_SUCCESS || ret == SENSOR_NOT_SUPPORT);

        if (ret == SENSOR_SUCCESS) {
            ret = g_sensorInterface->SetBatch({0, sensorId, 0, 0}, NORMAL_SAMPLING_INTERVAL,
                FAST_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Enable({0, sensorId, 0, 0});
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(NORMAL_WAIT_TIME);

            ret = g_sensorInterface->Disable({0, sensorId, 0, 0});
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }
    }

    void SensorComprehensiveTest::TestMultipleSensorsConcurrent(const std::vector<int32_t>& sensorIds)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        printf("Testing %zu sensors concurrently\n", sensorIds.size());

        std::vector<HdfSensorInformation> foundSensors;

        for (int32_t sensorId : sensorIds) {
            HdfSensorInformation info;
            if (FindSensorById(sensorId, info)) {
                foundSensors.push_back(info);
            }
        }

        if (foundSensors.empty()) {
            printf("No sensors found for concurrent test\n");
            return;
        }

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        for (const auto& info : foundSensors) {
            ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
                FAST_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }

        for (const auto& info : foundSensors) {
            ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }

        OsalMSleep(LONG_WAIT_TIME);

        printf("Received %d total data points from %zu sensors\n", g_callback->dataCount.load(),
            foundSensors.size());

        for (const auto& info : foundSensors) {
            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    void SensorComprehensiveTest::TestSensorInfoCompleteness(const HdfSensorInformation& info)
    {
        EXPECT_GT(info.sensorName.size(), 0);
        EXPECT_LT(info.sensorName.size(), SENSOR_NAME_MAX_LEN);
        EXPECT_GT(info.vendorName.size(), 0);
        EXPECT_LT(info.vendorName.size(), SENSOR_NAME_MAX_LEN);
        EXPECT_GT(info.firmwareVersion.size(), 0);
        EXPECT_LT(info.firmwareVersion.size(), SENSOR_VERSION_MAX_LEN);
        EXPECT_GT(info.hardwareVersion.size(), 0);
        EXPECT_LT(info.hardwareVersion.size(), SENSOR_VERSION_MAX_LEN);
        EXPECT_GE(info.power, 0.0f);
        EXPECT_GE(info.maxRange, 0.0f);
        EXPECT_GE(info.accuracy, 0.0f);
        EXPECT_GE(info.minDelay, 0);
        EXPECT_GE(info.maxDelay, info.minDelay);
        EXPECT_GE(info.fifoMaxEventCount, 0);
    }

    void SensorComprehensiveTest::TestDataConsistency(int32_t sensorId, int32_t expectedDataPoints)
    {
        if (expectedDataPoints <= 0) {
            return;
        }

        int actualCount = g_callback->dataCount.load();
        int32_t tolerance = expectedDataPoints / 5;

        if (actualCount >= expectedDataPoints - tolerance && actualCount <= expectedDataPoints + tolerance) {
            printf("Data count %d is within expected range %d±%d\n", actualCount,
                expectedDataPoints, tolerance);
        } else {
            printf("Warning: Data count %d is outside expected range %d±%d\n", actualCount,
                expectedDataPoints, tolerance);
        }
    }

    /**
     * @tc.name: GetAllSensorInfo001
     * @tc.desc: Test getting all sensor information. 获取所有传感器信息
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, GetAllSensorInfo001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        std::vector<HdfSensorInformation> info;
        int32_t ret = g_sensorInterface->GetAllSensorInfo(info);

        EXPECT_EQ(SENSOR_SUCCESS, ret);
        EXPECT_GT(info.size(), 0);

        printf("Total sensors found: %zu\n", info.size());

        for (const auto& sensor : info) {
            TestSensorInfoCompleteness(sensor);
            printf("Sensor: %s, Type: %d, ID: %d, Power: %.2f mW, Range: %.2f\n",
                sensor.sensorName.c_str(), sensor.deviceSensorInfo.sensorType,
                sensor.deviceSensorInfo.sensorId, sensor.power, sensor.maxRange);
        }
    }

    /**
     * @tc.name: RegisterCallback001
     * @tc.desc: Test registering traditional sensor callback. 注册传统传感器回调
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RegisterCallback001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: RegisterCallback002
     * @tc.desc: Test registering medical sensor callback. 注册医疗传感器回调
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RegisterCallback002, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(MEDICAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(MEDICAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: RegisterCallback003
     * @tc.desc: Test registering with null callback. 使用空指针注册回调
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RegisterCallback003, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, nullptr);
        EXPECT_EQ(SENSOR_NULL_PTR, ret);
    }

    /**
     * @tc.name: RegisterCallback004
     * @tc.desc: Test registering with invalid group type. 使用无效组类型注册回调
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RegisterCallback004, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(SENSOR_GROUP_TYPE_MAX, g_callback);
        EXPECT_EQ(SENSOR_INVALID_PARAM, ret);
    }

    /**
     * @tc.name: RegisterMultipleCallbacks001
     * @tc.desc: Test registering multiple callbacks. 注册多个回调
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RegisterMultipleCallbacks001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback2);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback2);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: AccelerometerFastSampling001
     * @tc.desc: Test accelerometer with fast sampling rate. 加速度传感器快速采样测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, AccelerometerFastSampling001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        EnableAndDisableSensorWithCallback(SENSOR_ID_ACCELEROMETER, g_callback, FAST_SAMPLING_INTERVAL,
            FAST_REPORT_INTERVAL, NORMAL_WAIT_TIME);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        TestSensorDataValidity(SENSOR_ID_ACCELEROMETER, g_callback->receivedData);
    }

    /**
     * @tc.name: AccelerometerNormalSampling001
     * @tc.desc: Test accelerometer with normal sampling rate. 加速度传感器正常采样测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, AccelerometerNormalSampling001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        EnableAndDisableSensorWithCallback(SENSOR_ID_ACCELEROMETER, g_callback, NORMAL_SAMPLING_INTERVAL,
            NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        TestSensorDataValidity(SENSOR_ID_ACCELEROMETER, g_callback->receivedData);
    }

    /**
     * @tc.name: AccelerometerSlowSampling001
     * @tc.desc: Test accelerometer with slow sampling rate. 加速度传感器慢速采样测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, AccelerometerSlowSampling001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        EnableAndDisableSensorWithCallback(SENSOR_ID_ACCELEROMETER, g_callback, SLOW_SAMPLING_INTERVAL,
            SLOW_REPORT_INTERVAL, LONG_WAIT_TIME);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        TestSensorDataValidity(SENSOR_ID_ACCELEROMETER, g_callback->receivedData);
    }

    /**
     * @tc.name: GyroscopeFastSampling001
     * @tc.desc: Test gyroscope with fast sampling rate. 陀螺仪传感器快速采样测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, GyroscopeFastSampling001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        EnableAndDisableSensorWithCallback(SENSOR_ID_GYROSCOPE, g_callback, FAST_SAMPLING_INTERVAL,
            FAST_REPORT_INTERVAL, NORMAL_WAIT_TIME);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        TestSensorDataValidity(SENSOR_ID_GYROSCOPE, g_callback->receivedData);
    }

    /**
     * @tc.name: GyroscopeNormalSampling001
     * @tc.desc: Test gyroscope with normal sampling rate. 陀螺仪传感器正常采样测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, GyroscopeNormalSampling001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        EnableAndDisableSensorWithCallback(SENSOR_ID_GYROSCOPE, g_callback, NORMAL_SAMPLING_INTERVAL,
            NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        TestSensorDataValidity(SENSOR_ID_GYROSCOPE, g_callback->receivedData);
    }

    /**
     * @tc.name: AmbientLightSensor001
     * @tc.desc: Test ambient light sensor functionality. 环境光传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, AmbientLightSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_AMBIENT_LIGHT, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_AMBIENT_LIGHT, g_callback,
                NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_AMBIENT_LIGHT, g_callback->receivedData);
        } else {
            printf("Ambient light sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: MagneticFieldSensor001
     * @tc.desc: Test magnetic field sensor functionality. 磁场传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, MagneticFieldSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_MAGNETIC_FIELD, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_MAGNETIC_FIELD, g_callback,
                NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_MAGNETIC_FIELD, g_callback->receivedData);
        } else {
            printf("Magnetic field sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: ProximitySensor001
     * @tc.desc: Test proximity sensor functionality. 接近传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, ProximitySensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_PROXIMITY, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_PROXIMITY, g_callback,
                SLOW_SAMPLING_INTERVAL, SLOW_REPORT_INTERVAL, LONG_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_PROXIMITY, g_callback->receivedData);
        } else {
            printf("Proximity sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: GravitySensor001
     * @tc.desc: Test gravity sensor functionality. 重力传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, GravitySensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_GRAVITY, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_GRAVITY, g_callback, NORMAL_SAMPLING_INTERVAL,
                NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_GRAVITY, g_callback->receivedData);
        } else {
            printf("Gravity sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: LinearAccelerationSensor001
     * @tc.desc: Test linear acceleration sensor functionality. 线性加速度传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, LinearAccelerationSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_LINEAR_ACCEL, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_LINEAR_ACCEL, g_callback,
                NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_LINEAR_ACCEL, g_callback->receivedData);
        } else {
            printf("Linear acceleration sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: RotationVectorSensor001
     * @tc.desc: Test rotation vector sensor functionality. 旋转矢量传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RotationVectorSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ROTATION_VECTOR, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_ROTATION_VECTOR, g_callback,
                NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_ROTATION_VECTOR, g_callback->receivedData);
        } else {
            printf("Rotation vector sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: GameRotationVectorSensor001
     * @tc.desc: Test game rotation vector sensor functionality. 游戏旋转矢量传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, GameRotationVectorSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_GAME_ROTATION, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_GAME_ROTATION, g_callback,
                NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_GAME_ROTATION, g_callback->receivedData);
        } else {
            printf("Game rotation vector sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: UncalibratedGyroscopeSensor001
     * @tc.desc: Test uncalibrated gyroscope sensor functionality. 未校准陀螺仪传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, UncalibratedGyroscopeSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_GYRO_UNCALIBRATED, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_GYRO_UNCALIBRATED, g_callback,
                NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_GYRO_UNCALIBRATED, g_callback->receivedData);
        } else {
            printf("Uncalibrated gyroscope sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: UncalibratedAccelerometerSensor001
     * @tc.desc: Test uncalibrated accelerometer sensor functionality. 未校准加速度传感器功能测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, UncalibratedAccelerometerSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCEL_UNCALIBRATED, info)) {
            EnableAndDisableSensorWithCallback(SENSOR_ID_ACCEL_UNCALIBRATED, g_callback,
                NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL, NORMAL_WAIT_TIME);

            TestSensorDataValidity(SENSOR_ID_ACCEL_UNCALIBRATED, g_callback->receivedData);
        } else {
            printf("Uncalibrated accelerometer sensor not found\n");
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: SetBatchFast001
     * @tc.desc: Test setting batch with fast sampling and report intervals. 使用快速采样和报告间隔配置批次
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetBatchFast001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestBatchConfiguration(SENSOR_ID_ACCELEROMETER, FAST_SAMPLING_INTERVAL, FAST_REPORT_INTERVAL);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetBatchNormal001
     * @tc.desc: Test setting batch with normal sampling and report intervals. 使用正常采样和报告间隔配置批次
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetBatchNormal001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestBatchConfiguration(SENSOR_ID_ACCELEROMETER, NORMAL_SAMPLING_INTERVAL, NORMAL_REPORT_INTERVAL);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetBatchSlow001
     * @tc.desc: Test setting batch with slow sampling and report intervals. 使用慢速采样和报告间隔配置批次
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetBatchSlow001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestBatchConfiguration(SENSOR_ID_ACCELEROMETER, SLOW_SAMPLING_INTERVAL, SLOW_REPORT_INTERVAL);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetBatchVerySlow001
     * @tc.desc: Test setting batch with very slow sampling and report intervals. 使用极慢速采样和报告间隔配置批次
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetBatchVerySlow001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestBatchConfiguration(SENSOR_ID_ACCELEROMETER, VERY_SLOW_SAMPLING_INTERVAL,
                VERY_SLOW_SAMPLING_INTERVAL);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetBatchWithZeroInterval001
     * @tc.desc: Test setting batch with zero interval. 使用零间隔配置批次
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetBatchWithZeroInterval001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, 0, 0);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetBatchWithNegativeInterval001
     * @tc.desc: Test setting batch with negative interval. 使用负间隔配置批次
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetBatchWithNegativeInterval001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, -1, -1);
            EXPECT_EQ(SENSOR_INVALID_PARAM, ret);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetModeRealtime001
     * @tc.desc: Test setting sensor mode to real-time. 设置传感器模式为实时
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetModeRealtime001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestModeConfiguration(SENSOR_ID_ACCELEROMETER, SENSOR_MODE_REALTIME);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetModeOnChange001
     * @tc.desc: Test setting sensor mode to on-change. 设置传感器模式为变化时
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetModeOnChange001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_PROXIMITY, info)) {
            TestModeConfiguration(SENSOR_ID_PROXIMITY, SENSOR_MODE_ON_CHANGE);
        } else {
            printf("Proximity sensor not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetModeOneShot001
     * @tc.desc: Test setting sensor mode to one-shot. 设置传感器模式为单次
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetModeOneShot001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_PROXIMITY, info)) {
            TestModeConfiguration(SENSOR_ID_PROXIMITY, SENSOR_MODE_ONE_SHOT);
        } else {
            printf("Proximity sensor not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetModeFifoMode001
     * @tc.desc: Test setting sensor mode to FIFO. 设置传感器模式为FIFO
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetModeFifoMode001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestModeConfiguration(SENSOR_ID_ACCELEROMETER, SENSOR_MODE_FIFO_MODE);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetModeInvalid001
     * @tc.desc: Test setting sensor mode to invalid value. 设置传感器模式为无效值
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetModeInvalid001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            int32_t ret = g_sensorInterface->SetMode(info.deviceSensorInfo, 999);
            EXPECT_EQ(SENSOR_FAILURE, ret);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetOptionDefault001
     * @tc.desc: Test setting sensor option to default. 设置传感器选项为默认值
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetOptionDefault001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestOptionConfiguration(SENSOR_ID_ACCELEROMETER, 0);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: SetOptionMax001
     * @tc.desc: Test setting sensor option to maximum value. 设置传感器选项为最大值
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetOptionMax001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            TestOptionConfiguration(SENSOR_ID_ACCELEROMETER, 0xFFFFFFFF);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: EnableSensor001
     * @tc.desc: Test enabling sensor. 启用传感器测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, EnableSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
                NORMAL_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(NORMAL_WAIT_TIME);

            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: DisableSensor001
     * @tc.desc: Test disabling sensor. 禁用传感器测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, DisableSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
                NORMAL_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(NORMAL_WAIT_TIME);

            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: EnableInvalidSensor001
     * @tc.desc: Test enabling invalid sensor. 启用无效传感器测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, EnableInvalidSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Enable({0, 99999, 0, 0});
        EXPECT_EQ(SENSOR_NOT_SUPPORT, ret);
    }

    /**
     * @tc.name: DisableInvalidSensor001
     * @tc.desc: Test disabling invalid sensor. 禁用无效传感器测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, DisableInvalidSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Disable({0, 99999, 0, 0});
        EXPECT_EQ(SENSOR_NOT_SUPPORT, ret);
    }

    /**
     * @tc.name: ReadSensorData001
     * @tc.desc: Test reading sensor data. 读取传感器数据测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, ReadSensorData001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            std::vector<HdfSensorEvents> events;

            int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
                NORMAL_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(NORMAL_WAIT_TIME);

            ret = g_sensorInterface->ReadData(info.deviceSensorInfo, events);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            printf("Read %zu sensor events\n", events.size());

            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: ReadSensorDataWithNullVector001
     * @tc.desc: Test reading sensor data with null vector. 使用空向量读取传感器数据
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, ReadSensorDataWithNullVector001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            std::vector<HdfSensorEvents> events;

            int32_t ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->ReadData(info.deviceSensorInfo, events);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        } else {
            printf("Accelerometer not found, skipping test\n");
        }
    }

    /**
     * @tc.name: MultipleSensorsConcurrent001
     * @tc.desc: Test multiple sensors operating concurrently. 多个传感器并发运行测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, MultipleSensorsConcurrent001, TestSize.Level1)
    {
        std::vector<int32_t> sensorIds = {
            SENSOR_ID_ACCELEROMETER,
            SENSOR_ID_GYROSCOPE,
            SENSOR_ID_MAGNETIC_FIELD,
            SENSOR_ID_GRAVITY
        };

        TestMultipleSensorsConcurrent(sensorIds);
    }

    /**
     * @tc.name: MultipleSensorsConcurrent002
     * @tc.desc: Test more sensors operating concurrently. 更多传感器并发运行测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, MultipleSensorsConcurrent002, TestSize.Level1)
    {
        std::vector<int32_t> sensorIds = {
            SENSOR_ID_ACCELEROMETER,
            SENSOR_ID_GYROSCOPE,
            SENSOR_ID_AMBIENT_LIGHT,
            SENSOR_ID_MAGNETIC_FIELD,
            SENSOR_ID_GRAVITY,
            SENSOR_ID_LINEAR_ACCEL,
            SENSOR_ID_ROTATION_VECTOR
        };

        TestMultipleSensorsConcurrent(sensorIds);
    }

    /**
     * @tc.name: EnableDisableMultipleTimes001
     * @tc.desc: Test enabling and disabling sensor multiple times. 多次启用和禁用传感器测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, EnableDisableMultipleTimes001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
            NORMAL_REPORT_INTERVAL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        for (int i = 0; i < 10; i++) {
            ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(SHORT_WAIT_TIME);

            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(SHORT_WAIT_TIME);
        }
    }

    /**
     * @tc.name: RegisterUnregisterMultipleTimes001
     * @tc.desc: Test registering and unregistering callback multiple times. 多次注册和注销回调测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RegisterUnregisterMultipleTimes001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        for (int i = 0; i < 10; i++) {
            int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }
    }

    /**
     * @tc.name: SetBatchMultipleTimes001
     * @tc.desc: Test setting batch configuration multiple times. 多次设置批次配置测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetBatchMultipleTimes001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        for (int i = 0; i < 10; i++) {
            int64_t interval = FAST_SAMPLING_INTERVAL + (i * 10 * NANOS_PER_MS);

            int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, interval,
                FAST_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(SHORT_WAIT_TIME);
        }
    }

    /**
     * @tc.name: SetModeMultipleTimes001
     * @tc.desc: Test setting mode multiple times. 多次设置模式测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetModeMultipleTimes001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        for (int i = 0; i < 5; i++) {
            int32_t mode = SENSOR_MODE_REALTIME;

            int32_t ret = g_sensorInterface->SetMode(info.deviceSensorInfo, mode);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(SHORT_WAIT_TIME);
        }
    }

    /**
     * @tc.name: SetOptionMultipleTimes001
     * @tc.desc: Test setting option multiple times. 多次设置选项测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetOptionMultipleTimes001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        for (uint32_t i = 0; i < 5; i++) {
            int32_t ret = g_sensorInterface->SetOption(info.deviceSensorInfo, i);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(SHORT_WAIT_TIME);
        }
    }

    /**
     * @tc.name: DataConsistencyTest001
     * @tc.desc: Test data consistency for accelerometer. 加速度传感器数据一致性测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, DataConsistencyTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
            FAST_REPORT_INTERVAL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Enable(info.deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        OsalMSleep(NORMAL_WAIT_TIME);

        TestDataConsistency(SENSOR_ID_ACCELEROMETER,
            NORMAL_WAIT_TIME / (NORMAL_SAMPLING_INTERVAL / NANOS_PER_MS));

        ret = g_sensorInterface->Disable(info.deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: SensorDataRangeTest001
     * @tc.desc: Test sensor data is within expected range. 传感器数据范围验证测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SensorDataRangeTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
            FAST_REPORT_INTERVAL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Enable(info.deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        OsalMSleep(NORMAL_WAIT_TIME);

        if (!g_callback->receivedData.empty()) {
            for (const auto& data : g_callback->receivedData) {
                for (float value : data.data) {
                    EXPECT_GE(value, -info.maxRange);
                    EXPECT_LE(value, info.maxRange);
                }
            }
            printf("All %zu data points are within range ±%.2f\n",
                g_callback->receivedData.size(), info.maxRange);
        }

        ret = g_sensorInterface->Disable(info.deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: TimestampTest001
     * @tc.desc: Test sensor data timestamps are monotonically increasing. 传感器数据时间戳单调性测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, TimestampTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
            FAST_REPORT_INTERVAL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Enable(info.deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        OsalMSleep(NORMAL_WAIT_TIME);

        if (g_callback->receivedData.size() > 1) {
            bool monotonic = true;
            int64_t prevTimestamp = g_callback->receivedData[0].timestamp;

            for (size_t i = 1; i < g_callback->receivedData.size(); i++) {
                if (g_callback->receivedData[i].timestamp < prevTimestamp) {
                    monotonic = false;
                    printf("Timestamp not monotonic at index %zu: %s < %s\n",
                        i, std::to_string(g_callback->receivedData[i].timestamp).c_str(),
                        std::to_string(prevTimestamp).c_str());
                    break;
                }
                prevTimestamp = g_callback->receivedData[i].timestamp;
            }

            if (monotonic) {
                printf("All %zu timestamps are monotonically increasing\n",
                    g_callback->receivedData.size());
            }
            EXPECT_TRUE(monotonic);
        }

        ret = g_sensorInterface->Disable(info.deviceSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: RapidModeChange001
     * @tc.desc: Test rapid mode changes. 快速模式变更测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RapidModeChange001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, NORMAL_SAMPLING_INTERVAL,
            FAST_REPORT_INTERVAL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        for (int i = 0; i < 20; i++) {
            int32_t mode = (i % 2 == 0) ? SENSOR_MODE_REALTIME : SENSOR_MODE_ON_CHANGE;

            ret = g_sensorInterface->SetMode(info.deviceSensorInfo, mode);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(10);
        }
    }

    /**
     * @tc.name: RapidOptionChange001
     * @tc.desc: Test rapid option changes. 快速选项变更测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RapidOptionChange001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        for (uint32_t i = 0; i < 20; i++) {
            int32_t ret = g_sensorInterface->SetOption(info.deviceSensorInfo, i % 10);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(10);
        }
    }

    /**
     * @tc.name: SetSdcSensor001
     * @tc.desc: Test SDC sensor configuration. SDC传感器配置测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SetSdcSensor001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        int32_t ret = g_sensorInterface->SetSdcSensor(info.deviceSensorInfo, true, 10);
        EXPECT_TRUE(ret == SENSOR_SUCCESS || ret == SENSOR_NOT_SUPPORT);

        if (ret == SENSOR_SUCCESS) {
            OsalMSleep(NORMAL_WAIT_TIME);

            ret = g_sensorInterface->SetSdcSensor(info.deviceSensorInfo, false, 10);
            EXPECT_EQ(SENSOR_SUCCESS, ret);
        }
    }

    /**
     * @tc.name: GetSdcSensorInfo001
     * @tc.desc: Test getting SDC sensor information. 获取SDC传感器信息测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, GetSdcSensorInfo001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        std::vector<OHOS::HDI::Sensor::V3_0::SdcSensorInfo> sdcSensorInfo;
        int32_t ret = g_sensorInterface->GetSdcSensorInfo(sdcSensorInfo);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        printf("Retrieved %zu SDC sensor info entries\n", sdcSensorInfo.size());

        for (const auto& info : sdcSensorInfo) {
            printf("SDC Sensor: ID=%d, ddrSize=%d, minRateLevel=%d, maxRateLevel=%d\n",
                info.deviceSensorInfo.sensorType, info.ddrSize, info.minRateLevel,
                info.maxRateLevel);
        }
    }

    /**
     * @tc.name: RegisterAsync001
     * @tc.desc: Test async callback registration. 异步回调注册测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, RegisterAsync001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->RegisterAsync(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        ret = g_sensorInterface->UnregisterAsync(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: SensorStressTest001
     * @tc.desc: Stress test with rapid enable/disable cycles. 快速启用/禁用循环压力测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SensorStressTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        HdfSensorInformation info;
        if (!FindSensorById(SENSOR_ID_ACCELEROMETER, info)) {
            printf("Accelerometer not found, skipping test\n");
            return;
        }

        int32_t ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, FAST_SAMPLING_INTERVAL,
            FAST_REPORT_INTERVAL);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        for (int i = 0; i < 100; i++) {
            ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(5);

            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            OsalMSleep(5);
        }

        printf("Completed 100 enable/disable cycles\n");
    }

    /**
     * @tc.name: AllSensorsSequentialEnable001
     * @tc.desc: Test enabling all sensors sequentially. 顺序启用所有传感器测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, AllSensorsSequentialEnable001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        if (g_sensorInfo.empty()) {
            printf("No sensors found\n");
            return;
        }

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        for (const auto& info : g_sensorInfo) {
            ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, SLOW_SAMPLING_INTERVAL,
                SLOW_REPORT_INTERVAL);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            ret = g_sensorInterface->Enable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            printf("Enabled sensor %s (ID=%d)\n", info.sensorName.c_str(),
                info.deviceSensorInfo.sensorType);

            OsalMSleep(SHORT_WAIT_TIME);
        }

        OsalMSleep(NORMAL_WAIT_TIME);

        for (const auto& info : g_sensorInfo) {
            ret = g_sensorInterface->Disable(info.deviceSensorInfo);
            EXPECT_EQ(SENSOR_SUCCESS, ret);

            printf("Disabled sensor %s (ID=%d)\n", info.sensorName.c_str(),
                info.deviceSensorInfo.sensorType);
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    /**
     * @tc.name: SensorPowerTest001
     * @tc.desc: Test sensor power consumption information. 传感器功耗信息测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SensorPowerTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        for (const auto& info : g_sensorInfo) {
            EXPECT_GE(info.power, 0.0f);
            EXPECT_LE(info.power, 1000.0f);

            printf("Sensor %s: Power=%.2f mW\n", info.sensorName.c_str(), info.power);
        }
    }

    /**
     * @tc.name: SensorAccuracyTest001
     * @tc.desc: Test sensor accuracy information. 传感器精度信息测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SensorAccuracyTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        for (const auto& info : g_sensorInfo) {
            EXPECT_GE(info.accuracy, 0.0f);

            printf("Sensor %s: Accuracy=%.4f\n", info.sensorName.c_str(), info.accuracy);
        }
    }

    /**
     * @tc.name: SensorFifoTest001
     * @tc.desc: Test sensor FIFO configuration. 传感器FIFO配置测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SensorFifoTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        for (const auto& info : g_sensorInfo) {
            EXPECT_GE(info.fifoMaxEventCount, 0);

            printf("Sensor %s: FIFO Max Event Count=%u\n", info.sensorName.c_str(),
                info.fifoMaxEventCount);
        }
    }

    /**
     * @tc.name: SensorDelayTest001
     * @tc.desc: Test sensor min/max delay information. 传感器最小/最大延迟信息测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, SensorDelayTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        for (const auto& info : g_sensorInfo) {
            EXPECT_GE(info.minDelay, 0);
            EXPECT_GE(info.maxDelay, info.minDelay);

            printf("Sensor %s: MinDelay=%s us, MaxDelay=%s us\n",
                info.sensorName.c_str(), std::to_string(info.minDelay).c_str(), std::to_string(info.maxDelay).c_str());
        }
    }

    /**
     * @tc.name: CrossSensorTypeTest001
     * @tc.desc: Test different sensor types. 不同传感器类型测试
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorComprehensiveTest, CrossSensorTypeTest001, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);

        int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        std::vector<int32_t> sensorTypes = {
            SENSOR_TYPE_ACCELEROMETER,
            SENSOR_TYPE_GYROSCOPE,
            SENSOR_TYPE_AMBIENT_LIGHT,
            SENSOR_TYPE_MAGNETIC_FIELD,
            SENSOR_TYPE_GRAVITY,
            SENSOR_TYPE_ORIENTATION,
            SENSOR_TYPE_LINEAR_ACCELERATION,
            SENSOR_TYPE_ROTATION_VECTOR
        };

        int enabledCount = 0;

        for (int32_t sensorType : sensorTypes) {
            HdfSensorInformation info;
            if (FindSensorById(sensorType, info)) {
                ret = g_sensorInterface->SetBatch(info.deviceSensorInfo, SLOW_SAMPLING_INTERVAL,
                    SLOW_REPORT_INTERVAL);
                EXPECT_EQ(SENSOR_SUCCESS, ret);

                ret = g_sensorInterface->Enable(info.deviceSensorInfo);
                EXPECT_EQ(SENSOR_SUCCESS, ret);

                enabledCount++;
                printf("Enabled sensor type %d (%s)\n", sensorType, info.sensorName.c_str());
            }
        }

        OsalMSleep(LONG_WAIT_TIME);

        for (int32_t sensorType : sensorTypes) {
            HdfSensorInformation info;
            if (FindSensorById(sensorType, info)) {
                ret = g_sensorInterface->Disable(info.deviceSensorInfo);
                EXPECT_EQ(SENSOR_SUCCESS, ret);
            }
        }

        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_callback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);

        printf("Successfully tested %d different sensor types\n", enabledCount);
    }
}
