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
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"

using namespace OHOS::HDI::Sensor::V3_0;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;
int32_t SensorCallbackImpl::sensorDataCount = 0;

namespace {
    sptr<V3_0::ISensorInterface>  g_sensorInterface = nullptr;
    sptr<V3_0::ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    int32_t g_duration = 2000;
    int64_t g_samplingInterval = SAMPLINGINTERVAL;

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
        ASSERT_NE(nullptr, g_sensorInterface);
        std::vector<V3_0::HdfSensorInformation> info;
        int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
        EXPECT_EQ(ret, HDF_SUCCESS);

        HdfSensorInformation hdfSensorInformation;
        DeviceSensorInfo deviceSensorInfo;
        for (auto it : info) {
            printf("it is {sensorName: %s, vendorName: %s, firmwareVersion: %s, hardwareVersion: %s, maxRange: %f, "
                   "accuracy: %f, power: %f, minDelay: %s, maxDelay: %s, fifoMaxEventCount: %ud, "
                   "deviceSensorInfo: %s, reserved: %ud}\r\n", it.sensorName.c_str(), it.vendorName.c_str(),
                   it.firmwareVersion.c_str(), it.hardwareVersion.c_str(), it.maxRange, it.accuracy, it.power,
                   std::to_string(it.minDelay).c_str(), std::to_string(it.maxDelay).c_str(),
                   it.fifoMaxEventCount, SENSOR_HANDLE_TO_C_STR(it.deviceSensorInfo), it.reserved);
        }
        if (info.size() == 0) {
            GTEST_SKIP() << "acc Sensor not Exist" << std::endl;
        } else {
            hdfSensorInformation = info[0];
            deviceSensorInfo = hdfSensorInformation.deviceSensorInfo;
        }
        if (hdfSensorInformation.minDelay > g_samplingInterval || hdfSensorInformation.maxDelay < g_samplingInterval) {
            GTEST_SKIP() << "g_samplingInterval not within the frequency range supported by the device" << std::endl;
        }
        ret = g_sensorInterface->Register(0, g_traditionalCallback);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->SetBatch(deviceSensorInfo, g_samplingInterval, 0);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->Enable(deviceSensorInfo);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(g_duration);

        ret = g_sensorInterface->Disable(deviceSensorInfo);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = g_sensorInterface->Unregister(0, g_traditionalCallback);
        EXPECT_EQ(ret, HDF_SUCCESS);
        int expectedMinCount = g_duration / (g_samplingInterval / 1000000) / 2;
        int expectedMaxCount = g_duration / (g_samplingInterval / 1000000) * 3 / 2;
        printf("SetBatch({%s}, %s, 0)\r\n", SENSOR_HANDLE_TO_C_STR(deviceSensorInfo),
                std::to_string(g_samplingInterval).c_str());
        printf("expectedMinCount is %s, expectedMaxCount is %s\r\n", std::to_string(expectedMinCount).c_str(),
               std::to_string(expectedMaxCount).c_str());
        if (SensorCallbackImpl::sensorDataCount > expectedMinCount &&
            SensorCallbackImpl::sensorDataCount < expectedMaxCount) {
            printf("\033[32mas expected, 2000ms get sensor data count is %d\033[0m\r\n",
                   SensorCallbackImpl::sensorDataCount);
        } else {
            printf("\033[31m[ERROR] 2000ms get sensor data count is %d\033[0m\r\n",
                   SensorCallbackImpl::sensorDataCount);
        }
    }
}