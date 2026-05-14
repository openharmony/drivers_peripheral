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
int32_t SensorCallbackImpl::sensorDataCountOld = 0;
bool SensorCallbackImpl::printDataFlag = false;

namespace {
    sptr<V3_0::ISensorInterface> g_sensorInterface = nullptr;
    sptr<V3_0::ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    DeviceSensorInfo g_deviceSensorInfo = {-1, 1, 0, 1};
    constexpr int64_t CLIENT4_SAMPLING_INTERVAL = 5000000;
    constexpr int32_t TOTAL_SECONDS = 2;
    constexpr int32_t EXPECTED_MIN_COUNT_PER_SECOND = 180;

    class SensorFourClientsClient4Test : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void SensorFourClientsClient4Test::SetUpTestCase()
    {
        printf("[Client4] SetUpTestCase enter\n");
        fflush(stdout);
        g_sensorInterface = V3_0::ISensorInterface::Get();
        printf("[Client4] ISensorInterface::Get() returned %p\n", (void*)g_sensorInterface.GetRefPtr());
        (void)fflush(stdout);
    }

    void SensorFourClientsClient4Test::TearDownTestCase()
    {
    }

    void SensorFourClientsClient4Test::SetUp()
    {
    }

    void SensorFourClientsClient4Test::TearDown()
    {
    }

    /**
     * @tc.name: SensorFourClientsClient4Test1
     * @tc.desc: Client4 subscribes sensor at 5ms via SetBatch, counts data for 2 seconds.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorFourClientsClient4Test, SensorFourClientsClient4Test1, TestSize.Level1)
    {
        setvbuf(stdout, nullptr, _IONBF, 0);
        ASSERT_NE(nullptr, g_sensorInterface);

        printf("[Client4] calling Register\n");
        fflush(stdout);
        int32_t ret = g_sensorInterface->Register(0, g_traditionalCallback);
        printf("[Client4] Register ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client4] calling SetBatch interval=%sns\n", std::to_string(CLIENT4_SAMPLING_INTERVAL).c_str());
        ret = g_sensorInterface->SetBatch(g_deviceSensorInfo, CLIENT4_SAMPLING_INTERVAL, 0);
        printf("[Client4] SetBatch ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client4] calling Enable\n");
        ret = g_sensorInterface->Enable(g_deviceSensorInfo);
        printf("[Client4] Enable ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client4] sensor enabled, start counting for %d seconds (expected min %d/s)\n",
            TOTAL_SECONDS, EXPECTED_MIN_COUNT_PER_SECOND);

        for (int32_t i = 0; i < TOTAL_SECONDS; i++) {
            OsalMSleep(1000);
            int32_t countPerSecond = SensorCallbackImpl::sensorDataCount - SensorCallbackImpl::sensorDataCountOld;
            SensorCallbackImpl::sensorDataCountOld = SensorCallbackImpl::sensorDataCount;
            if (countPerSecond >= EXPECTED_MIN_COUNT_PER_SECOND) {
                printf("\033[32m[Client4][%ds] OK, 1s data count=%d, total=%d\033[0m\n",
                    i + 1, countPerSecond, SensorCallbackImpl::sensorDataCount);
            } else {
                printf("\033[31m[Client4][%ds] [ERROR] 1s data count=%d (expected>=%d), total=%d\033[0m\n",
                    i + 1, countPerSecond, EXPECTED_MIN_COUNT_PER_SECOND, SensorCallbackImpl::sensorDataCount);
            }
        }

        printf("[Client4] calling Disable\n");
        ret = g_sensorInterface->Disable(g_deviceSensorInfo);
        printf("[Client4] Disable ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client4] calling Unregister\n");
        ret = g_sensorInterface->Unregister(0, g_traditionalCallback);
        printf("[Client4] Unregister ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client4] finished\n");
    }
}
