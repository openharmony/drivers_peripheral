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
    DeviceSensorInfo g_deviceSensorInfo = {-1, 1, 0, 1};
    constexpr int32_t CLIENT3_SDC_RATE_LEVEL = 500;
    constexpr int32_t CLIENT3_DURATION = 10000;

    class SimulationGpsClient3Test : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void SimulationGpsClient3Test::SetUpTestCase()
    {
        printf("[Client3] SetUpTestCase enter\n");
        fflush(stdout);
        g_sensorInterface = V3_0::ISensorInterface::Get();
        printf("[Client3] ISensorInterface::Get() returned %p\n", (void*)g_sensorInterface.GetRefPtr());
        (void)fflush(stdout);
    }

    void SimulationGpsClient3Test::TearDownTestCase()
    {
    }

    void SimulationGpsClient3Test::SetUp()
    {
    }

    void SimulationGpsClient3Test::TearDown()
    {
    }

    /**
     * @tc.name: SimulationGpsClient3Test1
     * @tc.desc: Client3 opens sensor via SetSdcSensor at 2ms rateLevel=500, runs 10s then closes.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SimulationGpsClient3Test, SimulationGpsClient3Test1, TestSize.Level1)
    {
        setvbuf(stdout, nullptr, _IONBF, 0);
        ASSERT_NE(nullptr, g_sensorInterface);

        printf("[Client3] calling SetSdcSensor(enable=true, rateLevel=%d)\n", CLIENT3_SDC_RATE_LEVEL);
        int32_t ret = g_sensorInterface->SetSdcSensor(g_deviceSensorInfo, true, CLIENT3_SDC_RATE_LEVEL);
        printf("[Client3] SetSdcSensor enable ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client3] sdc sensor enabled, sleeping %dms...\n", CLIENT3_DURATION);
        OsalMSleep(CLIENT3_DURATION);

        printf("[Client3] woke up, calling SetSdcSensor disable\n");
        ret = g_sensorInterface->SetSdcSensor(g_deviceSensorInfo, false, CLIENT3_SDC_RATE_LEVEL);
        printf("[Client3] SetSdcSensor disable ret=%d\n", ret);

        printf("[Client3] finished\n");
    }
}
