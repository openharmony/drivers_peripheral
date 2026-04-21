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
    constexpr int64_t CLIENT2_SAMPLING_INTERVAL = 5000000;
    constexpr int32_t CLIENT2_DURATION = 2000;

    class SimulationGpsClient2Test : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void SimulationGpsClient2Test::SetUpTestCase()
    {
        printf("[Client2] SetUpTestCase enter\n");
        fflush(stdout);
        g_sensorInterface = V3_0::ISensorInterface::Get();
        printf("[Client2] ISensorInterface::Get() returned %p\n", (void*)g_sensorInterface.GetRefPtr());
        (void)fflush(stdout);
    }

    void SimulationGpsClient2Test::TearDownTestCase()
    {
    }

    void SimulationGpsClient2Test::SetUp()
    {
    }

    void SimulationGpsClient2Test::TearDown()
    {
    }

    /**
     * @tc.name: SimulationGpsClient2Test1
     * @tc.desc: Client2 subscribes sensor at 5ms via SetBatch, runs 2s then disables.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SimulationGpsClient2Test, SimulationGpsClient2Test1, TestSize.Level1)
    {
        setvbuf(stdout, nullptr, _IONBF, 0);
        ASSERT_NE(nullptr, g_sensorInterface);

        printf("[Client2] calling Register\n");
        int32_t ret = g_sensorInterface->Register(0, g_traditionalCallback);
        printf("[Client2] Register ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client2] calling SetBatch interval=%sns\n", std::to_string(CCLIENT2_SAMPLING_INTERVAL).c_str());
        ret = g_sensorInterface->SetBatch(g_deviceSensorInfo, CLIENT2_SAMPLING_INTERVAL, 0);
        printf("[Client2] SetBatch ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client2] calling Enable\n");
        ret = g_sensorInterface->Enable(g_deviceSensorInfo);
        printf("[Client2] Enable ret=%d, sensor enabled\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client2] sleeping %dms...\n", CLIENT2_DURATION);
        OsalMSleep(CLIENT2_DURATION);

        printf("[Client2] woke up, calling Disable\n");
        ret = g_sensorInterface->Disable(g_deviceSensorInfo);
        printf("[Client2] Disable ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client2] calling Unregister\n");
        ret = g_sensorInterface->Unregister(0, g_traditionalCallback);
        printf("[Client2] Unregister ret=%d\n", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        printf("[Client2] finished, got %d data events\n", SensorCallbackImpl::sensorDataCount);
    }
}
