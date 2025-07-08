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

    class SensorSetSdcSensorTest : public testing::Test {
    public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void SensorSetSdcSensorTest::SetUpTestCase()
    {
        g_sensorInterface = V3_0::ISensorInterface::Get();
    }

    void SensorSetSdcSensorTest::TearDownTestCase()
    {
    }

    void SensorSetSdcSensorTest::SetUp()
    {
    }

    void SensorSetSdcSensorTest::TearDown()
    {
    }

    /**
     * @tc.name: SensorSetSdcSensorTest1
     * @tc.desc: Get a client and check whether the client is empty.
     * @tc.type: FUNC
     * @tc.require: #I4L3LF
     */
    HWTEST_F(SensorSetSdcSensorTest, SensorSetSdcSensorTest1, TestSize.Level1)
    {
        ASSERT_NE(nullptr, g_sensorInterface);
        std::vector<V3_0::HdfSensorInformation> info;
        int32_t ret = g_sensorInterface->GetAllSensorInfo(info);
        EXPECT_EQ(ret, HDF_SUCCESS);
        bool accSensorExist = false;
        DeviceSensorInfo deviceSensorInfo;
        for (auto it : info) {
            if (it.deviceSensorInfo.sensorType == HDF_SENSOR_TYPE_ACCELEROMETER) {
                accSensorExist = true;
                deviceSensorInfo = it.deviceSensorInfo;
            }
        }
        if (accSensorExist == false) {
            GTEST_SKIP() << "acc Sensor not Exist" << std::endl;
        }
        ret = g_sensorInterface->SetSdcSensor(deviceSensorInfo, true, 100);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(2000);

        ret = g_sensorInterface->SetSdcSensor(deviceSensorInfo, false, 100);
    }
}