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
#include <cstdlib>
#include <gtest/gtest.h>
#include <securec.h>
#include <iostream>
#include <string>
#include <thread>
#include <future>
#include <chrono>
#include <functional>
#include <stdexcept>
#include "hdf_base.h"
#include "osal_time.h"
#include "v3_1/isensor_interface.h"
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"

using namespace OHOS::HDI::Sensor::V3_1;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;
int32_t SensorCallbackImpl::sensorDataCount = 0;
int32_t SensorCallbackImpl::sensorDataCountOld = 0;
bool SensorCallbackImpl::printDataFlag = false;

namespace {
    sptr<V3_1::ISensorInterface> g_sensorInterface = nullptr;
    int64_t g_testRegisterTimes = 1001;

    class SensorSetBatchTest : public testing::Test {
        public:
        static void SetUpTestCase();
        static void TearDownTestCase();
        void SetUp();
        void TearDown();
    };

    void SensorSetBatchTest::SetUpTestCase()
    {
        SENSOR_TRACE;
        g_sensorInterface = V3_1::ISensorInterface::Get();
        const char* testRegisterTimes = std::getenv("g_testRegisterTimes");
        if (testRegisterTimes) {
            printf("testRegisterTimes=%s\n", testRegisterTimes);
            g_testRegisterTimes = std::atoi(testRegisterTimes);
        }
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
     *@tc.name: SensorSetBatchTest1
     *@tc.desc: Get a client and check whether the client is empty.
     *@tc.type: FUNC
     *@tc.require:#I4L3LF
     */
    HWTEST_F(SensorSetBatchTest, SensorSetBatchTest1, TestSize.Level1)
    {
        SENSOR_TRACE;
        std::vector<sptr<V3_0::ISensorCallback>> callbacks;
        for (int32_t i = 0; i < g_testRegisterTimes; i++) {
            sptr<V3_0::ISensorCallback> callback = new SensorCallbackImpl();
            uint32_t callbackId = CALLBACK_ID_END + i;
            int32_t ret = g_sensorInterface->RegisterWithCallbackId(0, callback, callbackId);
            printf("The ret of the %d Register is %d.\n", i, ret);
            callbacks.push_back(std::move(callback));
        }
    }
}