/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "sensor_uhdf_log.h"
#include "sensor_hdi_dump.h"

using namespace OHOS::HDI::Sensor::V2_0;
using namespace testing::ext;

namespace {
    sptr<ISensorInterface>  g_sensorInterface = nullptr;
    sptr<SensorIfService>  g_sensorIfService = nullptr;
    sptr<ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    std::vector<HdfSensorInformation> g_info;
    constexpr int64_t g_samplingInterval = 10000000;
    constexpr int64_t g_reportInterval = 1;
    constexpr int32_t g_waitTime = 2;
}

class HdfSensorDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfSensorDumpTest::SetUpTestCase()
{
    g_sensorInterface = ISensorInterface::Get();
    g_sensorIfService = SensorInterfaceImplGetInstance();
}

void HdfSensorDumpTest::TearDownTestCase()
{
}

void HdfSensorDumpTest::SetUp()
{
}

void HdfSensorDumpTest::TearDown()
{
}

/**
  * @tc.name: SensorDumpHelpTest
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorDumpHelpTest, TestSize.Level1)
{
    SENSOR_TRACE;
    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, 1u);
    HdfSbufWriteString(data, "-h");
    GetSensorDump(data, reply);
    const char* value = HdfSbufReadString(reply);
    ASSERT_NE(value, nullptr);
    printf("-h value is %s", value);
}

/**
  * @tc.name: SensorShowClientTest
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorShowClientTest, TestSize.Level1)
{
    SENSOR_TRACE;
    ASSERT_NE(g_sensorIfService, nullptr);
    int32_t ret = g_sensorIfService->GetAllSensorInfo(g_info);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorIfService->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, 1u);
    HdfSbufWriteString(data, "-c");
    GetSensorDump(data, reply);
    const char* value = HdfSbufReadString(reply);
    ASSERT_NE(value, nullptr);
    printf("-h value is %s", value);

    ret = g_sensorIfService->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

/**
  * @tc.name: SensorShowDataTest
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorShowDataTest, TestSize.Level1)
{
    SENSOR_TRACE;
    int32_t ret = g_sensorIfService->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    for (auto it : g_info) {
        ret = g_sensorIfService->SetBatch(it.sensorId, g_reportInterval, g_samplingInterval);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorIfService->Enable(it.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    OsalSleep(g_waitTime);

    for (auto it : g_info) {
        ret = g_sensorIfService->Disable(it.sensorId);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
    }

    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, 1u);
    HdfSbufWriteString(data, "-d");
    GetSensorDump(data, reply);
    const char* value = HdfSbufReadString(reply);
    ASSERT_NE(value, nullptr);
    printf("-h value is %s", value);

    ret = g_sensorIfService->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

/**
  * @tc.name: SensorShowListTest
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorShowListTest, TestSize.Level1)
{
    SENSOR_TRACE;
    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, 1u);
    HdfSbufWriteString(data, "-l");
    GetSensorDump(data, reply);
    const char* value = HdfSbufReadString(reply);
    ASSERT_NE(value, nullptr);
    printf("-h value is %s", value);
}