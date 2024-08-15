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
#include "sensor_clients_manager.h"

using namespace OHOS::HDI::Sensor;
using namespace OHOS::HDI::Sensor::V2_0;
using namespace testing::ext;

namespace {
    sptr<ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    std::vector<HdfSensorInformation> g_info;
    constexpr int64_t g_samplingInterval = 10000000;
    constexpr int64_t g_reportInterval = 1;
    constexpr int32_t g_serviceId = 1314;
}

class HdfSensorDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void GetAllSensorInfo(std::vector<HdfSensorInformation> &info)
    {
        struct HdfSensorInformation sensorInfo = {};
        sensorInfo.sensorName = "test_accelerometer";
        sensorInfo.vendorName = "test_accelerometer";
        sensorInfo.firmwareVersion = "test_accelerometer";
        sensorInfo.hardwareVersion = "test_accelerometer";
        sensorInfo.sensorTypeId = 1;
        sensorInfo.sensorId = 1;
        sensorInfo.maxRange = 999;
        sensorInfo.accuracy = 100;
        sensorInfo.power = 1;
        sensorInfo.minDelay = 10;
        sensorInfo.maxDelay = 1000000000;
        sensorInfo.fifoMaxEventCount = 10;
        info.push_back(std::move(sensorInfo));
        SensorClientsManager::GetInstance()->CopySensorInfo(info, 1);
    }
    void Register(int32_t groupId, const sptr<ISensorCallback> &callbackObj)
    {
        SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, getpid(), callbackObj);
    }
    void Unregister(int32_t groupId, const sptr<ISensorCallback> &callbackObj)
    {
        SensorClientsManager::GetInstance()->ReportDataCbUnRegister(groupId, g_serviceId, callbackObj);
    }
    void SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
    {
        SensorClientsManager::GetInstance()->SetClientSenSorConfig(sensorId, g_serviceId, samplingInterval, reportInterval);
        SensorClientsManager::GetInstance()->UpdateSensorConfig(sensorId, samplingInterval, reportInterval);
        SensorClientsManager::GetInstance()->UpdateClientPeriodCount(sensorId, samplingInterval, reportInterval);
    }
    void Enable(int32_t sensorId)
    {
        SensorClientsManager::GetInstance()->OpenSensor(sensorId, g_serviceId);
    }
    void Disable(int32_t sensorId)
    {
        SensorClientsManager::GetInstance()->IsUpadateSensorState(sensorId, g_serviceId, 0);
    }
    void OnDataEvent(const V2_0::HdfSensorEvents& event)
    {
        SensorClientsManager::GetInstance()->CopyEventData(event);
    }
    void PrintDumpResult(struct HdfSBuf* reply)
    {
        while (true) {
            const char* value = HdfSbufReadString(reply);
            if (value == nullptr) {
                return;
            }
            printf("%s", value);
        }
    }
};

void HdfSensorDumpTest::SetUpTestCase()
{
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
    PrintDumpResult(reply);
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
    GetAllSensorInfo(g_info);
    Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    for (auto it : g_info) {
        SetBatch(it.sensorId, g_reportInterval, g_samplingInterval);
        Enable(it.sensorId);
    }

    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, 1u);
    HdfSbufWriteString(data, "-c");
    GetSensorDump(data, reply);

    PrintDumpResult(reply);

    Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
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
    Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);

    V2_0::HdfSensorEvents event;
    for (auto it : g_info) {
        event.sensorId = it.sensorId;
        event.version = 1;
        event.timestamp = 100000000;
        event.option = 1;
        event.mode = 1;
        event.data = [1, 2, 3];
        event.dataLen = 3;
        OnDataEvent(event);
    }

    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, 1u);
    HdfSbufWriteString(data, "-d");
    GetSensorDump(data, reply);
    PrintDumpResult(reply);

    Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
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
    PrintDumpResult(reply);
}