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
    int32_t g_serviceId = 1314;
    constexpr int32_t g_sensorIdStart = 1;
    constexpr int32_t g_sensorIdEnd = 10;
    constexpr int32_t g_maxRange = 1000;
    constexpr int32_t g_accuracy = 100;
    constexpr int32_t g_power = 1;
    constexpr int32_t g_minDelay = 10;
    constexpr int32_t g_maxDelay = 1000000000;
    constexpr int32_t g_fifoMaxEventCount = 4;
    constexpr int32_t g_copyFlag = 1;
    constexpr uint32_t g_initDataNum = 1u;
    const std::string g_sensorName = "test_sensor";
}

class HdfSensorDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void GetAllSensorInfo(std::vector<HdfSensorInformation> &info);
    void Register(int32_t groupId, const sptr<ISensorCallback> &callbackObj);
    void Unregister(int32_t groupId, const sptr<ISensorCallback> &callbackObj);
    void SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval);
    void Enable(int32_t sensorId);
    void Disable(int32_t sensorId);
    void OnDataEvent(const V2_0::HdfSensorEvents& event);
    void PrintDumpResult(struct HdfSBuf* reply);
    V2_0::HdfSensorEvents g_event = {1, 1, 100000000, 1, 1, {1, 2, 3, 4}, 4};
};

void HdfSensorDumpTest::SetUpTestCase()
{
    g_serviceId = getpid();
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

void HdfSensorDumpTest::GetAllSensorInfo(std::vector<HdfSensorInformation> &info)
{
    SENSOR_TRACE;
    struct HdfSensorInformation sensorInfo = {};
    for (int32_t sensorId = g_sensorIdStart; sensorId <= g_sensorIdEnd; sensorId++) {
        sensorInfo.sensorName = g_sensorName + std::to_string(sensorId);
        sensorInfo.vendorName = g_sensorName + std::to_string(sensorId);
        sensorInfo.firmwareVersion = g_sensorName + std::to_string(sensorId);
        sensorInfo.hardwareVersion = g_sensorName + std::to_string(sensorId);
        sensorInfo.sensorTypeId = sensorId;
        sensorInfo.sensorId = sensorId;
        sensorInfo.maxRange = g_maxRange + sensorId;
        sensorInfo.accuracy = g_accuracy + sensorId;
        sensorInfo.power = g_power + sensorId;
        sensorInfo.minDelay = g_minDelay + sensorId;
        sensorInfo.maxDelay = g_maxDelay + sensorId;
        sensorInfo.fifoMaxEventCount = g_fifoMaxEventCount + sensorId;
        info.push_back(std::move(sensorInfo));
        SensorClientsManager::GetInstance()->CopySensorInfo(info, g_copyFlag);
    }
}

void HdfSensorDumpTest::Register(int32_t groupId, const sptr<ISensorCallback> &callbackObj)
{
    SENSOR_TRACE;
    SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, g_serviceId, callbackObj);
}

void HdfSensorDumpTest::Unregister(int32_t groupId, const sptr<ISensorCallback> &callbackObj)
{
    SENSOR_TRACE;
    SensorClientsManager::GetInstance()->ReportDataCbUnRegister(groupId, g_serviceId, callbackObj);
}

void HdfSensorDumpTest::SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    SENSOR_TRACE;
    SensorClientsManager::GetInstance()->SetClientSenSorConfig(sensorId, g_serviceId, samplingInterval, reportInterval);
    SensorClientsManager::GetInstance()->UpdateSensorConfig(sensorId, samplingInterval, reportInterval);
    SensorClientsManager::GetInstance()->UpdateClientPeriodCount(sensorId, samplingInterval, reportInterval);
}

void HdfSensorDumpTest::Enable(int32_t sensorId)
{
    SENSOR_TRACE;
    SensorClientsManager::GetInstance()->OpenSensor(sensorId, g_serviceId);
}

void HdfSensorDumpTest::Disable(int32_t sensorId)
{
    SENSOR_TRACE;
    SensorClientsManager::GetInstance()->IsUpadateSensorState(sensorId, g_serviceId, 0);
}

void HdfSensorDumpTest::OnDataEvent(const V2_0::HdfSensorEvents& event)
{
    SENSOR_TRACE;
    SensorClientsManager::GetInstance()->CopyEventData(event);
}

void HdfSensorDumpTest::PrintDumpResult(struct HdfSBuf* reply)
{
    SENSOR_TRACE;
    const char* value = nullptr;
    while ((value = HdfSbufReadString(reply)) != nullptr) {
        printf("%s", value);
    }
}

/**
  * @tc.name: SensorDumpHelpTest
  * @tc.desc: hdc shell "hidumper -s 5100 -a '-host sensor_host -h'"
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorDumpHelpTest, TestSize.Level1)
{
    SENSOR_TRACE;
    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, g_initDataNum);
    HdfSbufWriteString(data, "-h");
    GetSensorDump(data, reply);
    PrintDumpResult(reply);
}

/**
  * @tc.name: SensorShowClientTest
  * @tc.desc: hdc shell "hidumper -s 5100 -a '-host sensor_host -c'"
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
    HdfSbufWriteUint32(data, g_initDataNum);
    HdfSbufWriteString(data, "-c");
    GetSensorDump(data, reply);

    PrintDumpResult(reply);

    Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
}

/**
  * @tc.name: SensorShowDataTest
  * @tc.desc: hdc shell "hidumper -s 5100 -a '-host sensor_host -d'"
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorShowDataTest, TestSize.Level1)
{
    SENSOR_TRACE;
    Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);

    V2_0::HdfSensorEvents event;
    for (auto it : g_info) {
        g_event.sensorId = it.sensorId;
        OnDataEvent(g_event);
    }

    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, g_initDataNum);
    HdfSbufWriteString(data, "-d");
    GetSensorDump(data, reply);
    PrintDumpResult(reply);

    Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
}

/**
  * @tc.name: SensorShowListTest
  * @tc.desc: hdc shell "hidumper -s 5100 -a '-host sensor_host -l'"
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorShowListTest, TestSize.Level1)
{
    SENSOR_TRACE;
    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfSbufWriteUint32(data, g_initDataNum);
    HdfSbufWriteString(data, "-l");
    GetSensorDump(data, reply);
    PrintDumpResult(reply);
}