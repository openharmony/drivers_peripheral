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

#include "sensor_hdi_dump.h"
#include "osal_mem.h"
#include <securec.h>
#include <unordered_map>
#include "sensor_uhdf_log.h"

#define HDF_LOG_TAG uhdf_sensor_hdi_dump

constexpr int32_t GET_SENSORINFO = 0;
constexpr int32_t DATA_LEN = 256;

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_1 {

static const char *SENSOR_HELP =
    " Sensor manager dump options:\n"
    "     -h: [sensor command help]\n"
    "     -l: [show sensor list]\n"
    "     -d: [The data information is displayed 10 times]\n"
    "     -c: [show sensor client information]\n";

SensorHdiDump::SensorHdiDump()
{}

SensorHdiDump::~SensorHdiDump()
{}

int32_t SensorHdiDump::SensorShowList(struct HdfSBuf *reply)
{
    std::vector<HdfSensorInformation> sensorInfoList;

    SensorClientsManager::GetInstance()->CopySensorInfo(sensorInfoList, GET_SENSORINFO);

    if (sensorInfoList.empty()) {
        HDF_LOGE("%{public}s: no sensor info in list", __func__);
        return HDF_FAILURE;
    }

    for (const auto &it : sensorInfoList) {
        std::string st = {0};
        st = "sensorName:  " + it.sensorName + "\n" +
             "sensorId:  " + std::to_string(it.sensorId) + "\n" +
             "sensorTypeId:  " + std::to_string(it.sensorTypeId) + "\n" +
             "maxRange:  " + std::to_string(it.maxRange) + "\n" +
             "accuracy:  " + std::to_string(it.accuracy) + "\n" +
             "power:  " + std::to_string(it.power) + "\n" +
             "minDelay:  " + std::to_string(it.minDelay) + "\n" +
             "maxDelay:  " + std::to_string(it.maxDelay) + "\n" +
             "fifoMaxEventCount:  " + std::to_string(it.fifoMaxEventCount) + "\n" +
             "============================================\n";
            (void)HdfSbufWriteString(reply, st.c_str());
    }
    return HDF_SUCCESS;
}

std::string SensorHdiDump::SensorInfoDataToString(const float *data,
                                                  const int64_t timesTamp,
                                                  const int32_t dataDimension,
                                                  const int32_t sensorId)
{
    std::string dataStr = {0};
    std::string st = {0};
    char arrayStr[DATA_LEN] = {0};

    for (int32_t i = 0; i < dataDimension; i++) {
        if (sprintf_s(arrayStr + strlen(arrayStr), DATA_LEN, "[%f]", data[i]) < 0) {
            HDF_LOGE("%{public}s: sprintf_s failed", __func__);
            return st;
        }
    }

    dataStr = arrayStr;
    st = "sensor id: " + std::to_string(sensorId) + ", ts = " +
        std::to_string(timesTamp / 1e9) + ", data = " + dataStr + "\n";

    return st;
}

int32_t SensorHdiDump::ShowData(const float *data,
                                const int64_t timesTamp,
                                const int32_t dataDimension,
                                const int32_t sensorId,
                                struct HdfSBuf *reply)
{
    std::string sensorInfoData = {0};

    switch (dataDimension) {
        case MEM_X:
        case MEM_XY:
        case MEM_XYZ:
        case MEM_UNCALIBRATED:
        case MEM_POSTURE:
        case MEM_SPE_RGB:
            sensorInfoData = SensorInfoDataToString(data, timesTamp, dataDimension, sensorId);
            break;
        default:
            HDF_LOGE("%{public}s: unsupported dimension, dimension is %{public}d", __func__, dataDimension);
            break;
    }

    if (sensorInfoData.empty()) {
        HDF_LOGE("%{public}s: sensor infomation data is empty!", __func__);
        return HDF_FAILURE;
    }

    (void)HdfSbufWriteString(reply, sensorInfoData.c_str());
    return HDF_SUCCESS;
}

int32_t SensorHdiDump::SensorShowData(struct HdfSBuf *reply)
{
    struct SensorsDataPack eventDumpList;
    uint8_t *eventData = nullptr;

    SensorClientsManager::GetInstance()->GetEventData(eventDumpList);

    (void)HdfSbufWriteString(reply, "============== The last 10 data records ==============\n");

    for (int32_t i = 0; i < eventDumpList.count; i++) {
        int32_t index = static_cast<const uint32_t>(eventDumpList.pos + i) < MAX_DUMP_DATA_SIZE ?
            (eventDumpList.pos + i) : (eventDumpList.pos + i - MAX_DUMP_DATA_SIZE);
        uint32_t dataLen = eventDumpList.listDumpArray[index].dataLen;
        eventData = static_cast<uint8_t*>(OsalMemCalloc(dataLen));
        if (eventData == nullptr) {
            HDF_LOGE("%{public}s: malloc failed!", __func__);
            return HDF_FAILURE;
        }

        std::copy(eventDumpList.listDumpArray[index].data.begin(),
                  eventDumpList.listDumpArray[index].data.end(), eventData);
        float *data = reinterpret_cast<float*>(eventData);

        int32_t dataDimension = static_cast<int32_t>(dataLen / sizeof(float));

        int32_t ret = ShowData(data, eventDumpList.listDumpArray[index].timestamp, dataDimension,
                               eventDumpList.listDumpArray[index].sensorId, reply);
        if (ret != HDF_SUCCESS) {
            OsalMemFree(eventData);
            HDF_LOGE("%{public}s: print sensor infomation data failed!", __func__);
            return HDF_FAILURE;
        }

        OsalMemFree(eventData);
        eventData = nullptr;
    }

    return HDF_SUCCESS;
}

int32_t SensorHdiDump::SensorShowClient(struct HdfSBuf *reply)
{
    std::unordered_map<int, SensorClientInfo> sensorClientInfoMap;
    if (!SensorClientsManager::GetInstance()->GetClients(HDF_TRADITIONAL_SENSOR_TYPE, sensorClientInfoMap)) {
        HDF_LOGD("%{public}s groupId %{public}d is not used by anyone", __func__, HDF_TRADITIONAL_SENSOR_TYPE);
        return HDF_FAILURE;
    }
    std::unordered_map<int32_t, struct BestSensorConfig> bestSensorConfigMap;
    (void)SensorClientsManager::GetInstance()->GetBestSensorConfigMap(bestSensorConfigMap);
    std::unordered_map<int, std::set<int>> sensorEnabled = SensorClientsManager::GetInstance()->GetSensorUsed();
    (void)HdfSbufWriteString(reply, "============== all clients information ==============\n\n");
    std::string sensorInfoData = "";
    sensorInfoData += "bestSensorConfigMap={\n";
    for (const auto &entry2 : bestSensorConfigMap) {
        auto sensorId = entry2.first;
        auto bestSensorConfig = entry2.second;
        sensorInfoData += "{sensorId=" + std::to_string(sensorId) + ",";
        sensorInfoData += "bestSensorConfig={";
        sensorInfoData += "samplingInterval=" + std::to_string(bestSensorConfig.samplingInterval) + ",";
        sensorInfoData += "reportInterval=" + std::to_string(bestSensorConfig.reportInterval);
        sensorInfoData += "}}\n";
    }
    sensorInfoData += "}\n\n";
    for (const auto &entry : sensorClientInfoMap) {
        auto serviceId = entry.first;
        auto sensorClientInfo = entry.second;
        sensorInfoData += "serviceId=" + std::to_string(serviceId) + " ";
        sensorInfoData += "sensorConfigMap_={\n";
        for (const auto &entry2 : sensorClientInfo.sensorConfigMap_) {
            auto sensorId = entry2.first;
            auto sensorConfig = entry2.second;
            sensorInfoData += "{sensorId=" + std::to_string(sensorId) + ",";
            sensorInfoData += "sensorConfig={";
            sensorInfoData += "samplingInterval=" + std::to_string(sensorConfig.samplingInterval) + ",";
            sensorInfoData += "reportInterval=" + std::to_string(sensorConfig.reportInterval) + ",";
            sensorInfoData += "curCount/periodCount=" + std::to_string(sensorClientInfo.curCountMap_[sensorId]) + "/" +
                    std::to_string(sensorClientInfo.periodCountMap_[sensorId]) + ",";
            if (sensorEnabled.find(sensorId) != sensorEnabled.end() &&
                sensorEnabled.find(sensorId)->second.find(serviceId) != sensorEnabled.find(sensorId)->second.end()) {
                sensorInfoData += "enable";
            }
            sensorInfoData += "}}\n";
        }
        sensorInfoData += "}\n\n";
    }
    (void)HdfSbufWriteString(reply, sensorInfoData.c_str());
    return HDF_SUCCESS;
}

int32_t SensorHdiDump::DevHostSensorHdiDump(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t argc = 0;

    if (data == nullptr || reply == nullptr) {
        HDF_LOGE("%{public}s: data or reply is nullptr", __func__);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(data, &argc)) {
        HDF_LOGE("%{public}s: read &argc failed", __func__);
        return HDF_FAILURE;
    }

    if (argc == 0) {
        (void)HdfSbufWriteString(reply, SENSOR_HELP);
        return HDF_SUCCESS;
    }

    for (uint32_t i = 0; i < argc; i++) {
        const char *value = HdfSbufReadString(data);
        if (value == nullptr) {
            HDF_LOGE("%{public}s: arg is invalid", __func__);
            return HDF_FAILURE;
        }
        if (strcmp(value, "-h") == 0) {
            (void)HdfSbufWriteString(reply, SENSOR_HELP);
            return HDF_SUCCESS;
        } else if (strcmp(value, "-l") == 0) {
            SensorShowList(reply);
            return HDF_SUCCESS;
        } else if (strcmp(value, "-d") == 0) {
            SensorShowData(reply);
            return HDF_SUCCESS;
        } else if (strcmp(value, "-c") == 0) {
            SensorShowClient(reply);
            return HDF_SUCCESS;
        }
    }

    return HDF_SUCCESS;
}

int32_t GetSensorDump(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    SensorHdiDump::DevHostSensorHdiDump(data, reply);
    return HDF_SUCCESS;
}

} // V2_1
} // Sensor
} // HDI
} // OHOS