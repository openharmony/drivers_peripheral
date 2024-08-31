/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "sensor_uhdf_log.h"
#include "sensor_clients_manager.h"
#include <cinttypes>

#define HDF_LOG_TAG uhdf_sensor_clients_manager

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

namespace {
    const std::vector<int32_t> continuesSensor = {HDF_SENSOR_TYPE_ACCELEROMETER, HDF_SENSOR_TYPE_GYROSCOPE,
                                                  HDF_SENSOR_TYPE_MAGNETIC_FIELD, HDF_SENSOR_TYPE_SAR,
                                                  HDF_SENSOR_TYPE_ORIENTATION, HDF_SENSOR_TYPE_GRAVITY,
                                                  HDF_SENSOR_TYPE_LINEAR_ACCELERATION, HDF_SENSOR_TYPE_ROTATION_VECTOR,
                                                  HDF_SENSOR_TYPE_MAGNETIC_FIELD_UNCALIBRATED,
                                                  HDF_SENSOR_TYPE_GAME_ROTATION_VECTOR,
                                                  HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED, HDF_SENSOR_TYPE_DROP_DETECT,
                                                  HDF_SENSOR_TYPE_GEOMAGNETIC_ROTATION_VECTOR,
                                                  HDF_SENSOR_TYPE_ACCELEROMETER_UNCALIBRATED,
                                                  HDF_SENSOR_TYPE_BAROMETER};
    constexpr int64_t ERROR_INTERVAL = 0;
    constexpr int64_t STOP_INTERVAL = 0;
    constexpr int32_t INIT_CUR_COUNT = 0;
    constexpr int64_t INIT_REPORT_COUNT = 1;
}

std::mutex SensorClientsManager::instanceMutex_;

SensorClientsManager::SensorClientsManager()
{
}

SensorClientsManager::~SensorClientsManager()
{
    clients_.clear();
    sensorUsed_.clear();
    sensorConfig_.clear();
    sdcSensorConfig_.clear();
}

void SensorClientsManager::CopySensorInfo(std::vector<HdfSensorInformation> &info, bool cFlag)
{
    std::unique_lock<std::mutex> lock(sensorInfoMutex_);
    if (!cFlag) {
        info = sensorInfo_;
        return;
    }
    sensorInfo_ = info;
    return;
}

void SensorClientsManager::GetEventData(struct SensorsDataPack &dataPack)
{
    std::unique_lock<std::mutex> lock(sensorsDataPackMutex_);
    dataPack = listDump_;
    return;
}

void SensorClientsManager::CopyEventData(const struct HdfSensorEvents event)
{
    std::unique_lock<std::mutex> lock(sensorsDataPackMutex_);
    if (event.data.empty()) {
        HDF_LOGE("%{public}s: event data is empty!", __func__);
        return;
    }

    if (listDump_.count == MAX_DUMP_DATA_SIZE) {
        listDump_.listDumpArray[listDump_.pos++] = event;
        if (listDump_.pos == MAX_DUMP_DATA_SIZE) {
            listDump_.pos = 0;
        }
    } else {
        listDump_.listDumpArray[listDump_.count] = event;
        listDump_.count++;
    }
    return;
}

int SensorClientsManager::GetServiceId(int groupId, const sptr<ISensorCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    for (auto &iter : clients_[groupId]) {
        if (iter.second.GetReportDataCb() == callbackObj) {
            return iter.first;
        }
    }
    return HDF_FAILURE;
}

void SensorClientsManager::ReportDataCbRegister(int groupId, int serviceId, const sptr<ISensorCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        if (callbackObj == nullptr) {
            HDF_LOGE("%{public}s: the callback of service %{public}d is null", __func__, serviceId);
            return;
        }
        clients_[groupId].emplace(serviceId, callbackObj);
        HDF_LOGD("%{public}s: service %{public}d insert the callback", __func__, serviceId);
        return;
    }

    auto it = clients_[groupId].find(serviceId);
    it -> second.SetReportDataCb(callbackObj);
    HDF_LOGD("%{public}s: service %{public}d update the callback", __func__, serviceId);

    return;
}

void SensorClientsManager::ReportDataCbUnRegister(int groupId, int serviceId, const sptr<ISensorCallback> &callbackObj)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        HDF_LOGD("%{public}s: service %{public}d already UnRegister", __func__, serviceId);
        return;
    }

    auto it = clients_[groupId].find(serviceId);
    clients_[groupId].erase(it);
    HDF_LOGD("%{public}s: service: %{public}d, UnRegisterCB Success", __func__, serviceId);
    return;
}

void SensorClientsManager::UpdateSensorConfig(int sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorId);
    if (it != sensorConfig_.end()) {
        it->second.samplingInterval = samplingInterval <= it->second.samplingInterval ? samplingInterval
         : it->second.samplingInterval;
        it->second.reportInterval = reportInterval <= it->second.reportInterval ? reportInterval
         : it->second.reportInterval;
    } else {
        BestSensorConfig config = {samplingInterval, reportInterval};
        sensorConfig_.emplace(sensorId, config);
    }
}

void SensorClientsManager::UpdateSdcSensorConfig(int sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorId);
    if (it != sdcSensorConfig_.end()) {
        it->second.samplingInterval = samplingInterval <= it->second.samplingInterval ? samplingInterval
         : it->second.samplingInterval;
        it->second.reportInterval = reportInterval <= it->second.reportInterval ? reportInterval
         : it->second.reportInterval;
    } else {
        BestSensorConfig config = {samplingInterval, reportInterval};
        sdcSensorConfig_.emplace(sensorId, config);
    }
}

void SensorClientsManager::UpdateClientPeriodCount(int sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    SENSOR_TRACE_PID;
    HDF_LOGD("%{public}s: sensorId is %{public}d, samplingInterval is [%{public}" PRId64 "],"
        "reportInterval is [%{public}" PRId64 "]", __func__, sensorId,
        samplingInterval, reportInterval);
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (samplingInterval <= ERROR_INTERVAL || reportInterval < ERROR_INTERVAL) {
        HDF_LOGE("%{public}s: samplingInterval or reportInterval error", __func__);
        return;
    }
    int32_t groupId = HDF_TRADITIONAL_SENSOR_TYPE;
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].empty()) {
        return;
    }
    std::string result = "";
    for (auto &entry : clients_[groupId]) {
        auto &client = entry.second;
        if (client.curCountMap_.find(sensorId) == client.curCountMap_.end()) {
            client.curCountMap_[sensorId] = INIT_CUR_COUNT;
        }
        if (client.sensorConfigMap_.find(sensorId) != client.sensorConfigMap_.end()) {
            int32_t periodCount = client.sensorConfigMap_.find(sensorId)->second.samplingInterval / samplingInterval;
            result += " serviceId=" + std::to_string(entry.first) + ", sensorId=" + std::to_string(sensorId) +
                      ", periodCount=" + std::to_string(client.sensorConfigMap_.find(sensorId)->second.samplingInterval)
                      + "/" + std::to_string(samplingInterval) + "=" + std::to_string(periodCount);
            client.periodCountMap_[sensorId] = periodCount;
        }
    }
    HDF_LOGI("%{public}s: %{public}s", __func__, result.c_str());
}

void SensorClientsManager::SetSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorId);
    if (it == sensorConfig_.end()) {
        HDF_LOGD("%{public}s: sensor: %{public}d is enabled first time", __func__, sensorId);
        return;
    }
    
    samplingInterval = samplingInterval < it->second.samplingInterval ? samplingInterval : it->second.samplingInterval;
    reportInterval = reportInterval < it->second.reportInterval ? reportInterval : it->second.reportInterval;
    HDF_LOGD("%{public}s: sensorId is %{public}d, after SetSensorBestConfig, samplingInterval is %{public}s, "
             "reportInterval is %{public}s", __func__, sensorId, std::to_string(samplingInterval).c_str(),
             std::to_string(reportInterval).c_str());
    return;
}

void SensorClientsManager::SetSdcSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorId);
    if (it == sdcSensorConfig_.end()) {
        HDF_LOGD("%{public}s: sensor: %{public}d is enabled by sdc first time", __func__, sensorId);
        return;
    }

    samplingInterval = samplingInterval < it->second.samplingInterval ? samplingInterval : it->second.samplingInterval;
    reportInterval = reportInterval < it->second.reportInterval ? reportInterval : it->second.reportInterval;
    HDF_LOGD("%{public}s: sensorId is %{public}d, after SetSdcSensorBestConfig, samplingInterval is %{public}s, "
             "reportInterval is %{public}s", __func__, sensorId, std::to_string(samplingInterval).c_str(),
             std::to_string(reportInterval).c_str());
    return;
}


void SensorClientsManager::GetSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorId);
    if (it == sensorConfig_.end()) {
        samplingInterval = STOP_INTERVAL;
        reportInterval = STOP_INTERVAL;
        HDF_LOGD("%{public}s: sensor: %{public}d has no best config", __func__, sensorId);
        return;
    }

    samplingInterval = it->second.samplingInterval;
    reportInterval = it->second.reportInterval;
    HDF_LOGD("%{public}s: sensorId is %{public}d, after GetSensorBestConfig, samplingInterval is %{public}s, "
             "reportInterval is %{public}s", __func__, sensorId, std::to_string(samplingInterval).c_str(),
             std::to_string(reportInterval).c_str());
    return;
}

void SensorClientsManager::EraseSdcSensorBestConfig(int sensorId)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorId);
    if (it == sdcSensorConfig_.end()) {
        HDF_LOGD("%{public}s: sensor: %{public}d sdcSensorBestConfig not exist, not need erase", __func__, sensorId);
        return;
    }
    sdcSensorConfig_.erase(it);
    HDF_LOGD("%{public}s: sensor: %{public}d config has been erase from sdcSensorConfig_", __func__, sensorId);
    return;
}

void SensorClientsManager::OpenSensor(int sensorId, int serviceId)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    std::set<int> service = {serviceId};
    sensorUsed_.emplace(sensorId, service);
    HDF_LOGD("%{public}s: service: %{public}d enabled sensor %{public}d", __func__,  serviceId, sensorId);
}

bool SensorClientsManager::IsNeedOpenSensor(int sensorId, int serviceId)
{
    SENSOR_TRACE_PID;
    auto it = sensorUsed_.find(sensorId);
    if (it == sensorUsed_.end()) {
        HDF_LOGD("%{public}s: sensor %{public}d is enabled by service: %{public}d", __func__,  sensorId, serviceId);
        return true;
    }
    auto service = sensorUsed_[sensorId].find(serviceId);
    if (service == sensorUsed_[sensorId].end()) {
        sensorUsed_[sensorId].insert(serviceId);
        HDF_LOGD("%{public}s: service: %{public}d enabled sensor %{public}d", __func__,  serviceId, sensorId);
    }
    return false;
}

bool SensorClientsManager::IsNeedCloseSensor(int sensorId, int serviceId)
{
    SENSOR_TRACE_PID;
    auto it = sensorUsed_.find(sensorId);
    if (it == sensorUsed_.end()) {
        HDF_LOGE("%{public}s: sensor %{public}d has been disabled  or not support", __func__, sensorId);
        return true;
    }
    sensorUsed_[sensorId].erase(serviceId);
    if (sensorUsed_[sensorId].empty()) {
        sensorUsed_.erase(sensorId);
        sensorConfig_.erase(sensorId);
        HDF_LOGD("%{public}s: disabled sensor %{public}d", __func__, sensorId);
        return true;
    }
    for (auto sid : sensorUsed_[sensorId]) {
        HDF_LOGD("%{public}s: sensor %{public}d also is enable by service %{public}d", __func__, sensorId, sid);
    }
    return false;
}

bool SensorClientsManager::IsExistSdcSensorEnable(int sensorId)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorId);
    if (it == sdcSensorConfig_.end()) {
        return false;
    }
    HDF_LOGE("%{public}s: sensor %{public}d has been enabled by sdc service %{public}d", __func__, sensorId, it->first);
    return true;
}

bool SensorClientsManager::IsUpadateSensorState(int sensorId, int serviceId, bool isOpen)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    if (isOpen && IsNeedOpenSensor(sensorId, serviceId)) {
        return true;
    }
    if (!isOpen && IsNeedCloseSensor(sensorId, serviceId)) {
        return true;
    }
    return false;
}

bool SensorClientsManager::IsClientsEmpty(int groupId)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].empty()) {
        return true;
    }
    return false;
}

bool SensorClientsManager::IsNoSensorUsed()
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    for (auto it = sensorUsed_.begin(); it != sensorUsed_.end(); ++it) {
        if (!it->second.empty()) {
            return false;
        }
    }
    return true;
}

bool SensorClientsManager::GetClients(int groupId, std::unordered_map<int32_t, SensorClientInfo> &client)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    auto it = clients_.find(groupId);
    if (it == clients_.end() || it->second.empty()) {
        return false;
    }
    client = it->second;
    return true;
}

bool SensorClientsManager::GetBestSensorConfigMap(std::unordered_map<int32_t, struct BestSensorConfig> &map)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    map = sensorConfig_;
    return true;
}

void SensorClientsManager::SetClientSenSorConfig(int32_t sensorId, int32_t serviceId, int64_t samplingInterval,
                                                 int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    HDF_LOGD("%{public}s: service %{public}d enter the SetClientSenSorConfig function, sensorId is %{public}d, "
             "samplingInterval is %{public}s, reportInterval is %{public}s", __func__, serviceId, sensorId,
             std::to_string(samplingInterval).c_str(), std::to_string(reportInterval).c_str());

    int32_t groupId = HDF_TRADITIONAL_SENSOR_TYPE;
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        HDF_LOGE("%{public}s: service %{public}d already UnRegister", __func__, serviceId);
        return;
    }

    auto &client = clients_[groupId].find(serviceId)->second;
    SensorConfig sensorConfig = {samplingInterval, reportInterval};
    client.sensorConfigMap_[sensorId] = sensorConfig;
}

bool SensorClientsManager::IsSensorContinues(int32_t sensorId)
{
    return std::find(continuesSensor.begin(), continuesSensor.end(), sensorId) != continuesSensor.end();
}

bool SensorClientsManager::IsNotNeedReportData(SensorClientInfo &sensorClientInfo, const int32_t &sensorId,
                                               const int32_t &serviceId)
{
    SENSOR_TRACE;
    if (!SensorClientsManager::IsSensorContinues(sensorId)) {
        return false;
    }
    if (sensorClientInfo.periodCountMap_.find(sensorId) == sensorClientInfo.periodCountMap_.end()) {
        return false;
    }
    bool result = true;
    sensorClientInfo.PrintClientMapInfo(serviceId, sensorId);
    if (sensorClientInfo.curCountMap_[sensorId] == 0) {
        result = false;
    }
    sensorClientInfo.curCountMap_[sensorId]++;
    if (sensorClientInfo.curCountMap_[sensorId] >= sensorClientInfo.periodCountMap_[sensorId]) {
        sensorClientInfo.curCountMap_[sensorId] = 0;
    }
    return result;
}

std::set<int32_t> SensorClientsManager::GetServiceIds(int32_t &sensorId)
{
    SENSOR_TRACE;
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    if (sensorUsed_.find(sensorId) == sensorUsed_.end()) {
        HDF_LOGD("%{public}s sensor %{public}d is not enabled by anyone", __func__, sensorId);
        return std::set<int32_t>();
    }
    return sensorUsed_.find(sensorId)->second;
}

std::string SensorClientsManager::ReportEachClient(const V2_0::HdfSensorEvents& event)
{
    SENSOR_TRACE;
    std::string result = "services=";
    int32_t sensorId = event.sensorId;
    const std::set<int32_t> services = GetServiceIds(sensorId);
    int32_t groupId = HDF_TRADITIONAL_SENSOR_TYPE;
    {
        std::unique_lock<std::mutex> lock(clientsMutex_);
        if (clients_.find(groupId) == clients_.end() || clients_.find(groupId)->second.empty()) {
            HDF_LOGE("%{public}s groupId %{public}d is not enabled by anyone", __func__, sensorId);
            return result;
        }
    }
    for (auto it = services.begin(); it != services.end(); ++it) {
        int32_t serviceId = *it;
        sptr<ISensorCallback> callback;
        {
            std::unique_lock<std::mutex> lock(clientsMutex_);
            if (clients_.find(groupId)->second.find(serviceId) == clients_.find(groupId)->second.end()) {
                continue;
            }
            SensorClientInfo &sensorClientInfo = clients_.find(groupId)->second.find(serviceId)->second;
            if (IsNotNeedReportData(sensorClientInfo, sensorId, serviceId)) {
                continue;
            }
            callback = sensorClientInfo.GetReportDataCb();
            if (callback == nullptr) {
                HDF_LOGD("%{public}s the callback of %{public}d is nullptr", __func__, serviceId);
                continue;
            }
        }
        SENSOR_TRACE_MSG("serviceId=" + std::to_string(serviceId) + ",sensorId=" + std::to_string(event.sensorId));
        int32_t ret = callback->OnDataEvent(event);
        if (ret != HDF_SUCCESS) {
            HDF_LOGD("%{public}s Sensor OnDataEvent failed, error code is %{public}d", __func__, ret);
        } else {
            static std::unordered_map<int32_t, std::unordered_map<int32_t, int64_t>> sensorReportCountMap;
            auto it = sensorReportCountMap[sensorId].find(serviceId);
            int64_t reportCount = INIT_REPORT_COUNT;
            if (it == sensorReportCountMap[sensorId].end()) {
                sensorReportCountMap[sensorId][serviceId] = INIT_REPORT_COUNT;
            } else {
                it->second++;
                reportCount = it->second;
            }
            result += std::to_string(serviceId) + "-" + std::to_string(reportCount) + " ";
        }
    }
    return result;
}

std::unordered_map<int32_t, std::set<int32_t>> SensorClientsManager::GetSensorUsed()
{
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    return sensorUsed_;
}

SensorClientsManager* SensorClientsManager::GetInstance()
{
    static SensorClientsManager *instance = new SensorClientsManager();
    return instance;
}

} // V2_0
} // Sensor
} // HDI
} // OHOS