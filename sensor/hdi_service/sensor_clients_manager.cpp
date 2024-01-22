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

#define HDF_LOG_TAG uhdf_sensor_service

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
                                                  HDF_SENSOR_TYPE_ACCELEROMETER_UNCALIBRATED};
}

SensorClientsManager* SensorClientsManager::instance = nullptr;
std::mutex SensorClientsManager::instanceMutex_;

SensorClientsManager::SensorClientsManager()
{
}

SensorClientsManager::~SensorClientsManager()
{
    clients_.clear();
    sensorUsed_.clear();
    sensorConfig_.clear();
}

int SensorClientsManager::GetServiceId(int groupId, const sptr<ISensorCallback> &callbackObj)
{
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
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        if (callbackObj == nullptr) {
            HDF_LOGE("%{public}s: the callback of service %{public}d is null", __func__, serviceId);
            return;
        }
        clients_[groupId].emplace(serviceId, callbackObj);
        HDF_LOGI("%{public}s: service %{public}d insert the callback", __func__, serviceId);
        return;
    }

    auto it = clients_[groupId].find(serviceId);
    it -> second.SetReportDataCb(callbackObj);
    HDF_LOGI("%{public}s: service %{public}d update the callback", __func__, serviceId);

    return;
}

void SensorClientsManager::ReportDataCbUnRegister(int groupId, int serviceId, const sptr<ISensorCallback> &callbackObj)
{
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        HDF_LOGI("%{public}s: service %{public}d already UnRegister", __func__, serviceId);
        return;
    }

    auto it = clients_[groupId].find(serviceId);
    clients_[groupId].erase(it);
    HDF_LOGI("%{public}s: service: %{public}d, UnRegisterCB Success", __func__, serviceId);
    return;
}

void SensorClientsManager::UpdateSensorConfig(int sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorId);
    bool needUpdateEachClient = false;
    if (it != sensorConfig_.end()) {
        needUpdateEachClient = samplingInterval <= it->second.samplingInterval ||
                reportInterval <= it->second.reportInterval;
        it->second.samplingInterval = samplingInterval <= it->second.samplingInterval ? samplingInterval
         : it->second.samplingInterval;
        it->second.reportInterval = reportInterval <= it->second.reportInterval ? reportInterval
         : it->second.reportInterval;
    } else {
        BestSensorConfig config = {samplingInterval, reportInterval};
        sensorConfig_.emplace(sensorId, config);
        needUpdateEachClient = true;
    }
    it = sensorConfig_.find(sensorId);
    HDF_LOGI("%{public}s: sensorId is %{public}d, samplingInterval is [%{public}ld], "
             "reportInterval is [%{public}ld].", __func__, sensorId, it->second.samplingInterval,
             it->second.reportInterval);
    if (needUpdateEachClient) {
        UpdateEachClient(sensorId, it->second.samplingInterval);
    }
    return;
}

void SensorClientsManager::UpdateEachClient(int sensorId, int64_t samplingInterval)
{
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (samplingInterval == 0) {
        HDF_LOGE("%{public}s: error, samplingInterval is 0, sensorId is %{public}d", __func__, sensorId);
        return;
    }
    int32_t groupId = HDF_TRADITIONAL_SENSOR_TYPE;
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].empty()) {
        return;
    }
    for (auto &entry : clients_[groupId]) {
        auto &client = entry.second;
        if (client.sensorConfigMap_.find(sensorId) != client.sensorConfigMap_.end()) {
            int32_t periodCount = client.sensorConfigMap_.find(sensorId)->second.samplingInterval / samplingInterval;
            client.periodCountMap_[sensorId] = periodCount;
        }
    }
}

void SensorClientsManager::SetSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval)
{
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorId);
    if (it == sensorConfig_.end()) {
        HDF_LOGI("%{public}s: sensor: %{public}d is enabled first time", __func__, sensorId);
        return;
    }
    
    samplingInterval = samplingInterval < it->second.samplingInterval ? samplingInterval : it->second.samplingInterval;
    reportInterval = reportInterval < it->second.reportInterval ? reportInterval : it->second.reportInterval;
    HDF_LOGI("%{public}s: sensorId is %{public}d, samplingInterval is [%{public}ld], "
             "reportInterval is [%{public}ld].", __func__, sensorId, samplingInterval, reportInterval);
    return;
}

void SensorClientsManager::OpenSensor(int sensorId, int serviceId)
{
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    std::set<int> service = {serviceId};
    sensorUsed_.emplace(sensorId, service);
    HDF_LOGI("%{public}s: service: %{public}d enabled sensor %{public}d", __func__,  serviceId, sensorId);
}

bool SensorClientsManager::IsNeedOpenSensor(int sensorId, int serviceId)
{
    auto it = sensorUsed_.find(sensorId);
    if (it == sensorUsed_.end()) {
        HDF_LOGI("%{public}s: sensor %{public}d is enabled by service: %{public}d", __func__,  sensorId, serviceId);
        return true;
    }
    auto service = sensorUsed_[sensorId].find(serviceId);
    if (service == sensorUsed_[sensorId].end()) {
        sensorUsed_[sensorId].insert(serviceId);
        HDF_LOGI("%{public}s: service: %{public}d enabled sensor %{public}d", __func__,  serviceId, sensorId);
    }
    return false;
}

bool SensorClientsManager::IsNeedCloseSensor(int sensorId, int serviceId)
{
    auto it = sensorUsed_.find(sensorId);
    if (it == sensorUsed_.end()) {
        HDF_LOGE("%{public}s: sensor %{public}d has been disabled  or not support", __func__, sensorId);
        return true;
    }
    sensorUsed_[sensorId].erase(serviceId);
    if (sensorUsed_[sensorId].empty()) {
        sensorUsed_.erase(sensorId);
        sensorConfig_.erase(sensorId);
        HDF_LOGI("%{public}s: disabled sensor %{public}d", __func__, sensorId);
        return true;
    }
    return false;
}

bool SensorClientsManager::IsUpadateSensorState(int sensorId, int serviceId, bool isOpen)
{
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
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].empty()) {
        return true;
    }
    return false;
}

bool SensorClientsManager::GetClients(int groupId, std::unordered_map<int32_t, SensorClientInfo> &client)
{
    std::unique_lock<std::mutex> lock(clientsMutex_);
    auto it = clients_.find(groupId);
    if (it == clients_.end() || it->second.empty()) {
        return false;
    }
    client = it->second;
    return true;
}

void SensorClientsManager::SetClientSenSorConfig(int32_t sensorId, int32_t serviceId, int64_t samplingInterval,
                                                 int64_t &reportInterval)
{
    std::unique_lock<std::mutex> lock(clientsMutex_);
    HDF_LOGI("%{public}s: service %{public}d enter the SetClientSenSorConfig function, sensorId is %{public}d, "
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
    int64_t bestSamplingInterval = samplingInterval;
    int64_t bestReportInterval = reportInterval;
    SetSensorBestConfig(sensorId, bestSamplingInterval, bestReportInterval);
    if (bestSamplingInterval == 0) {
        HDF_LOGE("%{public}s: error, bestSamplingInterval is 0, sensorId is %{public}d", __func__, sensorId);
        return;
    }
    int32_t periodCount = samplingInterval / bestSamplingInterval;
    client.periodCountMap_[sensorId] = periodCount;
    client.curCountMap_[sensorId] = 0;
}

bool SensorClientsManager::IsNotNeedReportData(int32_t serviceId, int32_t sensorId)
{
    if (!IsSensorContinues(sensorId)) {
        return false;
    }
    int32_t groupId = HDF_TRADITIONAL_SENSOR_TYPE;
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        HDF_LOGE("%{public}s: service %{public}d already UnRegister", __func__, serviceId);
        return false;
    }
    auto &sensorClientInfo = clients_[groupId].find(serviceId)->second;
    if (sensorClientInfo.periodCountMap_.find(sensorId) == sensorClientInfo.periodCountMap_.end()) {
        return false;
    }
    sensorClientInfo.curCountMap_[sensorId]++;
    if (sensorClientInfo.curCountMap_[sensorId] >= sensorClientInfo.periodCountMap_[sensorId]) {
        sensorClientInfo.curCountMap_[sensorId] = 0;
        return false;
    }
    return true;
}

bool SensorClientsManager::IsSensorContinues(int32_t sensorId)
{
    return std::find(continuesSensor.begin(), continuesSensor.end(), sensorId) != continuesSensor.end();
}

std::unordered_map<int32_t, std::set<int32_t>> SensorClientsManager::GetSensorUsed()
{
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    return sensorUsed_;
}

SensorClientsManager* SensorClientsManager::GetInstance()
{
    if (instance == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (instance == nullptr) {
            instance = new SensorClientsManager();
        }
    }
    return instance;
}

} // V2_0
} // Sensor
} // HDI
} // OHOS