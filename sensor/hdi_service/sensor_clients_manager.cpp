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

#include "hdf_log.h"
#include "sensor_clients_manager.h"

#define HDF_LOG_TAG uhdf_sensor_service

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

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
    if (it != sensorConfig_.end()) {
        it->second.samplingInterval = samplingInterval <= it->second.samplingInterval ? samplingInterval
         : it->second.samplingInterval;
        it->second.reportInterval = reportInterval <= it->second.reportInterval ? reportInterval
         : it->second.reportInterval;
    } else {
        BestSensorConfig config = {samplingInterval, reportInterval};
        sensorConfig_.emplace(sensorId, config);
    }
    return;
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