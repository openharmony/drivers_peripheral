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
#include <iproxy_broker.h>

#define HDF_LOG_TAG uhdf_sensor_clients_manager

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {

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
    constexpr int32_t ZERO_PRINT_TIME = 0;
    constexpr int32_t MAX_PRINT_TIME = 30;
    constexpr int64_t INIT_REPORT_COUNT = 1;
}

std::mutex SensorClientsManager::instanceMutex_;

std::unordered_map<SensorHandle, std::unordered_map<int32_t, int64_t>> SensorClientsManager::sensorReportCountMap;

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

void SensorClientsManager::CopySensorInfo(std::vector<V3_0::HdfSensorInformation> &info, bool cFlag)
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

int SensorClientsManager::GetServiceId(int groupId, const sptr<IRemoteObject> &iRemoteObject)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    for (auto &iter : clients_[groupId]) {
        if (OHOS::HDI::hdi_objcast<V3_0::ISensorCallback>(iter.second.callbackV3_0) == iRemoteObject) {
            return iter.first;
        }
    }
    return HDF_FAILURE;
}

void SensorClientsManager::ReportDataCbRegister(int groupId, int serviceId,
                                                const sptr<V3_0::ISensorCallback> &callbackObj, bool oneway)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        if (callbackObj == nullptr) {
            HDF_LOGE("%{public}s: the callback of service %{public}d is null", __func__, serviceId);
            return;
        }
        SensorClientInfo sensorClientInfo;
        sensorClientInfo.callbackV3_0 = callbackObj;
        sensorClientInfo.oneway = oneway;
        clients_[groupId].emplace(serviceId, sensorClientInfo);
        HDF_LOGD("%{public}s: service %{public}d insert the callback", __func__, serviceId);
        return;
    }

    auto it = clients_[groupId].find(serviceId);
    it -> second.callbackV3_0 = callbackObj;
    it -> second.oneway = oneway;
    HDF_LOGD("%{public}s: service %{public}d update the callback", __func__, serviceId);

    return;
}

void SensorClientsManager::ReportDataCbUnRegister(int groupId, int serviceId,
    const sptr<V3_0::ISensorCallback> &callbackObj)
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

void SensorClientsManager::ReportDataCbOneWay(int groupId, int serviceId)
{
    SENSOR_TRACE_PID;
    HDF_LOGI("%{public}s: service: %{public}d", __func__, serviceId);
    std::unique_lock<std::mutex> lock(clientsMutex_);
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        HDF_LOGD("%{public}s: service %{public}d already UnRegister", __func__, serviceId);
        return;
    }

    auto it = clients_[groupId].find(serviceId);
    it->second.oneway = true;
    HDF_LOGI("%{public}s: service: %{public}d set oneway = true", __func__, serviceId);
    return;
}

void SensorClientsManager::UpdateSensorConfig(SensorHandle sensorHandle, int64_t samplingInterval,
                                              int64_t reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorHandle);
    if (it != sensorConfig_.end()) {
        it->second.samplingInterval = samplingInterval <= it->second.samplingInterval ? samplingInterval
         : it->second.samplingInterval;
        it->second.reportInterval = reportInterval <= it->second.reportInterval ? reportInterval
         : it->second.reportInterval;
    } else {
        BestSensorConfig config = {samplingInterval, reportInterval};
        sensorConfig_.emplace(sensorHandle, config);
    }
}

void SensorClientsManager::UpdateSdcSensorConfig(SensorHandle sensorHandle, int64_t samplingInterval,
                                                 int64_t reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorHandle);
    if (it != sdcSensorConfig_.end()) {
        it->second.samplingInterval = samplingInterval <= it->second.samplingInterval ? samplingInterval
         : it->second.samplingInterval;
        it->second.reportInterval = reportInterval <= it->second.reportInterval ? reportInterval
         : it->second.reportInterval;
    } else {
        BestSensorConfig config = {samplingInterval, reportInterval};
        sdcSensorConfig_.emplace(sensorHandle, config);
    }
}

void SensorClientsManager::UpdateClientPeriodCount(SensorHandle sensorHandle, int64_t samplingInterval,
                                                   int64_t reportInterval)
{
    SENSOR_TRACE_PID;
    HDF_LOGD("%{public}s: sensorHandle is %{public}s, samplingInterval is [%{public}" PRId64 "],"
        "reportInterval is [%{public}" PRId64 "]", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle),
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
        if (client.curCountMap_.find(sensorHandle) == client.curCountMap_.end() ||
            HdfRemoteGetCallingPid() == entry.first) {
            client.curCountMap_[sensorHandle] = INIT_CUR_COUNT;
        }
        if (client.sensorConfigMap_.find(sensorHandle) != client.sensorConfigMap_.end()) {
            int32_t periodCount =
                    client.sensorConfigMap_.find(sensorHandle)->second.samplingInterval / samplingInterval;
            result += " serviceId=" + std::to_string(entry.first) + ", sensorHandle=" +
                    SENSOR_HANDLE_TO_STRING(sensorHandle) + ", periodCount=" +
                      std::to_string(client.sensorConfigMap_.find(sensorHandle)->second.samplingInterval)
                      + "/" + std::to_string(samplingInterval) + "=" + std::to_string(periodCount);
            client.periodCountMap_[sensorHandle] = periodCount;
        }
    }
    HDF_LOGI("%{public}s: %{public}s", __func__, result.c_str());
}

void SensorClientsManager::SetSensorBestConfig(SensorHandle sensorHandle, int64_t &samplingInterval,
                                               int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorHandle);
    if (it == sensorConfig_.end()) {
        HDF_LOGD("%{public}s: sensorHandle: %{public}s is enabled first time", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return;
    }

    samplingInterval = samplingInterval < it->second.samplingInterval ? samplingInterval : it->second.samplingInterval;
    reportInterval = reportInterval < it->second.reportInterval ? reportInterval : it->second.reportInterval;
    HDF_LOGD("%{public}s: sensorHandle is %{public}s, after SetSensorBestConfig, samplingInterval is %{public}s, "
             "reportInterval is %{public}s", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle),
             std::to_string(samplingInterval).c_str(), std::to_string(reportInterval).c_str());
    return;
}

void SensorClientsManager::SetSdcSensorBestConfig(SensorHandle sensorHandle, int64_t &samplingInterval,
                                                  int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorHandle);
    if (it == sdcSensorConfig_.end()) {
        HDF_LOGD("%{public}s: sensorHandle: %{public}s is enabled by sdc first time", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return;
    }

    samplingInterval = samplingInterval < it->second.samplingInterval ? samplingInterval : it->second.samplingInterval;
    reportInterval = reportInterval < it->second.reportInterval ? reportInterval : it->second.reportInterval;
    HDF_LOGD("%{public}s: sensorHandle is %{public}s, after SetSdcSensorBestConfig, samplingInterval is %{public}s, "
             "reportInterval is %{public}s", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle),
             std::to_string(samplingInterval).c_str(), std::to_string(reportInterval).c_str());
    return;
}


void SensorClientsManager::GetSensorBestConfig(SensorHandle sensorHandle, int64_t &samplingInterval,
                                               int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorHandle);
    if (it == sensorConfig_.end()) {
        samplingInterval = STOP_INTERVAL;
        reportInterval = STOP_INTERVAL;
        HDF_LOGD("%{public}s: sensorHandle: %{public}s has no best config", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return;
    }

    samplingInterval = it->second.samplingInterval;
    reportInterval = it->second.reportInterval;
    HDF_LOGD("%{public}s: sensorHandle is %{public}s, after GetSensorBestConfig, samplingInterval is %{public}s, "
             "reportInterval is %{public}s", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle),
             std::to_string(samplingInterval).c_str(),
             std::to_string(reportInterval).c_str());
    return;
}

int64_t SensorClientsManager::GetSensorBestSamplingInterval(SensorHandle sensorHandle)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    auto it = sensorConfig_.find(sensorHandle);
    if (it == sensorConfig_.end()) {
        HDF_LOGD("%{public}s: sensorHandle: %{public}s has no best config", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return STOP_INTERVAL;
    }
    
    return it->second.samplingInterval;
}

void SensorClientsManager::EraseSdcSensorBestConfig(SensorHandle sensorHandle)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorHandle);
    if (it == sdcSensorConfig_.end()) {
        HDF_LOGD("%{public}s: sensorHandle: %{public}s sdcSensorBestConfig not exist, not need erase", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return;
    }
    sdcSensorConfig_.erase(it);
    HDF_LOGD("%{public}s: sensorHandle: %{public}s config has been erase from sdcSensorConfig_", __func__,
             SENSOR_HANDLE_TO_C_STR(sensorHandle));
    return;
}

void SensorClientsManager::OpenSensor(SensorHandle sensorHandle, int serviceId)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    std::set<int> service = {serviceId};
    sensorUsed_.emplace(sensorHandle, service);
    HDF_LOGD("%{public}s: service: %{public}d enabled sensorHandle %{public}s", __func__,  serviceId,
             SENSOR_HANDLE_TO_C_STR(sensorHandle));
}

bool SensorClientsManager::IsNeedOpenSensor(SensorHandle sensorHandle, int serviceId)
{
    SENSOR_TRACE_PID;
    auto it = sensorUsed_.find(sensorHandle);
    if (it == sensorUsed_.end()) {
        HDF_LOGD("%{public}s: sensorHandle %{public}s is enabled by service: %{public}d", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle), serviceId);
        return true;
    }
    auto service = sensorUsed_[sensorHandle].find(serviceId);
    if (service == sensorUsed_[sensorHandle].end()) {
        sensorUsed_[sensorHandle].insert(serviceId);
        HDF_LOGD("%{public}s: service: %{public}d enabled sensorHandle %{public}s", __func__,  serviceId,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
    }
    return false;
}

bool SensorClientsManager::IsNeedCloseSensor(SensorHandle sensorHandle, int serviceId)
{
    SENSOR_TRACE_PID;
    auto it = sensorUsed_.find(sensorHandle);
    if (it == sensorUsed_.end()) {
        HDF_LOGE("%{public}s: sensorHandle %{public}s has been disabled  or not support", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return true;
    }
    sensorUsed_[sensorHandle].erase(serviceId);
    if (sensorUsed_[sensorHandle].empty()) {
        sensorUsed_.erase(sensorHandle);
        sensorConfig_.erase(sensorHandle);
        HDF_LOGD("%{public}s: disabled sensorHandle %{public}s", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return true;
    }
    for (auto sid : sensorUsed_[sensorHandle]) {
        HDF_LOGD("%{public}s: sensorHandle %{public}s also is enable by service %{public}d", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle), sid);
    }
    return false;
}

bool SensorClientsManager::IsExistSdcSensorEnable(SensorHandle sensorHandle)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sdcSensorConfigMutex_);
    auto it = sdcSensorConfig_.find(sensorHandle);
    if (it == sdcSensorConfig_.end()) {
        return false;
    }
    HDF_LOGE("%{public}s: sensorHandle %{public}s has been enabled by sdc service", __func__,
             SENSOR_HANDLE_TO_C_STR(sensorHandle));
    return true;
}

bool SensorClientsManager::IsUpadateSensorState(SensorHandle sensorHandle, int serviceId, bool isOpen)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    if (isOpen && IsNeedOpenSensor(sensorHandle, serviceId)) {
        return true;
    }
    if (!isOpen && IsNeedCloseSensor(sensorHandle, serviceId)) {
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

bool SensorClientsManager::GetBestSensorConfigMap(std::unordered_map<SensorHandle, struct BestSensorConfig> &map)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(sensorConfigMutex_);
    map = sensorConfig_;
    return true;
}

void SensorClientsManager::SetClientSenSorConfig(SensorHandle sensorHandle, int32_t serviceId, int64_t samplingInterval,
                                                 int64_t &reportInterval)
{
    SENSOR_TRACE_PID;
    std::unique_lock<std::mutex> lock(clientsMutex_);
    HDF_LOGD("%{public}s: service %{public}d enter the SetClientSenSorConfig function, sensorHandle is %{public}s, "
             "samplingInterval is %{public}s, reportInterval is %{public}s", __func__, serviceId,
             SENSOR_HANDLE_TO_C_STR(sensorHandle), std::to_string(samplingInterval).c_str(),
             std::to_string(reportInterval).c_str());

    int32_t groupId = HDF_TRADITIONAL_SENSOR_TYPE;
    if (clients_.find(groupId) == clients_.end() || clients_[groupId].find(serviceId) == clients_[groupId].end()) {
        HDF_LOGE("%{public}s: service %{public}d already UnRegister", __func__, serviceId);
        return;
    }

    auto &client = clients_[groupId].find(serviceId)->second;
    SensorConfig sensorConfig = {samplingInterval, reportInterval};
    client.sensorConfigMap_[sensorHandle] = sensorConfig;
}

bool SensorClientsManager::IsSensorContinues(SensorHandle sensorHandle)
{
    return std::find(continuesSensor.begin(), continuesSensor.end(), sensorHandle.sensorType) != continuesSensor.end();
}

bool SensorClientsManager::IsNotNeedReportData(SensorClientInfo &sensorClientInfo, const SensorHandle sensorHandle,
                                               const int32_t &serviceId)
{
    SENSOR_TRACE;
    if (!SensorClientsManager::IsSensorContinues(sensorHandle)) {
        return false;
    }
    if (sensorClientInfo.periodCountMap_.find(sensorHandle) == sensorClientInfo.periodCountMap_.end()) {
        return false;
    }
    bool result = true;
    sensorClientInfo.PrintClientMapInfo(serviceId, sensorHandle);
    if (sensorClientInfo.curCountMap_[sensorHandle] == 0) {
        result = false;
    }
    sensorClientInfo.curCountMap_[sensorHandle]++;
    if (sensorClientInfo.curCountMap_[sensorHandle] >= sensorClientInfo.periodCountMap_[sensorHandle]) {
        sensorClientInfo.curCountMap_[sensorHandle] = 0;
    }
    return result;
}

std::set<int32_t> SensorClientsManager::GetServiceIds(SensorHandle sensorHandle)
{
    SENSOR_TRACE;
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    if (sensorUsed_.find(sensorHandle) == sensorUsed_.end()) {
        HDF_LOGD("%{public}s sensorHandle %{public}s is not enabled by anyone", __func__,
                 SENSOR_HANDLE_TO_C_STR(sensorHandle));
        return std::set<int32_t>();
    }
    return sensorUsed_.find(sensorHandle)->second;
}

std::string SensorClientsManager::ReportEachClient(const V3_0::HdfSensorEvents& event)
{
    SENSOR_TRACE;
    std::string result = "services=";
    SensorHandle sensorHandle =  {event.deviceSensorInfo.deviceId, event.deviceSensorInfo.sensorType,
                                  event.deviceSensorInfo.sensorId, event.deviceSensorInfo.location};
    const std::set<int32_t> services = GetServiceIds(sensorHandle);
    int32_t groupId = HDF_TRADITIONAL_SENSOR_TYPE;
    {
        std::unique_lock<std::mutex> lock(clientsMutex_);
        if (clients_.find(groupId) == clients_.end() || clients_.find(groupId)->second.empty()) {
            HDF_LOGE("%{public}s groupId %{public}d is not enabled by anyone", __func__, groupId);
            return result;
        }
    }
    for (auto it = services.begin(); it != services.end(); ++it) {
        int32_t serviceId = *it;

        static struct SensorInfoId sensorInfoId;
        sensorInfoId.sensorHandle = sensorHandle;
        sensorInfoId.serviceId = serviceId;

        sptr<V3_0::ISensorCallback> callbackV3_0 = nullptr;
        {
            std::unique_lock<std::mutex> lock(clientsMutex_);
            if (clients_.find(groupId)->second.find(serviceId) == clients_.find(groupId)->second.end()) {
                continue;
            }
            SensorClientInfo &sensorClientInfo = clients_.find(groupId)->second.find(serviceId)->second;
            if (IsNotNeedReportData(sensorClientInfo, sensorHandle, serviceId)) {
                continue;
            }
            sensorInfoId.oneway = sensorClientInfo.oneway;
            callbackV3_0 = sensorClientInfo.callbackV3_0;

            if (callbackV3_0 == nullptr) {
                HDF_LOGD("%{public}s the callback of %{public}d is nullptr", __func__, serviceId);
                continue;
            }
        }
        HITRACE_METER_FMT(HITRACE_TAG_HDF, "%s: serviceId %d, sensorHandle %s", __func__, serviceId,
                          SENSOR_HANDLE_TO_C_STR(event.deviceSensorInfo));

        HdiReportData(callbackV3_0, event, result, sensorInfoId);
    }
    return result;
}

void SensorClientsManager::HdiReportData(const sptr<V3_0::ISensorCallback> &callbackObj,
                                         const V3_0::HdfSensorEvents& event, std::string &result,
                                         SensorInfoId sensorInfoId)
{
    int32_t ret = HDF_SUCCESS;
    if (sensorInfoId.oneway) {
        std::vector<OHOS::HDI::Sensor::V3_0::HdfSensorEvents> eventsVector;
        eventsVector.push_back(std::move(event));
        callbackObj->OnDataEventAsync(eventsVector);
    } else {
        ret = callbackObj->OnDataEvent(event);
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGD("%{public}s Sensor OnDataEvent failed, error code is %{public}d", __func__, ret);
    } else {
        auto it = sensorReportCountMap[sensorInfoId.sensorHandle].find(sensorInfoId.serviceId);
        int64_t reportCount = INIT_REPORT_COUNT;
        if (it == sensorReportCountMap[sensorInfoId.sensorHandle].end()) {
            sensorReportCountMap[sensorInfoId.sensorHandle][sensorInfoId.serviceId] = INIT_REPORT_COUNT;
        } else {
            it->second++;
            reportCount = it->second;
        }
        result += std::to_string(sensorInfoId.serviceId) + "-" + std::to_string(reportCount) + " ";
    }
}

std::unordered_map<SensorHandle, std::set<int32_t>> SensorClientsManager::GetSensorUsed()
{
    std::unique_lock<std::mutex> lock(sensorUsedMutex_);
    return sensorUsed_;
}

void SensorClientsManager::ReSetSensorPrintTime(SensorHandle sensorHandle)
{
    SENSOR_TRACE;
    std::unique_lock<std::mutex> lock(sensorPrintTimesMutex_);
    sensorPrintTimes_[sensorHandle] = ZERO_PRINT_TIME;
}

bool SensorClientsManager::IsSensorNeedPrint(SensorHandle sensorHandle)
{
    SENSOR_TRACE;
    std::unique_lock<std::mutex> lock(sensorPrintTimesMutex_);
    auto it = sensorPrintTimes_.find(sensorHandle);
    if (it == sensorPrintTimes_.end() || it->second > MAX_PRINT_TIME) {
        return false;
    }
    it->second++;
    return true;
}

SensorClientsManager* SensorClientsManager::GetInstance()
{
    static SensorClientsManager *instance = new SensorClientsManager();
    return instance;
}

} // V3_0
} // Sensor
} // HDI
} // OHOS