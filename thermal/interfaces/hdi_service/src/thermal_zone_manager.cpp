/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "thermal_zone_manager.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <iostream>
#include <dirent.h>
#include <fcntl.h>
#include <climits>
#include <securec.h>
#include <unistd.h>
#include <sys/types.h>

#include "osal_mem.h"
#include "thermal_hdf_utils.h"
#include "thermal_log.h"

using namespace std;

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {
const std::string THERMAL_ZONE_TEMP_PATH = "/sys/class/thermal/thermal_zone%d/temp";
const std::string THERMAL_ZONE_TYPE_PATH = "/sys/class/thermal/thermal_zone%d/type";
const int32_t MAX_THERMAL_ZONE_NUM = 200;
const int32_t MAX_PATH_LEN = 64;
const int32_t NUM_ZERO = 0;
}

void ThermalZoneManager::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    InitThermalZoneSysfs();
    pollingMap_ = ThermalHdfConfig::GetInstance().GetPollingConfig();
}

void ThermalZoneManager::InitThermalZoneSysfs()
{
    int32_t maxTzNum = 0;
    for (int32_t idx = 0; idx < MAX_THERMAL_ZONE_NUM; ++idx) {
        char path[MAX_PATH_LEN];
        if (sprintf_s(path, MAX_PATH_LEN, THERMAL_ZONE_TYPE_PATH.c_str(), idx) <= 0) {
            break;
        }
        std::string type;
        if (!ThermalHdfUtils::ReadNode(path, type)) {
            break;
        }
        tznMap_[type] = idx;
        maxTzNum = idx;
    }
    THERMAL_HILOGI(COMP_HDI, "max thermal zone num is %{public}d", maxTzNum);
}

void ThermalZoneManager::UpdateDataType(XMLThermalZoneInfo& tzIter, ReportedThermalData& data, int32_t tzn)
{
    if (tzIter.isReplace) {
        data.type = tzIter.replace;
    } else {
        data.type = tzIter.type;
    }
    char path[MAX_PATH_LEN];
    if (sprintf_s(path, MAX_PATH_LEN, THERMAL_ZONE_TEMP_PATH.c_str(), tzn) > 0) {
        data.tempPath = path;
    } else {
        THERMAL_HILOGE(COMP_HDI, "thermal zone path format failed, num is %{public}d", tzn);
    }
}

void ThermalZoneManager::UpdateThermalZoneInfo(std::shared_ptr<SensorInfoConfig> &infoConfig)
{
    auto tzInfoList = infoConfig->GetXMLThermalZoneInfo();
    auto tnInfoList = infoConfig->GetXMLThermalNodeInfo();
    infoConfig->thermalDataList_.clear();
    for (auto tzIter : tzInfoList) {
        if (tznMap_.empty()) {
            break;
        }
        auto typeIter = tznMap_.find(tzIter.type);
        if (typeIter != tznMap_.end()) {
            ReportedThermalData data;
            UpdateDataType(tzIter, data, typeIter->second);
            infoConfig->thermalDataList_.push_back(data);
        }
    }
    for (auto tnIter : tnInfoList) {
        ReportedThermalData data;
        data.type = tnIter.type;
        if (access(tnIter.path.c_str(), 0) == NUM_ZERO) {
            THERMAL_HILOGD(COMP_HDI, "This directory already exists.");
            data.tempPath = tnIter.path;
        }
        infoConfig->thermalDataList_.push_back(data);
    }
}

int32_t ThermalZoneManager::UpdateThermalZoneData()
{
    {
        // Multi-thread access to pollingMap_ require lock
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &polling : pollingMap_) {
            for (auto &group : polling.second) {
                UpdateThermalZoneInfo(group.second);
            }
        }
    }

    CalculateMaxCd();
    return HDF_SUCCESS;
}

void ThermalZoneManager::CalculateMaxCd()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (pollingMap_.empty()) {
        THERMAL_HILOGE(COMP_HDI, "configured sensor info is empty");
        return;
    }
    std::vector<int32_t> intervalList;
    for (auto &polling : pollingMap_) {
        for (auto &group : polling.second) {
            intervalList.emplace_back(group.second->GetInterval());
        }
    }

    maxCd_ = GetIntervalCommonDivisor(intervalList);
    if (maxCd_ == 0) {
        return;
    }

    int32_t maxMultiple = 0;
    for (auto &polling : pollingMap_) {
        for (auto &group : polling.second) {
            group.second->multiple_ = group.second->GetInterval() / maxCd_;
            maxMultiple = std::max(maxMultiple, group.second->multiple_);
        }
    }
    maxReportTime_ = maxMultiple;

    THERMAL_HILOGI(COMP_HDI, "maxCd_ %{public}d maxReportTime_ %{public}d", maxCd_, maxReportTime_);
    return;
}

int32_t ThermalZoneManager::GetIntervalCommonDivisor(std::vector<int32_t> intervalList)
{
    if (intervalList.empty()) {
        return NUM_ZERO;
    }

    uint32_t count = intervalList.size();
    int32_t commonDivisor = intervalList[0];
    for (uint32_t i = 1; i < count; i++) {
        commonDivisor = ThermalHdfUtils::GetMaxCommonDivisor(commonDivisor, intervalList[i]);
    }
    return commonDivisor;
}

void ThermalZoneManager::CollectCallbackInfo(
    HdfThermalCallbackInfo &callbackInfo, const std::shared_ptr<SensorInfoConfig> &sensorInfo, int32_t reportTime)
{
    if (sensorInfo->multiple_ == NUM_ZERO) {
        return;
    }

    if (reportTime % (sensorInfo->multiple_) == NUM_ZERO) {
        for (auto iter : sensorInfo->thermalDataList_) {
            ThermalZoneInfo info;
            info.type = iter.type;
            info.temp = ThermalHdfUtils::ReadNodeToInt(iter.tempPath);
            THERMAL_HILOGD(COMP_HDI, "type: %{public}s temp: %{public}d", iter.type.c_str(), info.temp);
            callbackInfo.info.emplace_back(info);
        }
    }

    return;
}

void ThermalZoneManager::ReportThermalZoneData(int32_t reportTime)
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &polling : pollingMap_) {
        HdfThermalCallbackInfo callbackInfo;
        for (auto &group : polling.second) {
            CollectCallbackInfo(callbackInfo, group.second, reportTime);
        }
        if (!callbackInfo.info.empty()) {
            CallbackOnEvent(polling.first, callbackInfo);
        }
    }

    return;
}

void ThermalZoneManager::CallbackOnEvent(std::string name, HdfThermalCallbackInfo &info)
{
    if (name == "thermal") {
        if (thermalCb_ != nullptr) {
            thermalCb_->OnThermalDataEvent(info);
        }
    } else if (name == "fan") {
        if (fanCb_ != nullptr) {
            fanCb_->OnFanDataEvent(info);
        }
    }

    return;
}

HdfThermalCallbackInfo ThermalZoneManager::GetCallbackInfo()
{
    HdfThermalCallbackInfo callbackInfo;
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &polling : pollingMap_) {
        if (polling.first == "fan") {
            continue;
        }
        for (auto &group : polling.second) {
            for (auto iter : group.second->thermalDataList_) {
                ThermalZoneInfo info;
                info.type = iter.type;
                info.temp = ThermalHdfUtils::ReadNodeToInt(iter.tempPath);
                callbackInfo.info.emplace_back(info);
            }
        }
    }

    return callbackInfo;
}

void ThermalZoneManager::DumpPollingInfo()
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &polling : pollingMap_) {
        THERMAL_HILOGI(COMP_HDI, "pollingName %{public}s", polling.first.c_str());
        for (auto &group : polling.second) {
            THERMAL_HILOGI(COMP_HDI, "groupName %{public}s, interval %{public}d, multiple %{public}d",
                group.first.c_str(), group.second->GetInterval(), group.second->multiple_);
            for (auto tzIter : group.second->GetXMLThermalZoneInfo()) {
                THERMAL_HILOGI(COMP_HDI, "type %{public}s, replace %{public}s", tzIter.type.c_str(),
                    tzIter.replace.c_str());
            }
            for (auto tnIter : group.second->GetXMLThermalNodeInfo()) {
                THERMAL_HILOGI(COMP_HDI, "type %{public}s", tnIter.type.c_str());
            }
            for (auto dataIter : group.second->thermalDataList_) {
                THERMAL_HILOGI(COMP_HDI, "data type %{public}s", dataIter.type.c_str());
            }
        }
    }
}
} // V1_1
} // Thermal
} // HDI
} // OHOS
