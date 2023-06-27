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
const int32_t MAX_SYSFS_SIZE = 128;
const std::string THERMAL_SYSFS = "/sys/devices/virtual/thermal";
const std::string THERMAL_ZONE_DIR_NAME = "thermal_zone%d";
const std::string COOLING_DEVICE_DIR_NAME = "cooling_device%d";
const std::string THERMAL_ZONE_DIR_PATH = "/sys/class/thermal/%s";
const std::string THERMAL_TEMPERATURE_PATH = "/sys/class/thermal/%s/temp";
const std::string THEERMAL_TYPE_PATH = "/sys/class/thermal/%s/type";
const std::string CDEV_DIR_NAME = "cooling_device";
const std::string THERMAL_ZONE_TEMP_PATH_NAME = "/sys/class/thermal/thermal_zone%d/temp";
const uint32_t ARG_0 = 0;
const int32_t NUM_ZERO = 0;
const int32_t MS_PER_SECOND = 1000;
}

void ThermalZoneManager::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    pollingMap_ = ThermalHdfConfig::GetInstance().GetPollingConfig();
}

void ThermalZoneManager::FormatThermalPaths(char *path, size_t size, const char *format, const char* name)
{
    if (snprintf_s(path, size, size - 1, format, name) < EOK) {
        THERMAL_HILOGW(COMP_HDI, "failed to format path of %{public}s", name);
    }
}

void ThermalZoneManager::FormatThermalSysfsPaths(struct ThermalSysfsPathInfo *pTSysPathInfo)
{
    // Format Paths for thermal path
    FormatThermalPaths(pTSysPathInfo->thermalZonePath, sizeof(pTSysPathInfo->thermalZonePath),
        THERMAL_ZONE_DIR_PATH.c_str(), pTSysPathInfo->name);
    // Format paths for thermal zone node
    tzSysPathInfo_.name = pTSysPathInfo->name;
    FormatThermalPaths(tzSysPathInfo_.temperturePath, sizeof(tzSysPathInfo_.temperturePath),
        THERMAL_TEMPERATURE_PATH.c_str(), pTSysPathInfo->name);

    FormatThermalPaths(tzSysPathInfo_.typePath, sizeof(tzSysPathInfo_.typePath),
        THEERMAL_TYPE_PATH.c_str(), pTSysPathInfo->name);

    tzSysPathInfo_.fd = pTSysPathInfo->fd;
    lTzSysPathInfo_.push_back(tzSysPathInfo_);
}

int32_t ThermalZoneManager::InitThermalZoneSysfs()
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    int32_t index = 0;
    int32_t id = 0;

    dir = opendir(THERMAL_SYSFS.c_str());
    if (dir == NULL) {
        THERMAL_HILOGE(COMP_HDI, "cannot open thermal zone path");
        return HDF_ERR_IO;
    }

    while (true) {
        entry = readdir(dir);
        if (entry == NULL) {
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (strncmp(entry->d_name, CDEV_DIR_NAME.c_str(), CDEV_DIR_NAME.size()) == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR || entry->d_type == DT_LNK) {
            struct ThermalSysfsPathInfo sysfsInfo = {0};
            sysfsInfo.name = entry->d_name;
            THERMAL_HILOGI(COMP_HDI, "init sysfs info of %{public}s", sysfsInfo.name);
            int32_t ret = sscanf_s(sysfsInfo.name, THERMAL_ZONE_DIR_NAME.c_str(), &id);
            if (ret < HDF_SUCCESS) {
                closedir(dir);
                return ret;
            }

            THERMAL_HILOGI(COMP_HDI, "Sensor %{public}s found at tz: %{public}d", sysfsInfo.name, id);
            sysfsInfo.fd = id;
            if (index > MAX_SYSFS_SIZE) {
                THERMAL_HILOGE(COMP_HDI, "too many plugged types");
                break;
            }

            FormatThermalSysfsPaths(&sysfsInfo);
            index++;
        }
    }
    closedir(dir);
    return HDF_SUCCESS;
}

int32_t ThermalZoneManager::ParseThermalZoneInfo()
{
    int32_t ret;
    THERMAL_HILOGD(COMP_HDI, "start to parse thermal zone");

    ret = InitThermalZoneSysfs();
    if (ret != HDF_SUCCESS) {
        THERMAL_HILOGE(COMP_HDI, "failed to init thermal zone node");
    }
    std::map<std::string, std::string> tzPathMap;
    if (!lTzSysPathInfo_.empty()) {
        THERMAL_HILOGI(COMP_HDI, "thermal_zone size: %{public}zu", GetLTZPathInfo().size());
        for (auto iter = lTzSysPathInfo_.begin(); iter != lTzSysPathInfo_.end(); iter++) {
            std::string tzType;
            if (!ThermalHdfUtils::ReadNode(iter->typePath, tzType)) {
                THERMAL_HILOGE(COMP_HDI, "read tz type failed");
                continue;
            }
            tzPathMap.insert(std::make_pair(tzType, iter->temperturePath));
        }
    }
    return UpdateThermalZoneData(tzPathMap);
}

void ThermalZoneManager::UpdateDataType(XMLThermalZoneInfo& tzIter, ReportedThermalData& data)
{
    if (tzIter.isReplace) {
        data.type = tzIter.isReplace;
    } else {
        data.type = tzIter.type;
    }
}

int32_t ThermalZoneManager::UpdateThermalZoneData(std::map<std::string, std::string> &tzPathMap)
{
    int32_t reportTime = 1;
    {
        // Multi-thread access to pollingMap_ require lock
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &polling : pollingMap_) {
            for (auto &group : polling.second) {
                auto tzInfoList = group.second->GetXMLThermalZoneInfo();
                auto tnInfoList = group.second->GetXMLThermalNodeInfo();
                group.second->thermalDataList_.clear();
                for (auto tzIter : tzInfoList) {
                    if (tzPathMap.empty()) {
                        break;
                    }
                    auto typeIter = tzPathMap.find(tzIter.type);
                    if (typeIter != tzPathMap.end()) {
                        ReportedThermalData data;
                        UpdateDataType(tzIter, data);
                        data.tempPath = typeIter->second;
                        group.second->thermalDataList_.push_back(data);
                    }
                }
                for (auto tnIter : tnInfoList) {
                    ReportedThermalData data;
                    data.type = tnIter.type;
                    if (access(tnIter.path.c_str(), 0) == NUM_ZERO) {
                        THERMAL_HILOGD(COMP_HDI, "This directory already exists.");
                        data.tempPath = tnIter.path;
                    }
                    group.second->thermalDataList_.push_back(data);
                }
            }
        }
    }
    CalculateMaxCd();
    ReportThermalZoneData(reportTime);
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

int32_t ThermalZoneManager::GetMaxCommonDivisor(int32_t a, int32_t b)
{
    if (b == 0) {
        return NUM_ZERO;
    }

    a = a / MS_PER_SECOND * MS_PER_SECOND;
    b = b / MS_PER_SECOND * MS_PER_SECOND;

    if (a % b == 0) {
        return b;
    } else {
        return GetMaxCommonDivisor(b, a % b);
    }
}

int32_t ThermalZoneManager::GetIntervalCommonDivisor(std::vector<int32_t> intervalList)
{
    if (intervalList.empty()) {
        return ARG_0;
    }

    int32_t count = intervalList.size();
    int32_t commonDivisor = intervalList[0];
    for (int32_t i = 1; i < count; i++) {
        commonDivisor = GetMaxCommonDivisor(commonDivisor, intervalList[i]);
    }
    return commonDivisor;
}

void ThermalZoneManager::ReportThermalZoneData(int32_t reportTime)
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &polling : pollingMap_) {
        HdfThermalCallbackInfo callbackInfo;
        for (auto &group : polling.second) {
            if (group.second->multiple_ == NUM_ZERO) {
                continue;
            }

            if (reportTime % (group.second->multiple_) == NUM_ZERO) {
                for (auto iter : group.second->thermalDataList_) {
                    ThermalZoneInfo info;
                    info.type = iter.type;
                    info.temp = ThermalHdfUtils::ReadNodeToInt(iter.tempPath);
                    THERMAL_HILOGD(COMP_HDI, "type: %{public}s temp: %{public}d", iter.type.c_str(), info.temp);
                    callbackInfo.info.emplace_back(info);
                }
            }
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
