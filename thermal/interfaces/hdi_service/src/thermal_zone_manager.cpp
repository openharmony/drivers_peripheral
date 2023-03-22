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

#include "osal/osal_mem.h"
#include "thermal_log.h"

using namespace std;

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
namespace {
const int32_t MAX_BUFF_SIZE = 128;
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

inline void ThermalZoneManager::Trim(char* str) const
{
    if (str == nullptr) {
        return;
    }

    str[strcspn(str, "\n")] = 0;
}

int32_t ThermalZoneManager::ReadSysfsFile(const char* path, char* buf, size_t size) const
{
    int32_t readSize;
    int32_t fd = open(path, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
    if (fd < NUM_ZERO) {
        THERMAL_HILOGW(COMP_HDI, "failed to open file");
        return HDF_ERR_IO;
    }

    readSize = read(fd, buf, size - 1);
    if (readSize < NUM_ZERO) {
        THERMAL_HILOGW(COMP_HDI, "failed to read file");
        close(fd);
        return HDF_ERR_IO;
    }

    buf[readSize] = '\0';
    Trim(buf);
    close(fd);

    return HDF_SUCCESS;
}

int32_t ThermalZoneManager::ReadThermalSysfsToBuff(const char* path, char* buf, size_t size) const
{
    int32_t ret = ReadSysfsFile(path, buf, size);
    if (ret != HDF_SUCCESS) {
        THERMAL_HILOGW(COMP_HDI, "read path failed, ret: %{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t ThermalZoneManager::ParseThermalZoneInfo()
{
    int32_t ret;
    char bufType[MAX_BUFF_SIZE] = {0};
    THERMAL_HILOGD(COMP_HDI, "start to parse thermal zone");

    ret = InitThermalZoneSysfs();
    if (ret != HDF_SUCCESS) {
        THERMAL_HILOGE(COMP_HDI, "failed to init thermal zone node");
    }
    std::map<std::string, std::string> tzPathMap;
    if (!lTzSysPathInfo_.empty()) {
        THERMAL_HILOGI(COMP_HDI, "tzInfo.size=%{public}zu", GetLTZPathInfo().size());
        for (auto iter = lTzSysPathInfo_.begin(); iter != lTzSysPathInfo_.end(); iter++) {
            ret = ReadThermalSysfsToBuff(iter->typePath, bufType, sizeof(bufType));
            if (ret != HDF_SUCCESS) {
                THERMAL_HILOGE(COMP_HDI, "failed to read thermal zone type");
                return ret;
            }
            std::string tzType = bufType;
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
    std::vector<int32_t> multipleList;
    {
        // Multi-threaded access to sensorTypeMap_ requires locking
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto sensorIter : sensorTypeMap_) {
            auto tzInfoList = sensorIter.second->GetXMLThermalZoneInfo();
            auto tnInfoList = sensorIter.second->GetXMLThermalNodeInfo();
            sensorIter.second->thermalDataList_.clear();
            for (auto tzIter : tzInfoList) {
                if (tzPathMap.empty()) {
                    break;
                }
                auto typeIter = tzPathMap.find(tzIter.type);
                if (typeIter != tzPathMap.end()) {
                    ReportedThermalData data;
                    UpdateDataType(tzIter, data);
                    data.tempPath = typeIter->second;
                    sensorIter.second->thermalDataList_.push_back(data);
                }
            }
            for (auto tnIter : tnInfoList) {
                ReportedThermalData data;
                data.type = tnIter.type;
                if (access(tnIter.path.c_str(), 0) == NUM_ZERO) {
                    THERMAL_HILOGD(COMP_HDI, "This directory already exists.");
                    data.tempPath = tnIter.path;
                }
                sensorIter.second->thermalDataList_.push_back(data);
            }
        }
    }
    multipleList.push_back(reportTime);
    CalculateMaxCd();
    ReportThermalZoneData(reportTime, multipleList);
    return HDF_SUCCESS;
}

void ThermalZoneManager::ClearThermalZoneInfo()
{
    if (!tzInfoList_.empty()) {
        tzInfoList_.clear();
    } else {
        return;
    }
}

void ThermalZoneManager::CalculateMaxCd()
{
    std::lock_guard<std::mutex> lock(mutex_);
    sensorTypeMap_ = ThermalHdfConfig::GetInsance().GetSensorTypeMap();
    if (sensorTypeMap_.empty()) {
        THERMAL_HILOGE(COMP_HDI, "configured sensor info is empty");
        return;
    }

    std::vector<int32_t> intervalList;
    std::transform(sensorTypeMap_.begin(), sensorTypeMap_.end(), std::back_inserter(intervalList),
        [](auto& sensorIter) { return sensorIter.second->GetInterval(); });

    maxCd_ = GetIntervalCommonDivisor(intervalList);
    THERMAL_HILOGI(COMP_HDI, "maxCd_ %{public}d", maxCd_);
}

int32_t ThermalZoneManager::GetMaxCommonDivisor(int32_t a, int32_t b)
{
    if (b == 0) {
        return NUM_ZERO;
    }

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

void ThermalZoneManager::SetMultiples()
{
    if (maxCd_ == NUM_ZERO) {
        return;
    }
    for (auto sensorIter : sensorTypeMap_) {
        sensorIter.second->multiple_ = (sensorIter.second->GetInterval()) / maxCd_;
    }
    ThermalHdfConfig::GetInsance().SetSensorTypeMap(sensorTypeMap_);
}

void ThermalZoneManager::ReportThermalZoneData(int32_t reportTime, std::vector<int32_t> &multipleList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    char tempBuf[MAX_BUFF_SIZE] = {0};
    if (sensorTypeMap_.empty()) {
        THERMAL_HILOGD(COMP_HDI, "sensorTypeMap is empty");
        return;
    }

    int32_t ret;
    tzInfoAcaualEvent_.info.clear();
    multipleList.clear();
    for (auto sensorIter : sensorTypeMap_) {
        multipleList.push_back(sensorIter.second->multiple_);
        if (sensorIter.second->multiple_ == NUM_ZERO) {
            return;
        }
        THERMAL_HILOGD(COMP_HDI, "multiple %{public}d", sensorIter.second->multiple_);
        if (reportTime % (sensorIter.second->multiple_) == NUM_ZERO) {
            for (auto iter : sensorIter.second->thermalDataList_) {
                THERMAL_HILOGD(COMP_HDI, "data type %{public}s", iter.type.c_str());
                ThermalZoneInfo info;
                info.type = iter.type;
                ret = ReadThermalSysfsToBuff(iter.tempPath.c_str(), tempBuf, sizeof(tempBuf));
                if (ret != NUM_ZERO) {
                    THERMAL_HILOGE(COMP_HDI, "failed to read thermal zone temp");
                    continue;
                }
                info.temp = ConvertInt(tempBuf);
                THERMAL_HILOGD(COMP_HDI, "temp=%{public}d", info.temp);
                tzInfoAcaualEvent_.info.push_back(info);
            }
        }
    }
}
} // V1_0
} // Thermal
} // HDI
} // OHOS
