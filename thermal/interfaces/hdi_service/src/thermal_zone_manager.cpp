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
#include "utils/hdf_log.h"
#include "osal/osal_mem.h"

using namespace std;
namespace hdi {
namespace thermal {
namespace v1_0 {
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
}

void ThermalZoneManager::FormatThermalPaths(char *path, size_t size, const char *format, const char* name)
{
    if (snprintf_s(path, PATH_MAX, size - 1, format, name) < HDF_SUCCESS) {
        HDF_LOGW("%{public}s: failed to format path of %{public}s", __func__, name);
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

    HDF_LOGI("%{public}s: temp path: %{public}s, type path: %{public}s ",
        __func__, tzSysPathInfo_.temperturePath, tzSysPathInfo_.typePath);

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
        HDF_LOGE("%{public}s: cannot open thermal zone path", __func__);
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
            HDF_LOGI("%{public}s: init sysfs info of %{public}s", __func__, sysfsInfo.name);
            int32_t ret = sscanf_s(sysfsInfo.name, THERMAL_ZONE_DIR_NAME.c_str(), &id);
            if (ret < HDF_SUCCESS) {
                return ret;
            }

            HDF_LOGI("%{public}s: Sensor %{public}s found at tz: %{public}d", __func__, sysfsInfo.name, id);
            if (index > MAX_SYSFS_SIZE) {
                HDF_LOGE("%{public}s: too many plugged types", __func__);
                break;
            }
            FormatThermalSysfsPaths(&sysfsInfo);
            index++;
        }
    }
    closedir(dir);
    return HDF_SUCCESS;
}

int32_t ThermalZoneManager::ReadThermalSysfsPath(const char *path, char *buf, size_t size)
{
    int32_t ret = -1;

    int32_t fd = open(path, O_RDONLY);
    if (fd < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, path);
        return HDF_ERR_IO;
    }

    ret = read(fd, buf, size);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to read %{public}s, %{public}d", __func__, path, fd);
        close(fd);
        return HDF_ERR_IO;
    }

    close(fd);
    buf[size - 1] = '\0';
    return HDF_SUCCESS;
}

int32_t ThermalZoneManager::ReadThermalSysfsToBuff(const char *path, char *buf, size_t size)
{
    int32_t ret = -1;
    if (flag_) {
        if (tzSysPathInfo_.name == NULL) {
            HDF_LOGW("%{public}s: thermal sysfs info is not exist", __func__);
            return HDF_ERR_INVALID_OBJECT;
        }
    }

    ret = ReadThermalSysfsPath(path, buf, size);
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: read path %{public}s failed, ret: %{public}d", __func__, path, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t ThermalZoneManager::ParseThermalZoneInfo()
{
    int32_t ret = -1;
    char bufType[MAX_BUFF_SIZE] = {0};
    char bufTemp[MAX_BUFF_SIZE] = {0};
    ThermalZoneInfo thermalZoneInfo;
    int32_t value;
    ClearThermalZoneInfo();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        HDF_LOGI("%{public}s: tzInfo.size=%{public}zu", __func__, GetLTZPathInfo().size());
        for (auto it : GetLTZPathInfo()) {
            ret = ReadThermalSysfsToBuff(it.typePath, bufType, sizeof(bufType));
            if (ret != HDF_SUCCESS) {
                return ret;
            }
            HDF_LOGI("%{public}s: type %{public}s", __func__, bufType);
            std::string sensorType = bufType;
            thermalZoneInfo.type = sensorType;

            ret = ReadThermalSysfsToBuff(it.temperturePath, bufTemp, sizeof(bufTemp));
            if (ret != HDF_SUCCESS) {
                return ret;
            }
            std::string temp = bufTemp;
            value = ConvertInt(temp);
            HDF_LOGI("%{public}s: temp: %{public}d", __func__, value);
            thermalZoneInfo.temp = value;
            tzInfoList_.push_back(thermalZoneInfo);
        }
    }
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
} // v1_0
} // thermal
} // hdi