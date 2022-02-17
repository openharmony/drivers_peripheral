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

#include "thermal_simulation_node.h"

#include <iostream>
#include <cstring>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "hdf_base.h"
#include "hdf_log.h"
#include "securec.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
namespace {
const int32_t MAX_BUFF_SIZE = 128;
const int MAX_PATH = 256;
const int ARG_0 = 0;
const int ARG_1 = 1;
const int ARG_2 = 2;
const int ARG_3 = 3;
const int ARG_4 = 4;
const std::string SIMULATION_TYPE_DIR = "/data/sensor/%s/type";
const std::string SIMULATION_TEMP_DIR = "/data/sensor/%s/temp";
std::string thermalDir = "/data/sensor/";
std::string thermalNodeDir = "/data/sensor/%s";
std::string thermalFileDir = "%s/%s";
std::string thermalTypeDir = "/data/sensor/%s/type";
std::string thermalTempDir = "/data/sensor/%s/temp";
std::string mitigationDir = "/data/cooling";
std::string mitigationNodeDir = "/data/cooling/%s";
std::string mitigationNodeFileDir = "%s/%s";
}
int32_t ThermalSimulationNode::NodeInit()
{
    int32_t ret = -1;
    ret = AddSensorTypeTemp();
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    ret = AddMitigationDevice();
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::CreateNodeDir(std::string dir)
{
    HDF_LOGI("%{public}s: Enter", __func__);
    if (access(dir.c_str(), 0) != HDF_SUCCESS) {
        int flag = mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH| S_IXOTH);
        if (flag == HDF_SUCCESS) {
            HDF_LOGI("%{public}s: Create directory successfully.", __func__);
        } else {
            HDF_LOGE("%{public}s: Fail to create directory, flag: %{public}d", __func__, flag);
            return flag;
        }
    } else {
        HDF_LOGE("%{public}s: This directory already exists.", __func__);
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::CreateNodeFile(std::string filePath)
{
    int32_t fd = -1;
    if (access(filePath.c_str(), 0) != 0) {
        fd = open(filePath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP| S_IROTH);
        if (fd < HDF_SUCCESS) {
            HDF_LOGE("%{public}s: open failed to file.", __func__);
            return fd;
        }
    } else {
        HDF_LOGI("%{public}s: the file already exists.", __func__);
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::AddSensorTypeTemp()
{
    int32_t ret = -1;
    std::string file[] = {"type", "temp"};
    std::vector<std::string> vFile(file, file + ARG_2);
    std::map<std::string, int32_t> sensor;
    char nodeBuf[MAX_PATH] = {0};
    char fileBuf[MAX_PATH] = {0};
    char typeBuf[MAX_PATH] = {0};
    char tempBuf[MAX_PATH] = {0};
    sensor["battery"] = 0;
    sensor["charger"] = 0;
    sensor["pa"] = 0;
    sensor["ap"] = 0;
    sensor["ambient"] = 0;
    sensor["cpu"] = 0;
    sensor["soc"] = 0;
    sensor["shell"] = 0;
    CreateNodeDir(thermalDir);
    for (auto dir : sensor) {
        ret = snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - ARG_1, thermalNodeDir.c_str(), dir.first.c_str());
        if (ret < HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        HDF_LOGI("%{public}s: node name: %{public}s", __func__, nodeBuf);
        CreateNodeDir(static_cast<std::string>(nodeBuf));
        for (auto file : vFile) {
            ret = snprintf_s(fileBuf, PATH_MAX, sizeof(fileBuf) - ARG_1, thermalFileDir.c_str(), nodeBuf, file.c_str());
            if (ret < HDF_SUCCESS) {
                return HDF_FAILURE;
            }
            HDF_LOGI("%{public}s: file name: %{public}s", __func__, fileBuf);
            CreateNodeFile(static_cast<std::string>(fileBuf));
        }
        ret = snprintf_s(typeBuf, PATH_MAX, sizeof(typeBuf) - ARG_1, thermalTypeDir.c_str(), dir.first.c_str());
        if (ret < HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        std::string type = dir.first + "\n";
        WriteFile(typeBuf, type, type.length());
        ret = snprintf_s(tempBuf, PATH_MAX, sizeof(tempBuf) - ARG_1, thermalTempDir.c_str(), dir.first.c_str());
        if (ret < HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        std::string temp = std::to_string(dir.second) + "\n";
        WriteFile(tempBuf, temp, temp.length());
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::AddMitigationDevice()
{
    int32_t ret = -1;
    std::string sensor[] = {"cpu", "charger", "gpu", "battery"};
    std::vector<std::string> vSensor(sensor, sensor + ARG_4);
    std::string cpu = "freq";
    std::string charger = "current";
    std::string gpu = "freq";
    std::string battery[] = {"current", "voltage"};
    std::vector<std::string> vFile, vBattery(battery, battery + ARG_2);
    char nodeBuf[MAX_PATH] = {0};
    char fileBuf[MAX_PATH] = {0};
    int32_t temp = 0;
    std::string sTemp = std::to_string(temp);
    CreateNodeDir(mitigationDir);
    for (auto dir : vSensor) {
        ret = snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - ARG_1, mitigationNodeDir.c_str(), dir.c_str());
        if (ret < HDF_SUCCESS) return HDF_FAILURE;
        CreateNodeDir(static_cast<std::string>(nodeBuf));
        vFile.push_back(nodeBuf);
    }
    ret = snprintf_s(fileBuf, PATH_MAX, sizeof(fileBuf) - ARG_1, mitigationNodeFileDir.c_str(), vFile[ARG_0].c_str(),
        cpu.c_str());
    if (ret < HDF_SUCCESS) return HDF_FAILURE;
    CreateNodeFile(static_cast<std::string>(fileBuf));
    WriteFile(fileBuf, sTemp, sTemp.length());
    ret = snprintf_s(fileBuf, PATH_MAX, sizeof(fileBuf) - ARG_1, mitigationNodeFileDir.c_str(), vFile[ARG_1].c_str(),
        charger.c_str());
    if (ret < HDF_SUCCESS) return HDF_FAILURE;
    CreateNodeFile(static_cast<std::string>(fileBuf));
    WriteFile(fileBuf, sTemp, sTemp.length());
    ret = snprintf_s(fileBuf, PATH_MAX, sizeof(fileBuf) - ARG_1, mitigationNodeFileDir.c_str(), vFile[ARG_2].c_str(),
        gpu.c_str());
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    CreateNodeFile(static_cast<std::string>(fileBuf));
    WriteFile(fileBuf, sTemp, sTemp.length());
    for (auto b : vBattery) {
        ret = snprintf_s(fileBuf, PATH_MAX, sizeof(fileBuf) - ARG_1, mitigationNodeFileDir.c_str(),
            vFile[ARG_3].c_str(), b.c_str());
        if (ret < HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        CreateNodeFile(static_cast<std::string>(fileBuf));
        WriteFile(fileBuf, sTemp, sTemp.length());
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::WriteFile(std::string path, std::string buf, size_t size)
{
    mutex_.lock();
    int32_t fd = open(path.c_str(), O_RDWR);
    if (fd < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: open failed to file.", __func__);
    }
    write(fd, buf.c_str(), size);
    mutex_.unlock();
    close(fd);
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::SetTempRequest(std::string type, int32_t temp)
{
    HDF_LOGI("%{public}s: enter", __func__);
    char tempBuf[MAX_PATH] = {0};
    int32_t ret = -1;
    ret = snprintf_s(tempBuf, PATH_MAX, sizeof(tempBuf) - ARG_1, thermalTempDir.c_str(), type.c_str());
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    std::string sTemp = std::to_string(temp);
    WriteFile(tempBuf, sTemp, sTemp.length());
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::ReadFile(const char *path, char *buf, size_t size)
{
    std::lock_guard<std::mutex> lck(mutex_);
    int32_t ret = -1;

    int32_t fd = open(path, O_RDONLY);
    if (fd < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: open failed to file.", __func__);
        return HDF_FAILURE;
    }

    ret = read(fd, buf, size);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to read file.", __func__);
        close(fd);
        return HDF_FAILURE;
    }

    close(fd);
    buf[size - 1] = '\0';
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::ConvertInt(const std::string &value)
{
    return std::stoi(value);
}

int32_t ThermalSimulationNode::ParserSimulationNode()
{
    HDF_LOGI("%{public}s: Enter", __func__);
    int32_t ret = -1;
    int32_t value = -1;
    char bufType[MAX_BUFF_SIZE] = {0};
    char bufTemp[MAX_BUFF_SIZE] = {0};
    char typeValue[MAX_BUFF_SIZE] = {0};
    char tempValue[MAX_BUFF_SIZE] = {0};
    std::vector<std::string> typeList;
    typeList.push_back("battery");
    typeList.push_back("charger");
    typeList.push_back("pa");
    typeList.push_back("ambient");
    typeList.push_back("ap");
    typeList.push_back("cpu");
    typeList.push_back("soc");
    typeList.push_back("shell");

    ClearThermalZoneInfo();
    for (auto type : typeList) {
        ThermalZoneInfo thermalZoneInfo;
        ret = snprintf_s(bufType, PATH_MAX, sizeof(bufType) - 1, SIMULATION_TYPE_DIR.c_str(), type.c_str());
        if (ret < HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        ret = snprintf_s(bufTemp, PATH_MAX, sizeof(bufTemp) - 1, SIMULATION_TEMP_DIR.c_str(), type.c_str());
        if (ret < HDF_SUCCESS) {
            return HDF_FAILURE;
        }
        ret = ReadFile(bufType, typeValue, sizeof(typeValue));
        if (ret != HDF_SUCCESS) {
            return ret;
        }
        std::string sensorType = typeValue;
        thermalZoneInfo.type = sensorType;
        HDF_LOGI("%{public}s: parse type: %{public}s", __func__, sensorType.c_str());

        ret = ReadFile(bufTemp, tempValue, sizeof(tempValue));
        if (ret != HDF_SUCCESS) {
            return ret;
        }
        std::string temp = tempValue;
        value = ConvertInt(temp);
        HDF_LOGI("%{public}s: parse temp: %{public}d", __func__, value);
        thermalZoneInfo.temp = value;
        tzInfoList_.push_back(thermalZoneInfo);
    }
    return HDF_SUCCESS;
}

void ThermalSimulationNode::ClearThermalZoneInfo()
{
    if (!tzInfoList_.empty()) {
        tzInfoList_.clear();
    } else {
        return;
    }
}
} // V1_0
} // Thermal
} // HDI
} // OHOS