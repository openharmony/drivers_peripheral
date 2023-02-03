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
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "hdf_base.h"
#include "securec.h"
#include "thermal_log.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
namespace {
const int32_t MAX_PATH = 256;
const int32_t ARG_0 = 0;
const int32_t ARG_1 = 1;
const int32_t ARG_2 = 2;
const int32_t ARG_3 = 3;
const int32_t ARG_4 = 4;
const int32_t NUM_ZERO = 0;
const std::string THERMAL_DIR = "/data/service/el0/thermal/sensor/";
const std::string THERMAL_NODE_DIR = "/data/service/el0/thermal/sensor/%s";
const std::string THERMAL_TYPE_DIR = "/data/service/el0/thermal/sensor/%s/type";
const std::string THERMAL_TEMP_DIR = "/data/service/el0/thermal/sensor/%s/temp";
const std::string MITIGATION_DIR = "/data/service/el0/thermal/cooling";
const std::string MITIGATION_NODE_DIR = "/data/service/el0/thermal/cooling/%s";
const std::string MITIGATION_NODE_FILE = "%s/%s";
}
int32_t ThermalSimulationNode::NodeInit()
{
    int32_t ret = AddSensorTypeTemp();
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
    if (access(dir.c_str(), 0) != NUM_ZERO) {
        int32_t flag = mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH| S_IXOTH);
        if (flag == NUM_ZERO) {
            THERMAL_HILOGI(COMP_HDI, "Create directory successfully.");
        } else {
            THERMAL_HILOGE(COMP_HDI, "Fail to create directory, flag: %{public}d", flag);
            return flag;
        }
    } else {
        THERMAL_HILOGD(COMP_HDI, "This directory already exists.");
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::CreateNodeFile(std::string filePath)
{
    if (access(filePath.c_str(), 0) != 0) {
        int32_t fd = open(filePath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP| S_IROTH);
        if (fd < NUM_ZERO) {
            THERMAL_HILOGE(COMP_HDI, "open failed to file.");
            return fd;
        }
        close(fd);
    } else {
        THERMAL_HILOGD(COMP_HDI, "the file already exists.");
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::AddSensorTypeTemp()
{
    std::vector<std::string> vFile = {"type", "temp"};
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
    CreateNodeDir(THERMAL_DIR);
    for (auto dir : sensor) {
        int32_t ret = snprintf_s(nodeBuf, MAX_PATH, sizeof(nodeBuf) - ARG_1,
            THERMAL_NODE_DIR.c_str(), dir.first.c_str());
        if (ret < EOK) {
            return HDF_FAILURE;
        }
        THERMAL_HILOGI(COMP_HDI, "node name: %{public}s", nodeBuf);
        CreateNodeDir(static_cast<std::string>(nodeBuf));
        for (const auto& file : vFile) {
            ret = snprintf_s(fileBuf, MAX_PATH, sizeof(fileBuf) - ARG_1, "%s/%s", nodeBuf, file.c_str());
            if (ret < EOK) {
                return HDF_FAILURE;
            }
            THERMAL_HILOGI(COMP_HDI, "file name: %{public}s", fileBuf);
            CreateNodeFile(static_cast<std::string>(fileBuf));
        }
        ret = snprintf_s(typeBuf, MAX_PATH, sizeof(typeBuf) - ARG_1, THERMAL_TYPE_DIR.c_str(), dir.first.c_str());
        if (ret < EOK) {
            return HDF_FAILURE;
        }
        std::string type = dir.first;
        WriteFile(typeBuf, type, type.length());
        ret = snprintf_s(tempBuf, MAX_PATH, sizeof(tempBuf) - ARG_1, THERMAL_TEMP_DIR.c_str(), dir.first.c_str());
        if (ret < EOK) {
            return HDF_FAILURE;
        }
        std::string temp = std::to_string(dir.second);
        WriteFile(tempBuf, temp, temp.length());
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::AddMitigationDevice()
{
    int32_t ret;
    std::string sensor[] = {"cpu", "charger", "gpu", "battery"};
    std::vector<std::string> vSensor(sensor, sensor + ARG_4);
    std::string cpu = "freq";
    std::string charger = "current";
    std::string gpu = "freq";
    std::string battery[] = {"current", "voltage"};
    std::vector<std::string> vFile;
    char nodeBuf[MAX_PATH] = {0};
    char fileBuf[MAX_PATH] = {0};
    int32_t temp = 0;
    std::string sTemp = std::to_string(temp);
    CreateNodeDir(MITIGATION_DIR);
    for (auto dir : vSensor) {
        ret = snprintf_s(nodeBuf, MAX_PATH, sizeof(nodeBuf) - ARG_1, MITIGATION_NODE_DIR.c_str(), dir.c_str());
        if (ret < EOK) return HDF_FAILURE;
        CreateNodeDir(static_cast<std::string>(nodeBuf));
        vFile.push_back(nodeBuf);
    }
    ret = snprintf_s(fileBuf, MAX_PATH, sizeof(fileBuf) - ARG_1, MITIGATION_NODE_FILE.c_str(), vFile[ARG_0].c_str(),
        cpu.c_str());
    if (ret < EOK) return HDF_FAILURE;
    CreateNodeFile(static_cast<std::string>(fileBuf));
    WriteFile(fileBuf, sTemp, sTemp.length());
    ret = snprintf_s(fileBuf, MAX_PATH, sizeof(fileBuf) - ARG_1, MITIGATION_NODE_FILE.c_str(), vFile[ARG_1].c_str(),
        charger.c_str());
    if (ret < EOK) return HDF_FAILURE;
    CreateNodeFile(static_cast<std::string>(fileBuf));
    WriteFile(fileBuf, sTemp, sTemp.length());
    ret = snprintf_s(fileBuf, MAX_PATH, sizeof(fileBuf) - ARG_1, MITIGATION_NODE_FILE.c_str(), vFile[ARG_2].c_str(),
        gpu.c_str());
    if (ret < EOK) {
        return HDF_FAILURE;
    }
    CreateNodeFile(static_cast<std::string>(fileBuf));
    WriteFile(fileBuf, sTemp, sTemp.length());
    std::vector<std::string> vBattery(battery, battery + ARG_2);
    for (auto b : vBattery) {
        ret = snprintf_s(fileBuf, MAX_PATH, sizeof(fileBuf) - ARG_1, MITIGATION_NODE_FILE.c_str(),
            vFile[ARG_3].c_str(), b.c_str());
        if (ret < EOK) {
            return HDF_FAILURE;
        }
        CreateNodeFile(static_cast<std::string>(fileBuf));
        WriteFile(fileBuf, sTemp, sTemp.length());
    }
    return HDF_SUCCESS;
}

int32_t ThermalSimulationNode::WriteFile(std::string path, std::string buf, size_t size)
{
    int32_t fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < NUM_ZERO) {
        THERMAL_HILOGE(COMP_HDI, "open failed to file.");
    }
    write(fd, buf.c_str(), size);
    close(fd);
    return HDF_SUCCESS;
}
} // V1_0
} // Thermal
} // HDI
} // OHOS
