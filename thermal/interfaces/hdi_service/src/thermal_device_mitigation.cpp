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

#include "thermal_device_mitigation.h"

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <unistd.h>

#include "hdf_base.h"
#include "securec.h"
#include "hdf_log.h"
#include "thermal_log.h"
#include "thermal_hdf_config.h"

#define HDF_LOG_TAG ThermalDeviceMitigation

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {
const int32_t MAX_PATH = 256;
const int32_t MAX_BUF_PATH = 256;
const std::string SIM_CPU_FREQ_PATH = "/data/service/el0/thermal/cooling/cpu/freq";
const std::string GPU_FREQ_PATH = "/data/service/el0/thermal/cooling/gpu/freq";
const std::string BATTERY_CHARGER_CURRENT_PATH = "/data/service/el0/thermal/cooling/charger/current";
const std::string SIM_BATTERY_CURRENT_PATH = "/data/service/el0/thermal/cooling/battery/current";
const std::string BATTERY_VOLTAGE_PATH = "/data/service/el0/thermal/cooling/battery/voltage";
const std::string ACTUAL_BATTERY_CURRENT_PATH = "/sys/class/power_supply/battery/input_current_limited";
const int32_t NUM_ZERO = 0;
}
int32_t ThermalDeviceMitigation::WriteSysfsFd(int32_t fd, std::string buf, size_t bytesSize)
{
    ssize_t pos = 0;
    do {
        ssize_t recever = write(fd, buf.c_str() + (size_t) pos, bytesSize - (size_t)pos);
        if (recever < NUM_ZERO) {
            return recever;
        }
        pos += recever;
    } while ((ssize_t)bytesSize > pos);

    return (int32_t)bytesSize;
}

int32_t ThermalDeviceMitigation::OpenSysfsFile(std::string filePath, int32_t flags)
{
    int32_t ret;

    if (filePath.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }

    ret = open(filePath.c_str(), flags);
    if (ret < NUM_ZERO) {
        THERMAL_HILOGE(COMP_HDI, "failed to open file");
        return ret;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::WriteSysfsFile(std::string filePath, std::string buf, size_t bytesSize)
{
    std::fstream file(filePath.c_str(), std::ios::out | std::ios::trunc);
    file.close();
    int32_t fd = OpenSysfsFile(filePath.c_str(), O_RDWR);
    if (fd < NUM_ZERO) {
        THERMAL_HILOGE(COMP_HDI, "failed to open SysfsFile");
        return HDF_ERR_IO;
    }
    int32_t ret = WriteSysfsFd(fd, buf.c_str(), bytesSize);
    close(fd);
    return ret;
}

int32_t ThermalDeviceMitigation::SetFlag(bool flag)
{
    flag_ = flag;
    return HDF_SUCCESS;
}

int32_t ThermalDeviceMitigation::ExecuteCpuRequest(uint32_t freq, const std::string &path)
{
    int32_t ret = HDF_FAILURE;
    char freqBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    if (access(path.c_str(), 0) != NUM_ZERO) {
        return ret;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (snprintf_s(nodeBuf, MAX_BUF_PATH, sizeof(nodeBuf) - 1, "%s", path.c_str()) < EOK) {
        return ret;
    }
    if (snprintf_s(freqBuf, MAX_PATH, sizeof(freqBuf) - 1, "%u", freq) < EOK) {
        return ret;
    }
    if (WriteSysfsFile(nodeBuf, freqBuf, strlen(freqBuf)) > NUM_ZERO) {
        THERMAL_HILOGI(COMP_HDI, "Set freq to %{public}d", freq);
        ret = HDF_SUCCESS;
    } else {
        THERMAL_HILOGE(COMP_HDI, "failed to set freq");
        ret = HDF_FAILURE;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::CpuRequest(uint32_t freq)
{
    int32_t ret = ExecuteCpuRequest(freq, SIM_CPU_FREQ_PATH);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ThermalDeviceMitigation::ChargerRequest(uint32_t current)
{
    int32_t ret = ExecuteChargerRequest(current, ACTUAL_BATTERY_CURRENT_PATH);
    if (ret != HDF_SUCCESS) {
        THERMAL_HILOGE(COMP_HDI, "failed to really set current");
    }
    ret = ExecuteChargerRequest(current, SIM_BATTERY_CURRENT_PATH);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ThermalDeviceMitigation::GpuRequest(uint32_t freq)
{
    int32_t ret = HDF_FAILURE;
    char freqBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(nodeBuf, MAX_BUF_PATH, sizeof(nodeBuf) - 1, "%s", GPU_FREQ_PATH.c_str());
    if (ret < EOK) {
        return ret;
    }
    ret = snprintf_s(freqBuf, MAX_PATH, sizeof(freqBuf) - 1, "%u", freq);
    if (ret < EOK) {
        return ret;
    }
    if (WriteSysfsFile(nodeBuf, freqBuf, strlen(freqBuf)) > NUM_ZERO) {
        THERMAL_HILOGI(COMP_HDI, "Set freq to %{public}d", freq);
        ret = HDF_SUCCESS;
    } else {
        THERMAL_HILOGE(COMP_HDI, "failed to set freq");
        ret = HDF_FAILURE;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::ExecuteChargerRequest(uint32_t current, const std::string &path)
{
    int32_t ret = HDF_FAILURE;
    char currentBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    if (access(path.c_str(), 0) != NUM_ZERO) {
        return ret;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(nodeBuf, MAX_BUF_PATH, sizeof(nodeBuf) - 1, "%s", path.c_str());
    if (ret < EOK) {
        return ret;
    }
    ret = snprintf_s(currentBuf, MAX_PATH, sizeof(currentBuf) - 1, "%u%s", current, "\n");
    if (ret < EOK) {
        return ret;
    }
    if (WriteSysfsFile(nodeBuf, currentBuf, strlen(currentBuf)) > NUM_ZERO) {
        THERMAL_HILOGI(COMP_HDI, "Set current to %{public}d", current);
        ret = HDF_SUCCESS;
    } else {
        THERMAL_HILOGE(COMP_HDI, "failed to set current");
        ret = HDF_FAILURE;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::BatteryCurrentRequest(uint32_t current)
{
    int32_t ret = HDF_FAILURE;
    char currentBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(nodeBuf, MAX_BUF_PATH, sizeof(nodeBuf) - 1, "%s", SIM_BATTERY_CURRENT_PATH.c_str());
    if (ret < EOK) {
        return ret;
    }
    ret = snprintf_s(currentBuf, MAX_PATH, sizeof(currentBuf) - 1, "%u", current);
    if (ret < EOK) {
        return ret;
    }
    if (WriteSysfsFile(nodeBuf, currentBuf, strlen(currentBuf)) > NUM_ZERO) {
        THERMAL_HILOGI(COMP_HDI, "Set current to %{public}d", current);
        ret = HDF_SUCCESS;
    } else {
        THERMAL_HILOGE(COMP_HDI, "failed to set current");
        ret = HDF_FAILURE;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::BatteryVoltageRequest(uint32_t voltage)
{
    int32_t ret = HDF_FAILURE;
    char voltageBuf[MAX_PATH] = {0};
    char voltageNode[MAX_BUF_PATH] = {0};

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(voltageNode, MAX_BUF_PATH, sizeof(voltageNode) - 1, "%s", BATTERY_VOLTAGE_PATH.c_str());
    if (ret < EOK) {
        return ret;
    }
    ret = snprintf_s(voltageBuf, MAX_PATH, sizeof(voltageBuf) - 1, "%u", voltage);
    if (ret < EOK) {
        return ret;
    }
    if (WriteSysfsFile(voltageNode, voltageBuf, strlen(voltageBuf)) > NUM_ZERO) {
        THERMAL_HILOGI(COMP_HDI, "Set current to %{public}d", voltage);
        ret = HDF_SUCCESS;
    } else {
        THERMAL_HILOGE(COMP_HDI, "failed to set current");
        ret = HDF_FAILURE;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::IsolateCpu(int32_t num)
{
    int32_t ret = HDF_FAILURE;
    char valueBuf[MAX_PATH] = {0};
    char isolateCpuPath[MAX_BUF_PATH] = {0};
    std::string type = "soc";
    std::string path;

    ret = ThermalHdfConfig::GetInstance().GetIsolateCpuNodePath(flag_, type, path);
    if (ret != HDF_SUCCESS) {
        THERMAL_HILOGE(COMP_HDI, "get Isolate Cpu config path is null");
        return HDF_FAILURE;
    }

    ret = snprintf_s(isolateCpuPath, MAX_BUF_PATH, sizeof(isolateCpuPath) - 1, "%s", path.c_str());
    if (ret < EOK) {
        return ret;
    }

    ret = snprintf_s(valueBuf, MAX_PATH, sizeof(valueBuf) - 1, "%d", num);
    if (ret < EOK) {
        return ret;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (WriteSysfsFile(isolateCpuPath, valueBuf, strlen(valueBuf)) > NUM_ZERO) {
        THERMAL_HILOGI(COMP_HDI, "isolate cpu %{public}d", num);
        ret = HDF_SUCCESS;
    } else {
        THERMAL_HILOGE(COMP_HDI, "failed to isolate cpu");
        ret = HDF_FAILURE;
    }
    return ret;
}
} // V1_1
} // Thermal
} // HDI
} // OHOS
