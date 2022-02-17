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
#include <mutex>
#include <unistd.h>

#include "hdf_base.h"
#include "securec.h"
#include "utils/hdf_log.h"

#define HDF_LOG_TAG ThermalDeviceMitigation

namespace hdi {
namespace thermal {
namespace v1_0 {
namespace {
const int32_t MAX_PATH = 256;
const int32_t MAX_BUF_PATH = 256;
const std::string SIM_CPU_FREQ_PATH = "/data/cooling/cpu/freq";
const std::string GPU_FREQ_PATH = "/data/cooling/gpu/freq";
const std::string BATTERY_CHARGER_CURRENT_PATH = "/data/cooling/charger/current";
const std::string SIM_BATTERY_CURRENT_PATH = "/data/cooling/battery/current";
const std::string BATTERY_VOLTAGE_PATH = "/data/cooling/battery/voltage";
std::mutex mutex_;
const std::string ACTUAL_CPU_FREQ_PATH = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq";
const std::string ACTUAL_BATTERY_CURRENT_PATH = "/sys/class/power_supply/battery/input_current_limited";
}
int32_t ThermalDeviceMitigation::WriteSysfsFd(int32_t fd, std::string buf, size_t bytesSize)
{
    ssize_t pos = 0;
    ssize_t recever = 0;
    do {
        recever = write(fd, buf.c_str() + (size_t) pos, bytesSize - (size_t)pos);
        if (recever < HDF_SUCCESS) {
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
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to open file %{public}s", __func__, filePath.c_str());
        return ret;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::WriteSysfsFile(std::string filePath, std::string buf, size_t bytesSize)
{
    int32_t fd = OpenSysfsFile(filePath.c_str(), O_RDWR);
    if (fd < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, filePath.c_str());
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
    HDF_LOGI("CpuRequest %{public}s: the freq is %{public}d", __func__, freq);
    int32_t ret = -1;
    char freqBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    if (access(path.c_str(), 0) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - 1, "%s", path.c_str()) < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (snprintf_s(freqBuf, PATH_MAX, sizeof(freqBuf) - 1, "%d", freq) < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WriteSysfsFile(nodeBuf, freqBuf, strlen(freqBuf)) > HDF_SUCCESS) {
        HDF_LOGI("%{public}s: Set freq to %{public}d", __func__, freq);
        ret = 0;
    } else {
        HDF_LOGE("%{public}s: failed to set freq", __func__);
        ret = -1;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::CpuRequest(uint32_t freq)
{
    int32_t ret = ExecuteCpuRequest(freq, ACTUAL_CPU_FREQ_PATH);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to really set freq", __func__);
    }
    ret = ExecuteCpuRequest(freq, SIM_CPU_FREQ_PATH);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ThermalDeviceMitigation::ChargerRequest(uint32_t current)
{
    int32_t ret = ExecuteChargerRequest(current, ACTUAL_BATTERY_CURRENT_PATH);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to really set current", __func__);
    }
    ret = ExecuteChargerRequest(current, SIM_BATTERY_CURRENT_PATH);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ThermalDeviceMitigation::GpuRequest(uint32_t freq)
{
    HDF_LOGI("GpuRequest %{public}s: the freq is %{public}d", __func__, freq);
    int32_t ret;
    char freqBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - 1, "%s", GPU_FREQ_PATH.c_str());
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = snprintf_s(freqBuf, PATH_MAX, sizeof(freqBuf) - 1, "%d", freq);
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WriteSysfsFile(nodeBuf, freqBuf, strlen(freqBuf)) > HDF_SUCCESS) {
        HDF_LOGI("%{public}s: Set freq to %{public}d", __func__, freq);
        ret = 0;
    } else {
        HDF_LOGE("%{public}s: failed to set freq", __func__);
    }
    return ret;
}

int32_t ThermalDeviceMitigation::ExecuteChargerRequest(uint32_t current, const std::string &path)
{
    HDF_LOGI("%{public}s: the current is %{public}d", __func__, current);
    int32_t ret = -1;
    char currentBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    static uint32_t previous;
    if (access(path.c_str(), 0) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - 1, "%s", path.c_str());
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = snprintf_s(currentBuf, PATH_MAX, sizeof(currentBuf) - 1, "%d%s", current, "\n");
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WriteSysfsFile(nodeBuf, currentBuf, strlen(currentBuf)) > HDF_SUCCESS) {
        HDF_LOGI("%{public}s: Set current to %{public}d", __func__, current);
        previous = current;
        ret = 0;
    } else {
        HDF_LOGE("%{public}s: failed to set current", __func__);
        ret = -1;
    }
    return ret;
}

int32_t ThermalDeviceMitigation::BatteryCurrentRequest(uint32_t current)
{
    HDF_LOGI("%{public}s: current %{public}d", __func__, current);
    int32_t ret;
    char currentBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - 1, "%s", SIM_BATTERY_CURRENT_PATH.c_str());
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = snprintf_s(currentBuf, PATH_MAX, sizeof(currentBuf) - 1, "%d", current);
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WriteSysfsFile(nodeBuf, currentBuf, strlen(currentBuf)) > HDF_SUCCESS) {
        HDF_LOGI("%{public}s: Set current to %{public}d", __func__, current);
        ret = 0;
    } else {
        HDF_LOGE("%{public}s: failed to set current", __func__);
    }
    return ret;
}

int32_t ThermalDeviceMitigation::BatteryVoltageRequest(uint32_t voltage)
{
    HDF_LOGI("%{public}s: current %{public}d", __func__, voltage);
    int32_t ret;
    char voltageBuf[MAX_PATH] = {0};
    char voltageNode[MAX_BUF_PATH] = {0};

    std::lock_guard<std::mutex> lock(mutex_);
    ret = snprintf_s(voltageNode, PATH_MAX, sizeof(voltageNode) - 1, "%s", BATTERY_VOLTAGE_PATH.c_str());
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = snprintf_s(voltageBuf, PATH_MAX, sizeof(voltageBuf) - 1, "%d", voltage);
    if (ret < HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WriteSysfsFile(voltageNode, voltageBuf, strlen(voltageBuf)) > HDF_SUCCESS) {
        HDF_LOGI("%{public}s: Set current to %{public}d", __func__, voltage);
        ret = 0;
    } else {
        HDF_LOGE("%{public}s: failed to set current", __func__);
    }
    return ret;
}
} // v1_0
} // thermal
} // hdi