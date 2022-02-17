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

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
namespace {
const int32_t MAX_PATH = 256;
const int32_t MAX_BUF_PATH = 256;
const std::string CPU_FREQ_PATH = "/data/cooling/cpu/freq";
const std::string GPU_FREQ_PATH = "/data/cooling/gpu/freq";
const std::string BATTERY_CHARGER_CURRENT_PATH = "/data/cooling/charger/current";
const std::string BATTERY_CURRENT_PATH = "/data/cooling/battery/current";
const std::string BATTERY_VOLTAGE_PATH = "/data/cooling/battery/voltage";
std::mutex mutex_;
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
    int32_t ret = -1;

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
    int32_t ret = -1;
    int32_t fd = -1;
    fd = OpenSysfsFile(filePath.c_str(), O_RDWR);
    if (fd < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, filePath.c_str());
        return HDF_ERR_IO;
    }
    ret = WriteSysfsFd(fd, buf.c_str(), bytesSize);
    close(fd);
    return ret;
}

int32_t ThermalDeviceMitigation::SetFlag(bool flag)
{
    flag_ = flag;
    return HDF_SUCCESS;
}

int32_t ThermalDeviceMitigation::CpuRequest(uint32_t freq)
{
    HDF_LOGI("CpuRequest %{public}s: the freq is %{public}d", __func__, freq);
    int32_t ret = -1;
    char freqBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    static uint32_t previous;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!flag_) {
        if (freq != previous) {
            if (snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - 1, "%s", CPU_FREQ_PATH.c_str()) < HDF_SUCCESS) {
                return HDF_FAILURE;
            }
            if (snprintf_s(freqBuf, PATH_MAX, sizeof(freqBuf) - 1, "%d", freq) < HDF_SUCCESS) {
                return HDF_FAILURE;
            }
            if (WriteSysfsFile(nodeBuf, freqBuf, strlen(freqBuf)) > HDF_SUCCESS) {
                HDF_LOGI("%{public}s: Set freq to %{public}d", __func__, freq);
                previous = freq;
                ret = 0;
            } else {
                HDF_LOGE("%{public}s: failed to set freq", __func__);
            }
        } else {
            HDF_LOGI("%{public}s: the freq mitigation is already at %{public}d", __func__, freq);
            ret = 0;
        }
    } else {
        HDF_LOGI("%{public}s: Write real mitigation device tuning nodes", __func__);
    }

    return ret;
}

int32_t ThermalDeviceMitigation::GpuRequest(uint32_t freq)
{
    HDF_LOGI("GpuRequest %{public}s: the freq is %{public}d", __func__, freq);
    int32_t ret = -1;
    char freqBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    static uint32_t previous;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!flag_) {
        if (freq != previous) {
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
                previous = freq;
                ret = 0;
            } else {
                HDF_LOGE("%{public}s: failed to set freq", __func__);
            }
        } else {
            HDF_LOGI("%{public}s: the freq mitigation is already at %{public}d", __func__, freq);
            ret = 0;
        }
    } else {
        HDF_LOGI("%{public}s: Write real mitigation device tuning nodes", __func__);
    }
    return ret;
}

int32_t ThermalDeviceMitigation::ChargerRequest(uint32_t current)
{
    HDF_LOGI("%{public}s: the current is %{public}d", __func__, current);
    int32_t ret = -1;
    char currentBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    static uint32_t previous;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!flag_) {
        if (current != previous) {
            ret = snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - 1, "%s", BATTERY_CHARGER_CURRENT_PATH.c_str());
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
            }
        } else {
            HDF_LOGI("%{public}s: the current mitigation is already at %{public}d", __func__, current);
            ret = 0;
        }
    } else {
        HDF_LOGI("%{public}s: Write real mitigation device tuning nodes", __func__);
    }
    return ret;
}

int32_t ThermalDeviceMitigation::BatteryCurrentRequest(uint32_t current)
{
    HDF_LOGI("%{public}s: current %{public}d", __func__, current);
    int32_t ret = -1;
    char currentBuf[MAX_PATH] = {0};
    char nodeBuf[MAX_BUF_PATH] = {0};
    static uint32_t previous;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!flag_) {
        if (current != previous) {
            ret = snprintf_s(nodeBuf, PATH_MAX, sizeof(nodeBuf) - 1, "%s", BATTERY_CURRENT_PATH.c_str());
            if (ret < HDF_SUCCESS) {
                return HDF_FAILURE;
            }
            ret = snprintf_s(currentBuf, PATH_MAX, sizeof(currentBuf) - 1, "%d", current);
            if (ret < HDF_SUCCESS) {
                return HDF_FAILURE;
            }
            if (WriteSysfsFile(nodeBuf, currentBuf, strlen(currentBuf)) > HDF_SUCCESS) {
                HDF_LOGI("%{public}s: Set current to %{public}d", __func__, current);
                previous = current;
                ret = 0;
            } else {
                HDF_LOGE("%{public}s: failed to set current", __func__);
            }
        } else {
            HDF_LOGI("%{public}s: the current mitigation is already at %{public}d", __func__, current);
            ret = 0;
        }
    } else {
        HDF_LOGI("%{public}s: Write real mitigation device tuning nodes", __func__);
    }
    return ret;
}

int32_t ThermalDeviceMitigation::BatteryVoltageRequest(uint32_t voltage)
{
    HDF_LOGI("%{public}s: current %{public}d", __func__, voltage);
    int32_t ret = -1;
    char voltageBuf[MAX_PATH] = {0};
    char voltageNode[MAX_BUF_PATH] = {0};
    static uint32_t previousVoltage;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!flag_) {
        if (voltage != previousVoltage) {
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
                previousVoltage = voltage;
                ret = 0;
            } else {
                HDF_LOGE("%{public}s: failed to set current", __func__);
            }
        } else {
            HDF_LOGI("%{public}s: the current mitigation is already at %{public}d", __func__, voltage);
            ret = 0;
        }
    } else {
        HDF_LOGI("%{public}s: Write real mitigation device tuning nodes", __func__);
    }
    return ret;
}
} // V1_0
} // Thermal
} // HDI
} // OHOS