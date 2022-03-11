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

#include "hdi_service_test.h"
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <streambuf>
#include <sys/stat.h>
#include <thread>
#include <vector>
#include "battery_service.h"
#include "battery_thread_test.h"
#include "battery_vibrate.h"
#include "hdf_base.h"
#include "power_supply_provider.h"
#include "utils/hdf_log.h"

#define HDF_LOG_TAG HdiServiceTest

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HDI::Battery::V1_0;
using namespace OHOS::PowerMgr;
using namespace std;

namespace HdiServiceTest {
const std::string SYSTEM_BATTERY_PATH = "/sys/class/power_supply";
static std::vector<std::string> g_filenodeName;
static std::map<std::string, std::string> g_nodeInfo;
const int STR_TO_LONG_LEN = 10;
const int NUM_ZERO = 0;
std::unique_ptr<PowerSupplyProvider> giver_ = nullptr;

void HdiServiceTest::SetUpTestCase(void)
{
    giver_ = std::make_unique<PowerSupplyProvider>();
    if (giver_ == nullptr) {
        HDF_LOGI("%{public}s: Failed to get PowerSupplyProvider", __func__);
    }
}

void HdiServiceTest::TearDownTestCase(void)
{
}

void HdiServiceTest::SetUp(void)
{
}

void HdiServiceTest::TearDown(void)
{
}

struct StringEnumMap {
    const char* str;
    int32_t enumVal;
};

std::string CreateFile(std::string path, std::string content)
{
    std::ofstream stream(path.c_str());
    if (!stream.is_open()) {
        HDF_LOGI("%{public}s: Cannot create file %{public}s", __func__, path.c_str());
        return nullptr;
    }
    stream << content.c_str() << std::endl;
    stream.close();
    return path;
}

static void CheckSubfolderNode(const std::string& path)
{
    DIR *dir = nullptr;
    struct dirent* entry = nullptr;
    std::string batteryPath = SYSTEM_BATTERY_PATH + "/" + path;
    HDF_LOGI("%{public}s: subfolder path is:%{public}s", __func__, batteryPath.c_str());

    dir = opendir(batteryPath.c_str());
    if (dir == nullptr) {
        HDF_LOGI("%{public}s: subfolder file is not exist.", __func__);
        return;
    }

    while (true) {
        entry = readdir(dir);
        if (entry == nullptr) {
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR || entry->d_type == DT_LNK) {
            continue;
        }

        if ((strcmp(entry->d_name, "type") == 0) && (g_nodeInfo["type"] == "") &&
            (strcasecmp(path.c_str(), "battery") != 0)) {
            g_nodeInfo["type"] = path;
        }

        for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
            if ((strcmp(entry->d_name, iter->first.c_str()) == 0) && (g_nodeInfo[iter->first] == "")) {
                g_nodeInfo[iter->first] = path;
            }
        }
    }
    closedir(dir);
}

static void TraversalBaseNode()
{
    g_nodeInfo.insert(std::make_pair("type", ""));
    g_nodeInfo.insert(std::make_pair("online", ""));
    g_nodeInfo.insert(std::make_pair("current_max", ""));
    g_nodeInfo.insert(std::make_pair("voltage_max", ""));
    g_nodeInfo.insert(std::make_pair("capacity", ""));
    g_nodeInfo.insert(std::make_pair("voltage_now", ""));
    g_nodeInfo.insert(std::make_pair("temp", ""));
    g_nodeInfo.insert(std::make_pair("health", ""));
    g_nodeInfo.insert(std::make_pair("status", ""));
    g_nodeInfo.insert(std::make_pair("present", ""));
    g_nodeInfo.insert(std::make_pair("charge_counter", ""));
    g_nodeInfo.insert(std::make_pair("technology", ""));
    g_nodeInfo.insert(std::make_pair("charge_full", ""));
    g_nodeInfo.insert(std::make_pair("current_avg", ""));
    g_nodeInfo.insert(std::make_pair("current_now", ""));
    g_nodeInfo.insert(std::make_pair("charge_now", ""));

    auto iter = g_filenodeName.begin();
    while (iter != g_filenodeName.end()) {
        if (*iter == "battery") {
            CheckSubfolderNode(*iter);
            iter = g_filenodeName.erase(iter);
        } else {
            iter++;
        }
    }

    iter = g_filenodeName.begin();
    while (iter != g_filenodeName.end()) {
        if (*iter == "Battery") {
            CheckSubfolderNode(*iter);
            iter = g_filenodeName.erase(iter);
        } else {
            iter++;
        }
    }

    for (auto it = g_filenodeName.begin(); it != g_filenodeName.end(); ++it) {
        CheckSubfolderNode(*it);
    }
}

static int32_t InitBaseSysfs(void)
{
    DIR* dir = nullptr;
    struct dirent* entry = nullptr;
    int32_t index = 0;

    dir = opendir(SYSTEM_BATTERY_PATH.c_str());
    if (dir == nullptr) {
        HDF_LOGE("%{public}s: cannot open POWER_SUPPLY_BASE_PATH", __func__);
        return HDF_ERR_IO;
    }

    while (true) {
        entry = readdir(dir);
        if (entry == nullptr) {
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR || entry->d_type == DT_LNK) {
            HDF_LOGI("%{public}s: init sysfs info of %{public}s", __func__, entry->d_name);
            if (index >= MAX_SYSFS_SIZE) {
                HDF_LOGE("%{public}s: too many plugged types", __func__);
                break;
            }
            g_filenodeName.emplace_back(entry->d_name);
            index++;
        }
    }

    TraversalBaseNode();
    HDF_LOGI("%{public}s: index is %{public}d", __func__, index);
    closedir(dir);

    return HDF_SUCCESS;
}

static int32_t ReadTemperatureSysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    InitBaseSysfs();
    std::string tempNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "temp") {
            tempNode = iter->second;
            break;
        }
    }
    std::string sysBattTemPath = SYSTEM_BATTERY_PATH + "/" + tempNode + "/" + "temp";
    HDF_LOGE("%{public}s: sysBattTemPath is %{public}s", __func__, sysBattTemPath.c_str());

    int fd = open(sysBattTemPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysBattTemPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysBattTemPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t battTemperature = strtol(buf, nullptr, strlen);
    if (battTemperature < NUM_ZERO) {
        HDF_LOGE("%{public}s: read system file temperature is %{public}d", __func__, battTemperature);
    }
    HDF_LOGE("%{public}s: read system file temperature is %{public}d", __func__, battTemperature);
    close(fd);
    return battTemperature;
}

static int32_t ReadVoltageSysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    std::string voltageNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "voltage_now") {
            voltageNode = iter->second;
            break;
        }
    }
    std::string sysBattVolPath = SYSTEM_BATTERY_PATH + "/" + voltageNode + "/" + "voltage_now";
    HDF_LOGE("%{public}s: sysBattVolPath is %{public}s", __func__, sysBattVolPath.c_str());

    int fd = open(sysBattVolPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysBattVolPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysBattVolPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t battVoltage = strtol(buf, nullptr, strlen);
    if (battVoltage < NUM_ZERO) {
        HDF_LOGE("%{public}s: read system file voltage is %{public}d", __func__, battVoltage);
    }
    HDF_LOGE("%{public}s: read system file voltage is %{public}d", __func__, battVoltage);
    close(fd);
    return battVoltage;
}

static int32_t ReadCapacitySysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    std::string capacityNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "capacity") {
            capacityNode = iter->second;
            break;
        }
    }
    std::string sysBattCapPath = SYSTEM_BATTERY_PATH + "/" + capacityNode + "/" + "capacity";
    HDF_LOGE("%{public}s: sysBattCapPath is %{public}s", __func__, sysBattCapPath.c_str());

    int fd = open(sysBattCapPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysBattCapPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysBattCapPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t battCapacity = strtol(buf, nullptr, strlen);
    if (battCapacity < NUM_ZERO) {
        HDF_LOGE("%{public}s: read system file capacity is %{public}d", __func__, battCapacity);
    }
    HDF_LOGE("%{public}s: read system file capacity is %{public}d", __func__, battCapacity);
    close(fd);
    return battCapacity;
}

static int32_t ReadTotalEnergySysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    InitBaseSysfs();
    std::string totalEnergyNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "charge_full") {
            totalEnergyNode = iter->second;
            break;
        }
    }
    std::string sysBattTotalEnergyPath = SYSTEM_BATTERY_PATH + "/" + totalEnergyNode + "/" + "charge_full";
    HDF_LOGE("%{public}s: sysBattTotalEnergyPath is %{public}s", __func__, sysBattTotalEnergyPath.c_str());

    int fd = open(sysBattTotalEnergyPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysBattTotalEnergyPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysBattTotalEnergyPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t totalEnergy = strtol(buf, nullptr, strlen);
    if (totalEnergy < NUM_ZERO) {
        HDF_LOGE("%{public}s: read system file totalEnergy is %{public}d", __func__, totalEnergy);
    }
    HDF_LOGE("%{public}s: read system file totalEnergy is %{public}d", __func__, totalEnergy);
    close(fd);
    return totalEnergy;
}

static int32_t ReadCurrentAverageSysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    InitBaseSysfs();
    std::string currentAvgNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "current_avg") {
            currentAvgNode = iter->second;
            break;
        }
    }
    std::string sysBattCurrentAvgPath = SYSTEM_BATTERY_PATH + "/" + currentAvgNode + "/" + "current_avg";
    HDF_LOGE("%{public}s: sysBattCurrentAvgPath is %{public}s", __func__, sysBattCurrentAvgPath.c_str());

    int fd = open(sysBattCurrentAvgPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysBattCurrentAvgPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysBattCurrentAvgPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t currentAvg = strtol(buf, nullptr, strlen);
    if (currentAvg < NUM_ZERO) {
        HDF_LOGE("%{public}s: read system file currentAvg is %{public}d", __func__, currentAvg);
    }
    HDF_LOGE("%{public}s: read system file currentAvg is %{public}d", __func__, currentAvg);
    close(fd);
    return currentAvg;
}

static int32_t ReadCurrentNowSysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    InitBaseSysfs();
    std::string currentNowNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "current_now") {
            currentNowNode = iter->second;
            break;
        }
    }
    std::string sysBattCurrentNowPath = SYSTEM_BATTERY_PATH + "/" + currentNowNode + "/" + "current_now";
    HDF_LOGE("%{public}s: sysBattCurrentNowPath is %{public}s", __func__, sysBattCurrentNowPath.c_str());

    int fd = open(sysBattCurrentNowPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysBattCurrentNowPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysBattCurrentNowPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t currentNow = strtol(buf, nullptr, strlen);
    if (currentNow < NUM_ZERO) {
        HDF_LOGE("%{public}s: read system file currentNow is %{public}d", __func__, currentNow);
    }
    HDF_LOGE("%{public}s: read system file currentNow is %{public}d", __func__, currentNow);
    close(fd);
    return currentNow;
}

static int32_t ReadRemainEnergySysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    InitBaseSysfs();
    std::string chargeNowNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "charge_now") {
            chargeNowNode = iter->second;
            break;
        }
    }
    std::string sysBattChargeNowPath = SYSTEM_BATTERY_PATH + "/" + chargeNowNode + "/" + "charge_now";
    HDF_LOGE("%{public}s: sysBattChargeNowPath is %{public}s", __func__, sysBattChargeNowPath.c_str());

    int fd = open(sysBattChargeNowPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysBattChargeNowPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysBattChargeNowPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t chargeNow = strtol(buf, nullptr, strlen);
    if (chargeNow < NUM_ZERO) {
        HDF_LOGE("%{public}s: read system file chargeNow is %{public}d", __func__, chargeNow);
    }
    HDF_LOGE("%{public}s: read system file chargeNow is %{public}d", __func__, chargeNow);
    close(fd);
    return chargeNow;
}

static void Trim(char* str)
{
    if (str == nullptr) {
        return;
    }
    str[strcspn(str, "\n")] = 0;
}

static int32_t HealthStateEnumConverter(const char* str)
{
    struct StringEnumMap healthStateEnumMap[] = {
        { "Good", PowerSupplyProvider::BATTERY_HEALTH_GOOD },
        { "Cold", PowerSupplyProvider::BATTERY_HEALTH_COLD },
        { "Warm", PowerSupplyProvider::BATTERY_HEALTH_GOOD }, // JEITA specification
        { "Cool", PowerSupplyProvider::BATTERY_HEALTH_GOOD }, // JEITA specification
        { "Hot", PowerSupplyProvider::BATTERY_HEALTH_OVERHEAT }, // JEITA specification
        { "Overheat", PowerSupplyProvider::BATTERY_HEALTH_OVERHEAT },
        { "Over voltage", PowerSupplyProvider::BATTERY_HEALTH_OVERVOLTAGE },
        { "Dead", PowerSupplyProvider::BATTERY_HEALTH_DEAD },
        { "Unknown", PowerSupplyProvider::BATTERY_HEALTH_UNKNOWN },
        { "Unspecified failure", PowerSupplyProvider::BATTERY_HEALTH_UNKNOWN },
        { NULL, PowerSupplyProvider::BATTERY_HEALTH_UNKNOWN },
    };

    for (int i = 0; healthStateEnumMap[i].str; ++i) {
        if (strcmp(str, healthStateEnumMap[i].str) == 0) {
            return healthStateEnumMap[i].enumVal;
        }
    }

    return PowerSupplyProvider::BATTERY_HEALTH_UNKNOWN;
}

static int32_t ReadHealthStateSysfs()
{
    char buf[128] = {0};
    int32_t readSize;
    std::string healthNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "health") {
            healthNode = iter->second;
            break;
        }
    }
    std::string sysHealthStatePath = SYSTEM_BATTERY_PATH + "/" + healthNode + "/" + "health";
    HDF_LOGE("%{public}s: sysHealthStatePath is %{public}s", __func__, sysHealthStatePath.c_str());

    int fd = open(sysHealthStatePath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysHealthStatePath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysHealthStatePath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    Trim(buf);

    int32_t battHealthState = HealthStateEnumConverter(buf);
    HDF_LOGE("%{public}s: read system file healthState is %{public}d", __func__, battHealthState);
    close(fd);
    return battHealthState;
}

static int32_t PluggedTypeEnumConverter(const char* str)
{
    struct StringEnumMap pluggedTypeEnumMap[] = {
        { "USB", PowerSupplyProvider::PLUGGED_TYPE_USB },
        { "USB_PD_DRP", PowerSupplyProvider::PLUGGED_TYPE_USB },
        { "Wireless", PowerSupplyProvider::PLUGGED_TYPE_WIRELESS },
        { "Mains", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "UPS", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "USB_ACA", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "USB_C", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "USB_CDP", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "USB_DCP", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "USB_HVDCP", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "USB_PD", PowerSupplyProvider::PLUGGED_TYPE_AC },
        { "Unknown", PowerSupplyProvider::PLUGGED_TYPE_BUTT },
        { NULL, PowerSupplyProvider::PLUGGED_TYPE_BUTT },
    };

    for (int i = 0; pluggedTypeEnumMap[i].str; ++i) {
        if (strcmp(str, pluggedTypeEnumMap[i].str) == 0) {
            return pluggedTypeEnumMap[i].enumVal;
        }
    }

    return PowerSupplyProvider::PLUGGED_TYPE_BUTT;
}


static int32_t GetPluggedTypeName()
{
    char buf[128] = {0};
    std::string onlineNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "online") {
            onlineNode = iter->second;
            break;
        }
    }
    std::string sysOnlinePath = SYSTEM_BATTERY_PATH + "/" + onlineNode + "/" + "online";
    HDF_LOGE("%{public}s: sysOnlinePath is %{public}s", __func__, sysOnlinePath.c_str());

    int fd = open(sysOnlinePath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysOnlinePath.c_str());
        return HDF_FAILURE;
    }

    int32_t readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysOnlinePath.c_str());
        close(fd);
        return HDF_FAILURE;
    }
    buf[readSize] = '\0';
    Trim(buf);

    int32_t online = strtol(buf, nullptr, STR_TO_LONG_LEN);
    return online;
}

static int32_t ReadPluggedTypeSysfs()
{
    char buf[128] = {0};
    int32_t readSize;
    int32_t online = GetPluggedTypeName();
    if (online != 1) {
        return PowerSupplyProvider::PLUGGED_TYPE_NONE;
    }

    std::string typeNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "type") {
            typeNode = iter->second;
            break;
        }
    }
    std::string sysPluggedTypePath = SYSTEM_BATTERY_PATH + "/" + typeNode + "/" + "type";
    HDF_LOGE("%{public}s: sysPluggedTypePath is %{public}s", __func__, sysPluggedTypePath.c_str());

    int fd = open(sysPluggedTypePath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysPluggedTypePath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysPluggedTypePath.c_str());
        close(fd);
        return HDF_FAILURE;
    }
    buf[readSize] = '\0';
    Trim(buf);
    int32_t battPlugType = PluggedTypeEnumConverter(buf);
    if (battPlugType == PowerSupplyProvider::PLUGGED_TYPE_BUTT) {
        HDF_LOGW("%{public}s: not support the online type %{public}s", __func__, buf);
        battPlugType = PowerSupplyProvider::PLUGGED_TYPE_NONE;
    }

    HDF_LOGE("%{public}s: read system file pluggedType is %{public}d", __func__, battPlugType);
    close(fd);
    return battPlugType;
}

int32_t ChargeStateEnumConverter(const char* str)
{
    struct StringEnumMap chargeStateEnumMap[] = {
        { "Discharging", PowerSupplyProvider::CHARGE_STATE_NONE },
        { "Charging", PowerSupplyProvider::CHARGE_STATE_ENABLE },
        { "Full", PowerSupplyProvider::CHARGE_STATE_FULL },
        { "Not charging", PowerSupplyProvider::CHARGE_STATE_DISABLE },
        { "Unknown", PowerSupplyProvider::CHARGE_STATE_RESERVED },
        { NULL, PowerSupplyProvider::CHARGE_STATE_RESERVED },
    };

    for (int i = 0; chargeStateEnumMap[i].str; ++i) {
        if (strcmp(str, chargeStateEnumMap[i].str) == 0) {
            return chargeStateEnumMap[i].enumVal;
        }
    }
    return PowerSupplyProvider::CHARGE_STATE_RESERVED;
}

static int32_t ReadChargeStateSysfs()
{
    char buf[128] = {0};
    int32_t readSize;
    std::string statusNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "status") {
            statusNode = iter->second;
            break;
        }
    }
    std::string sysChargeStatePath = SYSTEM_BATTERY_PATH + "/" + statusNode + "/" + "status";
    HDF_LOGE("%{public}s: sysChargeStatePath is %{public}s", __func__, sysChargeStatePath.c_str());

    int fd = open(sysChargeStatePath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysChargeStatePath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysChargeStatePath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    Trim(buf);
    int32_t battChargeState = ChargeStateEnumConverter(buf);
    HDF_LOGE("%{public}s: read system file chargeState is %{public}d", __func__, battChargeState);
    close(fd);

    return battChargeState;
}

static int32_t ReadChargeCounterSysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    std::string counterNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "charge_counter") {
            counterNode = iter->second;
            break;
        }
    }
    std::string sysChargeCounterPath = SYSTEM_BATTERY_PATH + "/" + counterNode + "/" + "charge_counter";
    HDF_LOGE("%{public}s: sysChargeCounterPath is %{public}s", __func__, sysChargeCounterPath.c_str());

    int fd = open(sysChargeCounterPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysChargeCounterPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysChargeCounterPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t battChargeCounter = strtol(buf, nullptr, strlen);
    if (battChargeCounter < 0) {
        HDF_LOGE("%{public}s: read system file chargeState is %{public}d", __func__, battChargeCounter);
    }
    HDF_LOGE("%{public}s: read system file chargeState is %{public}d", __func__, battChargeCounter);
    close(fd);

    return battChargeCounter;
}

static int32_t ReadPresentSysfs()
{
    int strlen = 10;
    char buf[128] = {0};
    int32_t readSize;
    std::string presentNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "present") {
            presentNode = iter->second;
            break;
        }
    }
    std::string sysPresentPath = SYSTEM_BATTERY_PATH + "/" + presentNode + "/" + "present";
    HDF_LOGE("%{public}s: sysPresentPath is %{public}s", __func__, sysPresentPath.c_str());

    int fd = open(sysPresentPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysPresentPath.c_str());
        return HDF_FAILURE;
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysPresentPath.c_str());
        close(fd);
        return HDF_FAILURE;
    }

    buf[readSize] = '\0';
    int32_t battPresent = strtol(buf, nullptr, strlen);
    if (battPresent < 0) {
        HDF_LOGE("%{public}s: read system file chargeState is %{public}d", __func__, battPresent);
    }
    HDF_LOGE("%{public}s: read system file chargeState is %{public}d", __func__, battPresent);
    close(fd);
    return battPresent;
}

static std::string ReadTechnologySysfs(std::string& battTechnology)
{
    char buf[128] = {0};
    int32_t readSize;
    std::string technologyNode = "battery";
    for (auto iter = g_nodeInfo.begin(); iter != g_nodeInfo.end(); ++iter) {
        if (iter->first == "technology") {
            technologyNode = iter->second;
            break;
        }
    }
    std::string sysTechnologyPath = SYSTEM_BATTERY_PATH + "/" + technologyNode + "/" + "technology";
    HDF_LOGE("%{public}s: sysTechnologyPath is %{public}s", __func__, sysTechnologyPath.c_str());

    int fd = open(sysTechnologyPath.c_str(), O_RDONLY);
    if (fd < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to open %{public}s", __func__, sysTechnologyPath.c_str());
        return "";
    }

    readSize = read(fd, buf, sizeof(buf) - 1);
    if (readSize < NUM_ZERO) {
        HDF_LOGE("%{public}s: failed to read %{public}s", __func__, sysTechnologyPath.c_str());
        close(fd);
        return "";
    }
    buf[readSize] = '\0';
    Trim(buf);

    battTechnology.assign(buf, strlen(buf));
    HDF_LOGE("%{public}s: read system file technology is %{public}s.", __func__, battTechnology.c_str());
    close(fd);
    return battTechnology;
}

static bool IsNotMock()
{
    bool rootExist = access(SYSTEM_BATTERY_PATH.c_str(), F_OK) == 0;
    bool lowerExist = access((SYSTEM_BATTERY_PATH + "/battery").c_str(), F_OK) == 0;
    bool upperExist = access((SYSTEM_BATTERY_PATH + "/Battery").c_str(), F_OK) == 0;
    return rootExist && (lowerExist || upperExist);
}

/**
 * @tc.name: ProviderIsNotNull
 * @tc.desc: Test functions of PowerSupplyProvider
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, ProviderIsNotNull, TestSize.Level1)
{
    ASSERT_TRUE(giver_ != nullptr);
    if (!IsNotMock()) {
        std::string path = "/data/local/tmp";
        giver_->SetSysFilePath(path);
        HDF_LOGI("%{public}s: Is mock test", __func__);
    }
    giver_->InitPowerSupplySysfs();
}

/**
 * @tc.name: HdiService001
 * @tc.desc: Test functions of ParseTemperature
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService001, TestSize.Level1)
{
    int32_t temperature = 0;
    if (IsNotMock()) {
        giver_->ParseTemperature(&temperature);
        int32_t sysfsTemp = ReadTemperatureSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService001::temperature=%{public}d, t=%{public}d",
            __func__, temperature, sysfsTemp);
        ASSERT_TRUE(temperature == sysfsTemp);
    } else {
        CreateFile("/data/local/tmp/battery/temp", "567");
        giver_->ParseTemperature(&temperature);
        HDF_LOGI("%{public}s: HdiService001::temperature=%{public}d.", __func__, temperature);
        ASSERT_TRUE(temperature == 567);
    }
}

/**
 * @tc.name: HdiService002
 * @tc.desc: Test functions of ParseVoltage
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService002, TestSize.Level1)
{
    int32_t voltage = 0;
    if (IsNotMock()) {
        giver_->ParseVoltage(&voltage);
        int32_t sysfsVoltage = ReadVoltageSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService002::voltage=%{public}d, v=%{public}d",
            __func__, voltage, sysfsVoltage);
        ASSERT_TRUE(voltage == sysfsVoltage);
    } else {
        CreateFile("/data/local/tmp/battery/voltage_avg", "4123456");
        CreateFile("/data/local/tmp/battery/voltage_now", "4123456");
        giver_->ParseVoltage(&voltage);
        HDF_LOGI("%{public}s: Not Mock HdiService002::voltage=%{public}d", __func__, voltage);
        ASSERT_TRUE(voltage == 4123456);
    }
}

/**
 * @tc.name: HdiService003
 * @tc.desc: Test functions of ParseCapacity
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService003, TestSize.Level1)
{
    int32_t capacity = -1;
    if (IsNotMock()) {
        giver_->ParseCapacity(&capacity);
        int32_t sysfsCapacity = ReadCapacitySysfs();
        HDF_LOGI("%{public}s: Not Mcok HdiService003::capacity=%{public}d, l=%{public}d",
            __func__, capacity, sysfsCapacity);
        ASSERT_TRUE(capacity == sysfsCapacity);
    } else {
        CreateFile("/data/local/tmp/battery/capacity", "11");
        giver_->ParseCapacity(&capacity);
        HDF_LOGI("%{public}s: HdiService003::capacity=%{public}d", __func__, capacity);
        ASSERT_TRUE(capacity == 11);
    }
}

/**
 * @tc.name: HdiService004
 * @tc.desc: Test functions of ParseHealthState
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService004, TestSize.Level1)
{
    int32_t healthState = -1;
    if (IsNotMock()) {
        giver_->ParseHealthState(&healthState);
        int32_t sysfsHealthState = ReadHealthStateSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService004::healthState=%{public}d, h=%{public}d",
            __func__, healthState, sysfsHealthState);
        ASSERT_TRUE(healthState == sysfsHealthState);
    } else {
        CreateFile("/data/local/tmp/battery/health", "Good");
        giver_->ParseHealthState(&healthState);
        HDF_LOGI("%{public}s: HdiService004::healthState=%{public}d.", __func__, healthState);
        ASSERT_TRUE(PowerSupplyProvider::BatteryHealthState(healthState) ==
            PowerSupplyProvider::BatteryHealthState::BATTERY_HEALTH_GOOD);
    }
}

/**
 * @tc.name: HdiService005
 * @tc.desc: Test functions of ParsePluggedType
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService005, TestSize.Level1)
{
    int32_t pluggedType = PowerSupplyProvider::PLUGGED_TYPE_NONE;
    if (IsNotMock()) {
        giver_->ParsePluggedType(&pluggedType);
        int32_t sysfsPluggedType = ReadPluggedTypeSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService005::pluggedType=%{public}d, p=%{public}d",
            __func__, pluggedType, sysfsPluggedType);
        ASSERT_TRUE(pluggedType == sysfsPluggedType);
    } else {
        CreateFile("/data/local/tmp/ohos_charger/online", "1");
        CreateFile("/data/local/tmp/ohos_charger/type", "Wireless");
        giver_->ParsePluggedType(&pluggedType);
        HDF_LOGI("%{public}s: HdiService005::pluggedType=%{public}d.", __func__, pluggedType);
        ASSERT_TRUE(PowerSupplyProvider::BatteryPluggedType(pluggedType) ==
            PowerSupplyProvider::BatteryPluggedType::PLUGGED_TYPE_WIRELESS);
    }
}

/**
 * @tc.name: HdiService006
 * @tc.desc: Test functions of ParseChargeState
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService006, TestSize.Level1)
{
    int32_t chargeState = PowerSupplyProvider::CHARGE_STATE_RESERVED;
    if (IsNotMock()) {
        giver_->ParseChargeState(&chargeState);
        int32_t sysfsChargeState = ReadChargeStateSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService006::chargeState=%{public}d, cs=%{public}d",
            __func__, chargeState, sysfsChargeState);
        ASSERT_TRUE(chargeState == sysfsChargeState);
    } else {
        CreateFile("/data/local/tmp/battery/status", "Not charging");
        giver_->ParseChargeState(&chargeState);
        HDF_LOGI("%{public}s: HdiService006::chargeState=%{public}d.", __func__, chargeState);
        ASSERT_TRUE(PowerSupplyProvider::BatteryChargeState(chargeState) ==
            PowerSupplyProvider::BatteryChargeState::CHARGE_STATE_DISABLE);
    }
}

/**
 * @tc.name: HdiService007
 * @tc.desc: Test functions of ParseChargeCounter
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService007, TestSize.Level1)
{
    int32_t chargeCounter = -1;
    if (IsNotMock()) {
        giver_->ParseChargeCounter(&chargeCounter);
        int32_t sysfsChargeCounter = ReadChargeCounterSysfs();
        HDF_LOGI("%{public}s: Not Mcok HdiService007::chargeCounter=%{public}d, cc=%{public}d",
            __func__, chargeCounter, sysfsChargeCounter);
        ASSERT_TRUE(chargeCounter == sysfsChargeCounter);
    } else {
        CreateFile("/data/local/tmp/battery/charge_counter", "12345");
        giver_->ParseChargeCounter(&chargeCounter);
        HDF_LOGI("%{public}s: HdiService007::chargeCounter=%{public}d.", __func__, chargeCounter);
        ASSERT_TRUE(chargeCounter == 12345);
    }
}

/**
 * @tc.name: HdiService008
 * @tc.desc: Test functions of ParsePresent
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService008, TestSize.Level1)
{
    int8_t present = -1;
    if (IsNotMock()) {
        giver_->ParsePresent(&present);
        int32_t sysfsPresent = ReadPresentSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService008::present=%{public}d, p=%{public}d",
            __func__, present, sysfsPresent);
        ASSERT_TRUE(present == sysfsPresent);
    } else {
        CreateFile("/data/local/tmp/battery/present", "1");
        giver_->ParsePresent(&present);
        HDF_LOGI("%{public}s: HdiService008::present=%{public}d.", __func__, present);
        ASSERT_TRUE(present == 1);
    }
}

/**
 * @tc.name: HdiService009
 * @tc.desc: Test functions to get value of technology
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService009, TestSize.Level1)
{
    std::string technology = "invalid";
    if (IsNotMock()) {
        giver_->ParseTechnology(technology);
        std::string sysfsTechnology = "";
        ReadTechnologySysfs(sysfsTechnology);
        HDF_LOGI("%{public}s: HdiService009::technology=%{public}s, ty=%{public}s",
            __func__, technology.c_str(), sysfsTechnology.c_str());
        ASSERT_TRUE(technology == sysfsTechnology);
    } else {
        CreateFile("/data/local/tmp/ohos-fgu/technology", "Li");
        giver_->ParseTechnology(technology);
        HDF_LOGI("%{public}s: HdiService009::technology=%{public}s.", __func__, technology.c_str());
        ASSERT_TRUE(technology == "Li");
    }
}

/**
 * @tc.name: HdiService010
 * @tc.desc: Test functions to get fd of socket
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService010, TestSize.Level1)
{
    using namespace OHOS::HDI::Battery::V1_0;

    BatteryThread bt;
    auto fd = OpenUeventSocketTest(bt);
    HDF_LOGI("%{public}s: HdiService010::fd=%{public}d.", __func__, fd);

    ASSERT_TRUE(fd > 0);
    close(fd);
}

/**
 * @tc.name: HdiService011
 * @tc.desc: Test functions UpdateEpollInterval when charge-online
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService011, TestSize.Level1)
{
    const int32_t CHARGE_STATE_ENABLE = 1;
    BatteryThread bt;

    UpdateEpollIntervalTest(CHARGE_STATE_ENABLE, bt);
    auto epollInterval = GetEpollIntervalTest(bt);
    HDF_LOGI("%{public}s: HdiService011::epollInterval=%{public}d.", __func__, epollInterval);

    ASSERT_TRUE(epollInterval == 2000);
}

/**
 * @tc.name: HdiService012
 * @tc.desc: Test functions UpdateEpollInterval when charge-offline
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService012, TestSize.Level1)
{
    const int32_t CHARGE_STATE_NONE = 0;
    BatteryThread bt;

    UpdateEpollIntervalTest(CHARGE_STATE_NONE, bt);
    auto epollInterval = GetEpollIntervalTest(bt);
    HDF_LOGI("%{public}s: HdiService012::epollInterval=%{public}d.", __func__, epollInterval);

    ASSERT_TRUE(epollInterval == -1);
}

/**
 * @tc.name: HdiService013
 * @tc.desc: Test functions Init
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService013, TestSize.Level1)
{
    void* service = nullptr;
    BatteryThread bt;

    InitTest(service, bt);
    HDF_LOGI("%{public}s: HdiService013::InitTest success", __func__);
    auto epollFd = GetEpollFdTest(bt);
    HDF_LOGI("%{public}s: HdiService013::epollFd=%{public}d", __func__, epollFd);

    ASSERT_TRUE(epollFd > 0);
}

/**
 * @tc.name: HdiService014
 * @tc.desc: Test functions InitTimer
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService014, TestSize.Level1)
{
    BatteryThread bt;

    InitTimerTest(bt);
    auto timerFd = GetTimerFdTest(bt);
    HDF_LOGI("%{public}s: HdiService014::timerFd==%{public}d", __func__, timerFd);

    ASSERT_TRUE(timerFd > 0);
}

/**
 * @tc.name: HdiService015
 * @tc.desc: Test functions GetLedConf in BatteryConfig
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService015, TestSize.Level1)
{
    std::unique_ptr<BatteryConfig> conf = std::make_unique<BatteryConfig>();
    conf->Init();
    std::vector<BatteryConfig::LedConf> ledConf = conf->GetLedConf();

    if (!ledConf.empty()) {
        ASSERT_TRUE(ledConf[0].capacityBegin == 0);
        ASSERT_TRUE(ledConf[0].capacityEnd == 10);
        ASSERT_TRUE(ledConf[0].color == 4);
        ASSERT_TRUE(ledConf[0].brightness == 255);
        ASSERT_TRUE(ledConf[1].capacityBegin == 10);
        ASSERT_TRUE(ledConf[1].capacityEnd == 90);
        ASSERT_TRUE(ledConf[1].color == 6);
        ASSERT_TRUE(ledConf[1].brightness == 255);
        ASSERT_TRUE(ledConf[2].capacityBegin == 90);
        ASSERT_TRUE(ledConf[2].capacityEnd == 100);
        ASSERT_TRUE(ledConf[2].color == 2);
        ASSERT_TRUE(ledConf[2].brightness == 255);
    }
}

/**
 * @tc.name: HdiService016
 * @tc.desc: Test functions GetTempConf in BatteryConfig
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService016, TestSize.Level1)
{
    std::unique_ptr<BatteryConfig> conf = std::make_unique<BatteryConfig>();
    conf->Init();
    auto tempConf = conf->GetTempConf();

    ASSERT_TRUE(tempConf.lower == -100);
    ASSERT_TRUE(tempConf.upper == 600);
}

/**
 * @tc.name: HdiService017
 * @tc.desc: Test functions GetCapacityConf in BatteryConfig
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService017, TestSize.Level1)
{
    std::unique_ptr<BatteryConfig> conf = std::make_unique<BatteryConfig>();
    conf->Init();
    auto capacityConf = conf->GetCapacityConf();

    ASSERT_TRUE(capacityConf == 3);
}

/**
 * @tc.name: HdiService018
 * @tc.desc: Test functions ParseLedInfo in BatteryConfig
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService018, TestSize.Level1)
{
    std::string filename = "error_path/system/etc/ledconfig/led_config.json";
    BatteryConfig bc;

    ParseConfigTest(filename, bc);
    std::unique_ptr<BatteryConfig> conf = std::make_unique<BatteryConfig>();
    auto ledConf = conf->GetLedConf();
    ASSERT_TRUE(ledConf.empty());
}

/**
 * @tc.name: HdiService019
 * @tc.desc: Test functions ParseTemperatureInfo in BatteryConfig
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService019, TestSize.Level1)
{
    std::string filename = "error_path/system/etc/ledconfig/led_config.json";
    BatteryConfig bc;

    ParseConfigTest(filename, bc);
    std::unique_ptr<BatteryConfig> conf = std::make_unique<BatteryConfig>();
    auto tempConf = conf->GetTempConf();

    ASSERT_TRUE(tempConf.lower != -100);
    ASSERT_TRUE(tempConf.upper != 600);
}

/**
 * @tc.name: HdiService020
 * @tc.desc: Test functions ParseSocInfo in BatteryConfig
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService020, TestSize.Level1)
{
    std::string filename = "error_path/system/etc/ledconfig/led_config.json";
    BatteryConfig bc;

    ParseConfigTest(filename, bc);
    std::unique_ptr<BatteryConfig> conf = std::make_unique<BatteryConfig>();
    auto capacityConf = conf->GetCapacityConf();

    ASSERT_TRUE(capacityConf != 3);
}

/**
 * @tc.name: HdiService021
 * @tc.desc: Test functions VibrateInit in ChargerThread
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService021, TestSize.Level1)
{
    std::unique_ptr<BatteryVibrate> vibrate = std::make_unique<BatteryVibrate>();
    const std::string VIBRATOR_PLAYMODE_PATH = "/sys/class/leds/vibrator/play_mode";
    const std::string VIBRATOR_DURATIONMODE_PATH = "/sys/class/leds/vibrator/duration";
    auto ret = vibrate->VibrateInit();
    if ((access(VIBRATOR_PLAYMODE_PATH.c_str(), F_OK) == 0) ||
        (access(VIBRATOR_DURATIONMODE_PATH.c_str(), F_OK) == 0)) {
        ASSERT_TRUE(ret == 0);
    } else {
        ASSERT_TRUE(ret == -1);
    }
}

/**
 * @tc.name: HdiService022
 * @tc.desc: Test functions CycleMatters in ChargerThread
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService022, TestSize.Level1)
{
    ChargerThread ct;

    ChargerThreadInitTest(ct);
    CycleMattersTest(ct);
    auto getBatteryInfo = GetBatteryInfoTest(ct);

    ASSERT_TRUE(getBatteryInfo);
}

/**
 * @tc.name: HdiService024
 * @tc.desc: Test functions SetTimerInterval
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService024, TestSize.Level1)
{
    BatteryThread bt;

    SetTimerFdTest(2, bt);
    SetTimerIntervalTest(5, bt);
    int interval = GetTimerIntervalTest(bt);

    ASSERT_TRUE(interval == 5);
}

/**
 * @tc.name: HdiService025
 * @tc.desc: Test functions HandleBacklight
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService025, TestSize.Level1)
{
    std::unique_ptr<BatteryBacklight> backlight = std::make_unique<BatteryBacklight>();
    backlight->InitBacklightSysfs();
    auto ret = backlight->HandleBacklight(0);
    HDF_LOGI("%{public}s: HdiService025::ret==%{public}d", __func__, ret);
    backlight->TurnOnScreen();

    ASSERT_TRUE(ret != -1);
}

/**
 * @tc.name: HdiService026
 * @tc.desc: Test functions of ParseTotalEnergy
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService026, TestSize.Level1)
{
    int32_t totalEnergy = 0;
    if (IsNotMock()) {
        giver_->ParseTotalEnergy(&totalEnergy);
        int32_t sysfsTotalEnergy = ReadTotalEnergySysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService026::totalEnergy=%{public}d, t=%{public}d",
            __func__, totalEnergy, sysfsTotalEnergy);
        ASSERT_TRUE(totalEnergy == sysfsTotalEnergy);
    } else {
        CreateFile("/data/local/tmp/battery/charge_full", "4000000");
        giver_->ParseTotalEnergy(&totalEnergy);
        HDF_LOGI("%{public}s: HdiService026::totalEnergy=%{public}d.", __func__, totalEnergy);
        ASSERT_TRUE(totalEnergy == 4000000);
    }
}

/**
 * @tc.name: HdiService027
 * @tc.desc: Test functions of ParseCurrentAverage
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService027, TestSize.Level1)
{
    int32_t currentAvg = 0;
    if (IsNotMock()) {
        giver_->ParseCurrentAverage(&currentAvg);
        int32_t sysfsCurrentAvg = ReadCurrentAverageSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService027::currentAvg=%{public}d, t=%{public}d",
            __func__, currentAvg, sysfsCurrentAvg);
        ASSERT_TRUE(currentAvg == sysfsCurrentAvg);
    } else {
        CreateFile("/data/local/tmp/battery/current_avg", "1000");
        giver_->ParseCurrentAverage(&currentAvg);
        HDF_LOGI("%{public}s: HdiService027::currentAvg=%{public}d.", __func__, currentAvg);
        ASSERT_TRUE(currentAvg == 1000);
    }
}

/**
 * @tc.name: HdiService028
 * @tc.desc: Test functions of ParseCurrentNow
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService028, TestSize.Level1)
{
    int32_t currentNow = 0;
    if (IsNotMock()) {
        giver_->ParseCurrentNow(&currentNow);
        int32_t sysfsCurrentNow = ReadCurrentNowSysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService028::currentNow=%{public}d, t=%{public}d",
            __func__, currentNow, sysfsCurrentNow);
        ASSERT_TRUE(currentNow == sysfsCurrentNow);
    } else {
        CreateFile("/data/local/tmp/battery/current_now", "1000");
        giver_->ParseCurrentNow(&currentNow);
        HDF_LOGI("%{public}s: HdiService028::currentNow=%{public}d.", __func__, currentNow);
        ASSERT_TRUE(currentNow == 1000);
    }
}

/**
 * @tc.name: HdiService029
 * @tc.desc: Test functions of ParseChargeNow
 * @tc.type: FUNC
 */
HWTEST_F (HdiServiceTest, HdiService029, TestSize.Level1)
{
    int32_t chargeNow = 0;
    if (IsNotMock()) {
        giver_->ParseRemainEnergy(&chargeNow);
        int32_t sysfsChargeNow = ReadRemainEnergySysfs();
        HDF_LOGI("%{public}s: Not Mock HdiService029::chargeNow=%{public}d, t=%{public}d",
            __func__, chargeNow, sysfsChargeNow);
        ASSERT_TRUE(chargeNow == sysfsChargeNow);
    } else {
        CreateFile("/data/local/tmp/battery/charge_now", "1000");
        giver_->ParseRemainEnergy(&chargeNow);
        HDF_LOGI("%{public}s: HdiService029::chargeNow=%{public}d.", __func__, chargeNow);
        ASSERT_TRUE(chargeNow == 1000);
    }
}
}
