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

#include "power_supply_provider.h"
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "battery_log.h"
#include "battery_config.h"
#include "osal_mem.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V2_0 {
namespace {
constexpr int32_t MAX_SYSFS_SIZE = 64;
constexpr int32_t MAX_BUFF_SIZE = 128;
constexpr int32_t INVALID_BATT_INT_VALUE = -1;
constexpr int32_t STR_TO_LONG_LEN = 10;
constexpr int32_t UVOL_TO_MVOL = 1000;
constexpr int32_t MKDIR_WAIT_TIME = 1;
constexpr int32_t NUM_ZERO = 0;
const std::string POWER_SUPPLY_BASE_PATH = "/sys/class/power_supply";
const std::string MOCK_POWER_SUPPLY_BASE_PATH = "/data/service/el0/battery";
const std::string POWER_SUPPLY_BATTERY = "Battery";
const std::string BATTERY_KEY_CAPACITY = "POWER_SUPPLY_CAPACITY=";
const std::string BATTERY_KEY_VOLTAGE = "POWER_SUPPLY_VOLTAGE_NOW=";
const std::string BATTERY_KEY_TEMPERATURE = "POWER_SUPPLY_TEMP=";
const std::string BATTERY_KEY_HEALTH = "POWER_SUPPLY_HEALTH=";
const std::string BATTERY_KEY_CHARGE_STATUS = "POWER_SUPPLY_STATUS=";
const std::string BATTERY_KEY_PRESENT = "POWER_SUPPLY_PRESENT=";
const std::string BATTERY_KEY_TECHNOLOGY = "POWER_SUPPLY_TECHNOLOGY=";
const std::string BATTERY_KEY_CHARGE_COUNTER = "POWER_SUPPLY_CHARGE_COUNTER=";
const std::string BATTERY_KEY_TOTAL_ENERGY = "POWER_SUPPLY_TOTAL_ENERGY=";
const std::string BATTERY_KEY_REMAIN_ENERGY = "POWER_SUPPLY_REMAIN_ENERGY=";
const std::string BATTERY_KEY_CURRENT_AVERAGE = "POWER_SUPPLY_CURRENT_AVERAGE=";
const std::string BATTERY_KEY_CURRENT_NOW = "POWER_SUPPLY_CURRENT_NOW=";
const std::string INVALID_STRING_VALUE = "invalid";
const std::string BATTERY_NODE_PATH = "battery";
}

BatterydInfo g_batteryInfo;

struct StringEnumMap {
    const char* str;
    int32_t enumVal;
};

struct BatteryAssigner {
    const char* prefix;
    const size_t prefixLen;
    void (*Assigner)(const char*, struct BatterydInfo*);
};

PowerSupplyProvider::PowerSupplyProvider()
{
    path_ = POWER_SUPPLY_BASE_PATH;
    index_ = 0;
}

PowerSupplyProvider::~PowerSupplyProvider()
{
    for (auto it = nodeCacheFiles_.begin(); it != nodeCacheFiles_.end();) {
        int32_t fd = it->second;
        close(fd);
        nodeCacheFiles_.erase(it++);
    }
}

inline int32_t PowerSupplyProvider::ParseInt(const char* str)
{
    return static_cast<int32_t>(strtol(str, nullptr, STR_TO_LONG_LEN));
}

inline void PowerSupplyProvider::Trim(char* str)
{
    if (str == nullptr) {
        return;
    }

    size_t strc = strcspn(str, "\n");
    if (strc >= strlen(str)) {
        return;
    }

    str[strc] = 0;
}

inline void PowerSupplyProvider::CapacityAssigner(const char* str, struct BatterydInfo* info)
{
    info->capacity_ = ParseInt(str); // default in percent format
}

inline void PowerSupplyProvider::TotalEnergyAssigner(const char* str, struct BatterydInfo* info)
{
    info->totalEnergy_ = ParseInt(str);
}

inline void PowerSupplyProvider::RemainEnergyAssigner(const char* str, struct BatterydInfo* info)
{
    info->remainEnergy_ = ParseInt(str);
}

inline void PowerSupplyProvider::VoltageAssigner(const char* str, struct BatterydInfo* info)
{
    info->voltage_ = ParseInt(str) / UVOL_TO_MVOL; // convert to millivolt(mV) format
}

inline void PowerSupplyProvider::TemperatureAssigner(const char* str, struct BatterydInfo* info)
{
    info->temperature_ = ParseInt(str);
}

int32_t PowerSupplyProvider::HealthStateEnumConverter(const char* str)
{
    struct StringEnumMap healthStateEnumMap[] = {
        { "Good", BATTERY_HEALTH_GOOD },
        { "Cold", BATTERY_HEALTH_COLD },
        { "Warm", BATTERY_HEALTH_GOOD }, // JEITA specification
        { "Cool", BATTERY_HEALTH_GOOD }, // JEITA specification
        { "Hot", BATTERY_HEALTH_OVERHEAT }, // JEITA specification
        { "Overheat", BATTERY_HEALTH_OVERHEAT },
        { "Over voltage", BATTERY_HEALTH_OVERVOLTAGE },
        { "Dead", BATTERY_HEALTH_DEAD },
        { "Unknown", BATTERY_HEALTH_UNKNOWN },
        { "Unspecified failure", BATTERY_HEALTH_UNKNOWN },
        { nullptr, BATTERY_HEALTH_UNKNOWN },
    };

    for (int32_t i = 0; healthStateEnumMap[i].str; ++i) {
        if (strcmp(str, healthStateEnumMap[i].str) == 0) {
            return healthStateEnumMap[i].enumVal;
        }
    }

    return BATTERY_HEALTH_UNKNOWN;
}

inline void PowerSupplyProvider::HealthStateAssigner(const char* str, struct BatterydInfo* info)
{
    info->healthState_ = HealthStateEnumConverter(str);
}

int32_t PowerSupplyProvider::ChargeStateEnumConverter(const char* str)
{
    struct StringEnumMap chargeStateEnumMap[] = {
        { "Discharging", CHARGE_STATE_NONE },
        { "Charging", CHARGE_STATE_ENABLE },
        { "Full", CHARGE_STATE_FULL },
        { "Not charging", CHARGE_STATE_DISABLE },
        { "Unknown", CHARGE_STATE_RESERVED },
        { nullptr, CHARGE_STATE_RESERVED },
    };

    for (int32_t i = 0; chargeStateEnumMap[i].str; ++i) {
        if (strcmp(str, chargeStateEnumMap[i].str) == 0) {
            return chargeStateEnumMap[i].enumVal;
        }
    }

    return CHARGE_STATE_RESERVED;
}

int32_t PowerSupplyProvider::ChargeTypeEumConverter(const char* str)
{
    struct StringEnumMap chargeTypeEnumMap[] = {
        { "0", CHARGE_TYPE_NONE },
        { "1", CHARGE_TYPE_WIRED_NORMAL },
        { "2", CHARGE_TYPE_WIRED_QUICK },
        { "3", CHARGE_TYPE_WIRED_SUPER_QUICK },
        { "4", CHARGE_TYPE_WIRELESS_NORMAL },
        { "5", CHARGE_TYPE_WIRELESS_QUICK },
        { "6", CHARGE_TYPE_WIRELESS_SUPER_QUICK },
        { nullptr, CHARGE_TYPE_NONE },
    };

    for (int32_t i = 0; chargeTypeEnumMap[i].str; ++i) {
        if (strcmp(str, chargeTypeEnumMap[i].str) == 0) {
            return chargeTypeEnumMap[i].enumVal;
        }
    }

    return CHARGE_TYPE_NONE;
}

inline void PowerSupplyProvider::ChargeStateAssigner(const char* str, struct BatterydInfo* info)
{
    info->chargeState_ = ChargeStateEnumConverter(str);
}

inline void PowerSupplyProvider::PresentAssigner(const char* str, struct BatterydInfo* info)
{
    info->present_ = static_cast<int8_t>(ParseInt(str));
}

inline void PowerSupplyProvider::TechnologyAssigner(const char* str, struct BatterydInfo* info)
{
    info->technology_ = str;
}

inline void PowerSupplyProvider::ChargeCounterAssigner(const char* str, struct BatterydInfo* info)
{
    info->chargeCounter_ = ParseInt(str);
}

inline void PowerSupplyProvider::CurrentAverageAssigner(const char* str, struct BatterydInfo* info)
{
    info->curAverage_ = ParseInt(str);
}

inline void PowerSupplyProvider::CurrentNowAssigner(const char* str, struct BatterydInfo* info)
{
    info->curNow_ = ParseInt(str);
}

void PowerSupplyProvider::FormatPath(std::string& path,
    size_t size, const char* format, const char* basePath, const char* name) const
{
    char buff[PATH_MAX] = {0};
    if (strcpy_s(buff, PATH_MAX, path.c_str()) != EOK) {
        BATTERY_HILOGW(FEATURE_BATT_INFO, "failed to copy path of %{public}s", name);
        return;
    }

    if (snprintf_s(buff, PATH_MAX, size - 1, format, basePath, name) == -1) {
        BATTERY_HILOGW(FEATURE_BATT_INFO, "failed to format path of %{public}s", name);
        return;
    }
    path.assign(buff, strlen(buff));
}

void PowerSupplyProvider::FormatSysfsPaths()
{
    // Format paths for power supply types
    FormatPath(batterySysfsInfo_.capacityPath, PATH_MAX, "%s/%s/capacity", path_.c_str(),
               nodeNamePathMap_["capacity"].c_str());
    FormatPath(batterySysfsInfo_.voltagePath, PATH_MAX, "%s/%s/voltage_now", path_.c_str(),
               nodeNamePathMap_["voltage_now"].c_str());
    FormatPath(batterySysfsInfo_.temperaturePath, PATH_MAX, "%s/%s/temp", path_.c_str(),
               nodeNamePathMap_["temp"].c_str());
    FormatPath(batterySysfsInfo_.healthStatePath, PATH_MAX, "%s/%s/health", path_.c_str(),
               nodeNamePathMap_["health"].c_str());
    FormatPath(batterySysfsInfo_.chargeStatePath, PATH_MAX, "%s/%s/status", path_.c_str(),
               nodeNamePathMap_["status"].c_str());
    FormatPath(batterySysfsInfo_.presentPath, PATH_MAX, "%s/%s/present", path_.c_str(),
               nodeNamePathMap_["present"].c_str());
    FormatPath(batterySysfsInfo_.chargeCounterPath, PATH_MAX, "%s/%s/charge_counter", path_.c_str(),
               nodeNamePathMap_["charge_counter"].c_str());
    FormatPath(batterySysfsInfo_.technologyPath, PATH_MAX, "%s/%s/technology", path_.c_str(),
               nodeNamePathMap_["technology"].c_str());
    FormatPath(batterySysfsInfo_.totalEnergyPath, PATH_MAX, "%s/%s/charge_full", path_.c_str(),
               nodeNamePathMap_["charge_full"].c_str());
    FormatPath(batterySysfsInfo_.curAveragePath, PATH_MAX, "%s/%s/current_avg", path_.c_str(),
               nodeNamePathMap_["current_avg"].c_str());
    FormatPath(batterySysfsInfo_.curNowPath, PATH_MAX, "%s/%s/current_now", path_.c_str(),
               nodeNamePathMap_["current_now"].c_str());
    FormatPath(batterySysfsInfo_.remainEnergyPath, PATH_MAX, "%s/%s/charge_now", path_.c_str(),
               nodeNamePathMap_["charge_now"].c_str());
}

int32_t PowerSupplyProvider::ReadSysfsFile(const char* path, char* buf, size_t size)
{
    int32_t fd = -1;

    auto item = nodeCacheFiles_.find(path);
    if (item != nodeCacheFiles_.end()) {
        fd = item->second;
    }

    if (fd != -1) {
        size_t readSize = pread(fd, buf, size - 1, 0);
        buf[readSize] = '\0';
        Trim(buf);
        return HDF_SUCCESS;
    }

    fd = open(path, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
    if (fd < NUM_ZERO) {
        BATTERY_HILOGD(FEATURE_BATT_INFO, "failed to open file %{public}s, errno: %{public}d", path, errno);
        return HDF_ERR_IO;
    }

    size_t readSize = read(fd, buf, size - 1);
    buf[readSize] = '\0';
    Trim(buf);
    nodeCacheFiles_.insert(std::make_pair(path, fd));

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ReadBatterySysfsToBuff(const char* path, char* buf, size_t size)
{
    int32_t ret = ReadSysfsFile(path, buf, size);
    if (ret != HDF_SUCCESS) {
        BATTERY_HILOGW(FEATURE_BATT_INFO, "read path(%{public}s) failed, ret: %{public}d",
            (path != nullptr ? path : "NULL"), ret);
        return ret;
    }

    return HDF_SUCCESS;
}

void PowerSupplyProvider::GetPluggedTypeName(char* buf, size_t size)
{
    std::string onlineNode = "USB";
    int32_t ret;
    int32_t online;
    std::string onlinePath = path_ + "/" + onlineNode + "/" + "online";
    ret = ReadSysfsFile(onlinePath.c_str(), buf, size);
    online = ParseInt(buf);
    auto iter = nodeNames_.begin();
    while (!online && iter != nodeNames_.end()) {
        if (*iter == "USB") {
            iter++;
            continue;
        }
        onlinePath = path_ + "/" + *iter + "/" + "online";
        ret = ReadSysfsFile(onlinePath.c_str(), buf, size);
        if (ret != HDF_SUCCESS) {
            BATTERY_HILOGD(FEATURE_BATT_INFO, "read online path failed in loop, ret: %{public}d", ret);
        }
        online = ParseInt(buf);
        if (online) {
            onlineNode = *iter;
            break;
        }
        iter++;
    }

    if (ret != HDF_SUCCESS) {
        BATTERY_HILOGD(FEATURE_BATT_INFO, "read online path failed, ret: %{public}d", ret);
        return;
    }

    if (!online) {
        BATTERY_HILOGW(FEATURE_BATT_INFO, "charger is not online, so no type return");
        return;
    }

    std::string typeNode = onlineNode;
    std::string typePath = path_ + "/" + typeNode + "/" + "type";
    ret = ReadSysfsFile(typePath.c_str(), buf, size);
    if (ret != HDF_SUCCESS) {
        BATTERY_HILOGW(FEATURE_BATT_INFO, "read type path failed, ret: %{public}d", ret);
        return;
    }
    Trim(buf);
}

int32_t PowerSupplyProvider::PluggedTypeEnumConverter(const char* str) const
{
    struct StringEnumMap pluggedTypeEnumMap[] = {
        { "USB", PLUGGED_TYPE_USB },
        { "USB_PD_DRP", PLUGGED_TYPE_USB },
        { "Wireless", PLUGGED_TYPE_WIRELESS },
        { "Mains", PLUGGED_TYPE_AC },
        { "UPS", PLUGGED_TYPE_AC },
        { "USB_ACA", PLUGGED_TYPE_AC },
        { "USB_C", PLUGGED_TYPE_AC },
        { "USB_CDP", PLUGGED_TYPE_AC },
        { "USB_DCP", PLUGGED_TYPE_AC },
        { "USB_HVDCP", PLUGGED_TYPE_AC },
        { "USB_PD", PLUGGED_TYPE_AC },
        { "Unknown", PLUGGED_TYPE_BUTT },
        { nullptr, PLUGGED_TYPE_BUTT },
    };

    for (int32_t i = 0; pluggedTypeEnumMap[i].str; ++i) {
        if (strcmp(str, pluggedTypeEnumMap[i].str) == 0) {
            return pluggedTypeEnumMap[i].enumVal;
        }
    }
    return PLUGGED_TYPE_BUTT;
}

int32_t PowerSupplyProvider::ParsePluggedMaxCurrent(int32_t* maxCurrent)
{
    char buf[MAX_BUFF_SIZE] = {0};
    GetPluggedTypeName(buf, sizeof(buf));
    std::string currentMaxNode = POWER_SUPPLY_BATTERY;

    const auto& item = nodeNamePathMap_.find("current_max");
    if (item != nodeNamePathMap_.end()) {
        currentMaxNode = item->second;
    }

    std::string currentMaxPath = POWER_SUPPLY_BASE_PATH + "/" + currentMaxNode + "/" + "current_max";
    int32_t ret = ReadBatterySysfsToBuff(currentMaxPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    int32_t value = ParseInt(buf);
    *maxCurrent = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParsePluggedMaxVoltage(int32_t* maxVoltage)
{
    char buf[MAX_BUFF_SIZE] = {0};
    GetPluggedTypeName(buf, sizeof(buf));
    std::string voltageMaxNode = POWER_SUPPLY_BATTERY;

    const auto& item = nodeNamePathMap_.find("voltage_max");
    if (item != nodeNamePathMap_.end()) {
        voltageMaxNode = item->second;
    }

    std::string voltageMaxPath = POWER_SUPPLY_BASE_PATH + "/" + voltageMaxNode + "/" + "voltage_max";
    int32_t ret = ReadBatterySysfsToBuff(voltageMaxPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    int32_t value = ParseInt(buf);
    *maxVoltage = value;

    return HDF_SUCCESS;
}

void PowerSupplyProvider::UpdateInfoByReadSysFile(struct BatterydInfo* info)
{
    ParseCapacity(&info->capacity_);
    ParseVoltage(&info->voltage_);
    ParseTemperature(&info->temperature_);
    ParseHealthState(&info->healthState_);
    ParseChargeState(&info->chargeState_);
    ParseChargeCounter(&info->chargeCounter_);
    ParseCurrentNow(&info->curNow_);
    ParseCurrentAverage(&info->curAverage_);
    ParseRemainEnergy(&info->remainEnergy_);
    ParseTotalEnergy(&info->totalEnergy_);
    ParsePresent(&info->present_);

    info->pluggedType_ = PLUGGED_TYPE_NONE;
    ParsePluggedType(&info->pluggedType_);

    info->pluggedMaxCurrent_ = INVALID_BATT_INT_VALUE;
    ParsePluggedMaxCurrent(&info->pluggedMaxCurrent_);

    info->pluggedMaxVoltage_ = INVALID_BATT_INT_VALUE;
    ParsePluggedMaxVoltage(&info->pluggedMaxVoltage_);

    info->technology_ = INVALID_STRING_VALUE;
    ParseTechnology(info->technology_);

    CopyBatteryInfo(info);
}

void PowerSupplyProvider::ParseUeventToBatterydInfo(const char* msg, struct BatterydInfo* info)
{
    static struct BatteryAssigner batteryAssigners[] = {
        { BATTERY_KEY_CAPACITY.c_str(), BATTERY_KEY_CAPACITY.length(), CapacityAssigner },
        { BATTERY_KEY_TOTAL_ENERGY.c_str(), BATTERY_KEY_TOTAL_ENERGY.length(), TotalEnergyAssigner },
        { BATTERY_KEY_REMAIN_ENERGY.c_str(), BATTERY_KEY_REMAIN_ENERGY.length(), RemainEnergyAssigner },
        { BATTERY_KEY_VOLTAGE.c_str(), BATTERY_KEY_VOLTAGE.length(), VoltageAssigner },
        { BATTERY_KEY_TEMPERATURE.c_str(), BATTERY_KEY_TEMPERATURE.length(), TemperatureAssigner },
        { BATTERY_KEY_HEALTH.c_str(), BATTERY_KEY_HEALTH.length(), HealthStateAssigner },
        { BATTERY_KEY_CHARGE_STATUS.c_str(), BATTERY_KEY_CHARGE_STATUS.length(), ChargeStateAssigner },
        { BATTERY_KEY_PRESENT.c_str(), BATTERY_KEY_PRESENT.length(), PresentAssigner },
        { BATTERY_KEY_TECHNOLOGY.c_str(), BATTERY_KEY_TECHNOLOGY.length(), TechnologyAssigner },
        { BATTERY_KEY_CHARGE_COUNTER.c_str(), BATTERY_KEY_CHARGE_COUNTER.length(), ChargeCounterAssigner },
        { BATTERY_KEY_CURRENT_AVERAGE.c_str(), BATTERY_KEY_CURRENT_AVERAGE.length(), CurrentAverageAssigner },
        { BATTERY_KEY_CURRENT_NOW.c_str(), BATTERY_KEY_CURRENT_NOW.length(), CurrentNowAssigner },
        { nullptr, 0, nullptr } // end of the array
    };

    while (*msg) {
        for (int32_t i = 0; batteryAssigners[i].prefix; ++i) {
            if (!strncmp(msg, batteryAssigners[i].prefix, batteryAssigners[i].prefixLen)) {
                BATTERY_HILOGD(FEATURE_BATT_INFO, "msg: %{public}s", msg);
                msg += batteryAssigners[i].prefixLen;
                batteryAssigners[i].Assigner(msg, info);
                break;
            }
        }
        while (*msg++) {} // move to next
    }

    info->pluggedType_ = PLUGGED_TYPE_NONE;
    ParsePluggedType(&info->pluggedType_);

    info->pluggedMaxCurrent_ = INVALID_BATT_INT_VALUE;
    ParsePluggedMaxCurrent(&info->pluggedMaxCurrent_);

    info->pluggedMaxVoltage_ = INVALID_BATT_INT_VALUE;
    ParsePluggedMaxVoltage(&info->pluggedMaxVoltage_);

    info->technology_ = INVALID_STRING_VALUE;
    ParseTechnology(info->technology_);

    CopyBatteryInfo(info);
}

void PowerSupplyProvider::CopyBatteryInfo(const struct BatterydInfo* info) const
{
    g_batteryInfo.capacity_ = info->capacity_;
    g_batteryInfo.voltage_ = info->voltage_;
    g_batteryInfo.temperature_ = info->temperature_;
    g_batteryInfo.healthState_ = info->healthState_;
    g_batteryInfo.pluggedType_ = info->pluggedType_;
    g_batteryInfo.pluggedMaxCurrent_ = info->pluggedMaxCurrent_;
    g_batteryInfo.pluggedMaxVoltage_ = info->pluggedMaxVoltage_;
    g_batteryInfo.chargeState_ = info->chargeState_;
    g_batteryInfo.chargeCounter_ = info->chargeCounter_;
    g_batteryInfo.curNow_ = info->curNow_;
    g_batteryInfo.curAverage_ = info->curAverage_;
    g_batteryInfo.totalEnergy_ = info->totalEnergy_;
    g_batteryInfo.remainEnergy_ = info->remainEnergy_;
    g_batteryInfo.present_ = info->present_;
    g_batteryInfo.technology_ = info->technology_;
}

void PowerSupplyProvider::SetSysFilePath(const std::string& path)
{
    if (path.empty()) {
        BATTERY_HILOGI(FEATURE_BATT_INFO, "path is empty");
        return;
    }
    path_ = path;
}

void PowerSupplyProvider::CreateFile(const std::string& path, const std::string& content)
{
    if (access(path.c_str(), F_OK) == 0) {
        return;
    }

    std::ofstream stream(path.c_str());
    if (!stream.is_open()) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "cannot create file");
        return;
    }
    stream << content.c_str() << std::endl;
    stream.close();
}

void PowerSupplyProvider::InitBatteryPath()
{
    std::string sysLowercaseBatteryPath = "/sys/class/power_supply/battery";

    if (access(sysLowercaseBatteryPath.c_str(), F_OK) == 0) {
        BATTERY_HILOGI(FEATURE_BATT_INFO, "system battery path is exist");
        return;
    } else {
        std::string sysCapitalBatteryPath = "/sys/class/power_supply/Battery";
        if (access(sysCapitalBatteryPath.c_str(), F_OK) == 0) {
            BATTERY_HILOGI(FEATURE_BATT_INFO, "system Battery path is exist");
            return;
        }
        InitDefaultSysfs();
    }
    InitChargerSysfs();
}

int32_t PowerSupplyProvider::InitPowerSupplySysfs()
{
    DIR* dir = nullptr;
    struct dirent* entry = nullptr;
    index_ = 0;

    dir = opendir(path_.c_str());
    if (dir == nullptr) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "cannot open path_");
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
            if (index_ >= MAX_SYSFS_SIZE) {
                BATTERY_HILOGW(FEATURE_BATT_INFO, "too many power supply types");
                break;
            }
            nodeNames_.emplace_back(entry->d_name);
            index_++;
        }
    }
    nodeNamePathMap_.clear();
    TraversalNode();
    FormatSysfsPaths();
    BATTERY_HILOGD(FEATURE_BATT_INFO, "init power supply sysfs nodes, total count %{public}d", index_);
    closedir(dir);

    return HDF_SUCCESS;
}

void PowerSupplyProvider::InitChargerSysfs()
{
    auto& batteryConfig = BatteryConfig::GetInstance();
    batteryConfig.ParseConfig();
    BatteryConfig::ChargerConfig chargerConfig = batteryConfig.GetChargerConfig();
    
    std::string mockCurrentLimitPath = chargerConfig.currentPath;
    if (access(mockCurrentLimitPath.c_str(), 0) == -1) {
        CreateFile(mockCurrentLimitPath, "0");
    }

    std::string mockVoltageLimitPath = chargerConfig.voltagePath;
    if (access(mockVoltageLimitPath.c_str(), 0) == -1) {
        CreateFile(mockVoltageLimitPath, "0");
    }

    std::string mockChargeTypePath = chargerConfig.chargeTypePath;
    if (access(mockChargeTypePath.c_str(), 0) == -1) {
        CreateFile(mockChargeTypePath, "0");
    }
}

void PowerSupplyProvider::TraversalNode()
{
    nodeNamePathMap_.insert(std::make_pair("type", ""));
    nodeNamePathMap_.insert(std::make_pair("online", ""));
    nodeNamePathMap_.insert(std::make_pair("current_max", ""));
    nodeNamePathMap_.insert(std::make_pair("voltage_max", ""));
    nodeNamePathMap_.insert(std::make_pair("capacity", ""));
    nodeNamePathMap_.insert(std::make_pair("voltage_now", ""));
    nodeNamePathMap_.insert(std::make_pair("temp", ""));
    nodeNamePathMap_.insert(std::make_pair("health", ""));
    nodeNamePathMap_.insert(std::make_pair("status", ""));
    nodeNamePathMap_.insert(std::make_pair("present", ""));
    nodeNamePathMap_.insert(std::make_pair("charge_counter", ""));
    nodeNamePathMap_.insert(std::make_pair("technology", ""));
    nodeNamePathMap_.insert(std::make_pair("charge_full", ""));
    nodeNamePathMap_.insert(std::make_pair("current_avg", ""));
    nodeNamePathMap_.insert(std::make_pair("current_now", ""));
    nodeNamePathMap_.insert(std::make_pair("charge_now", ""));

    auto iter = nodeNames_.begin();
    while (iter != nodeNames_.end()) {
        if (*iter == "battery") {
            CheckSubfolderNode(*iter);
            iter = nodeNames_.erase(iter);
        } else {
            iter++;
        }
    }

    iter = nodeNames_.begin();
    while (iter != nodeNames_.end()) {
        if (*iter == POWER_SUPPLY_BATTERY) {
            CheckSubfolderNode(*iter);
            iter = nodeNames_.erase(iter);
        } else {
            iter++;
        }
    }

    for (auto& nodeName : nodeNames_) {
        CheckSubfolderNode(nodeName);
    }
}

void PowerSupplyProvider::CheckSubfolderNode(const std::string& path)
{
    DIR *dir = nullptr;
    struct dirent* entry = nullptr;
    std::string batteryPath = path_ + "/" + path;

    dir = opendir(batteryPath.c_str());
    if (dir == nullptr) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "subfolder file is not exist.");
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

        if ((strcmp(entry->d_name, "type") == 0) && (nodeNamePathMap_["type"].empty()) &&
            (strcasecmp(path.c_str(), BATTERY_NODE_PATH.c_str()) != 0)) {
            nodeNamePathMap_["type"] = path;
        }

        for (auto& iter : nodeNamePathMap_) {
            if ((strcmp(entry->d_name, iter.first.c_str()) == 0) && (nodeNamePathMap_[iter.first].empty())) {
                nodeNamePathMap_[iter.first] = path;
            }
        }
    }
    closedir(dir);
}

int32_t PowerSupplyProvider::ParseCapacity(int32_t* capacity)
{
    char buf[MAX_BUFF_SIZE] = {0};

    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.capacityPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *capacity = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseTotalEnergy(int32_t* totalEnergy)
{
    char buf[MAX_BUFF_SIZE] = {0};

    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.totalEnergyPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *totalEnergy = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseCurrentAverage(int32_t* curAverage)
{
    char buf[MAX_BUFF_SIZE] = {0};

    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.curAveragePath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *curAverage = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseCurrentNow(int32_t* curNow)
{
    char buf[MAX_BUFF_SIZE] = {0};

    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.curNowPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *curNow = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseRemainEnergy(int32_t* remainEnergy)
{
    char buf[MAX_BUFF_SIZE] = {0};

    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.remainEnergyPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *remainEnergy = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseVoltage(int32_t* voltage)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.voltagePath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *voltage = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseTemperature(int32_t* temperature)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.temperaturePath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *temperature = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseHealthState(int32_t* healthState)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.healthStatePath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    Trim(buf);
    *healthState = HealthStateEnumConverter(buf);
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParsePluggedType(int32_t* pluggedType)
{
    char buf[MAX_BUFF_SIZE] = {0};
    GetPluggedTypeName(buf, sizeof(buf));
    int32_t type = PluggedTypeEnumConverter(buf);
    if (type == PLUGGED_TYPE_BUTT) {
        BATTERY_HILOGD(FEATURE_BATT_INFO, "not support the online type %{public}s", buf);
        return HDF_ERR_NOT_SUPPORT;
    }

    *pluggedType = type;
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseChargeState(int32_t* chargeState)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.chargeStatePath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    Trim(buf);
    *chargeState = ChargeStateEnumConverter(buf);
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParsePresent(int8_t* present)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.presentPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    auto value = static_cast<int8_t>(ParseInt(buf));
    *present = value;
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseChargeCounter(int32_t* chargeCounter)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.chargeCounterPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    int32_t value = ParseInt(buf);
    *chargeCounter = value;

    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseTechnology(std::string& technology)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(batterySysfsInfo_.technologyPath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    technology.assign(buf, strlen(buf));
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::ParseChargeType(int32_t* chargeType, std::string& chargeTypePath)
{
    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(chargeTypePath.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    Trim(buf);
    *chargeType = ChargeTypeEumConverter(buf);
    return HDF_SUCCESS;
}

BatterydInfo PowerSupplyProvider::GetBatteryInfo()
{
    UpdateInfoByReadSysFile(&g_batteryInfo);
    return g_batteryInfo;
}

void PowerSupplyProvider::CreateMockTechPath(std::string& mockTechPath)
{
    BATTERY_HILOGI(FEATURE_BATT_INFO, "create mockFilePath path");
    CreateFile(mockTechPath + "/capacity", "1000");
    CreateFile(mockTechPath + "/current_avg", "1000");
    CreateFile(mockTechPath + "/current_now", "1000");
    CreateFile(mockTechPath + "/health", "Over voltage");
    CreateFile(mockTechPath + "/present", "0");
    CreateFile(mockTechPath + "/status", "Not charging");
    CreateFile(mockTechPath + "/type", "Unknown");
    CreateFile(mockTechPath + "/temp", "345");
    CreateFile(mockTechPath + "/technology", "Li-ion");
}

void PowerSupplyProvider::CreateMockChargerPath(std::string& mockChargerPath)
{
    BATTERY_HILOGI(FEATURE_BATT_INFO, "create mockFilePath path");
    CreateFile(mockChargerPath + "/type", "USB");
    CreateFile(mockChargerPath + "/constant_charge_current", "0");
    CreateFile(mockChargerPath + "/health", "Good");
    CreateFile(mockChargerPath + "/online", "1");
    CreateFile(mockChargerPath + "/status", "Charging");
}

void PowerSupplyProvider::CreateMockBatteryPath(std::string& mockBatteryPath)
{
    BATTERY_HILOGI(FEATURE_BATT_INFO, "create mockFilePath path");
    CreateFile(mockBatteryPath + "/capacity", "11");
    CreateFile(mockBatteryPath + "/charge_control_limit", "0");
    CreateFile(mockBatteryPath + "/charge_counter", "4000000");
    CreateFile(mockBatteryPath + "/charge_full", "4000000");
    CreateFile(mockBatteryPath + "/charge_now", "4000000");
    CreateFile(mockBatteryPath + "/constant_charge_current", "0");
    CreateFile(mockBatteryPath + "/current_avg", "1000");
    CreateFile(mockBatteryPath + "/current_now", "1000");
    CreateFile(mockBatteryPath + "/health", "Good");
    CreateFile(mockBatteryPath + "/input_current_limit", "0");
    CreateFile(mockBatteryPath + "/online", "1");
    CreateFile(mockBatteryPath + "/present", "0");
    CreateFile(mockBatteryPath + "/status", "Charging");
    CreateFile(mockBatteryPath + "/temp", "222");
    CreateFile(mockBatteryPath + "/voltage_avg", "4123456");
    CreateFile(mockBatteryPath + "/voltage_now", "4123456");
    CreateFile(mockBatteryPath + "/type", "Battery");
}

void PowerSupplyProvider::InitDefaultSysfs()
{
    std::string mockBatteryPath = MOCK_POWER_SUPPLY_BASE_PATH + "/battery";
    std::string mockChargerPath = MOCK_POWER_SUPPLY_BASE_PATH + "/ohos_charger";
    std::string mockTechPath = MOCK_POWER_SUPPLY_BASE_PATH + "/ohos-fgu";

    if (access(mockBatteryPath.c_str(), 0) == -1) {
        mkdir(mockBatteryPath.c_str(), S_IRWXU | S_IRWXG);
        sleep(MKDIR_WAIT_TIME);
    }

    if (access(mockChargerPath.c_str(), 0) == -1) {
        mkdir(mockChargerPath.c_str(), S_IRWXU);
        sleep(MKDIR_WAIT_TIME);
    }

    if (access(mockTechPath.c_str(), 0) == -1) {
        mkdir(mockTechPath.c_str(), S_IRWXU);
        sleep(MKDIR_WAIT_TIME);
    }

    CreateMockTechPath(mockTechPath);
    CreateMockChargerPath(mockChargerPath);
    CreateMockBatteryPath(mockBatteryPath);
    path_ = MOCK_POWER_SUPPLY_BASE_PATH;
}

int32_t PowerSupplyProvider::SetChargingLimit(const std::vector<ChargingLimit>& chargerLimitList,
    std::string& currentPath, std::string& voltagePath)
{
    BATTERY_HILOGD(FEATURE_BATT_INFO, "enter");
    if (chargerLimitList.empty()) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "the parameter is empty");
        return HDF_ERR_INVALID_PARAM;
    }

    std::string limitPath;
    std::string chargeLimitStr;
    for (const auto& iter : chargerLimitList) {
        if (iter.type == ChargingLimitType::TYPE_CURRENT) {
            limitPath = currentPath;
        } else if (iter.type == ChargingLimitType::TYPE_VOLTAGE) {
            limitPath = voltagePath;
        }
        chargeLimitStr = chargeLimitStr + (iter.protocol + " " + std::to_string(iter.value) + "\n");
    }

    int32_t ret = SetConfigByPath(limitPath, chargeLimitStr);
    if (ret < HDF_SUCCESS) {
        return ret;
    }
    BATTERY_HILOGD(FEATURE_BATT_INFO, "Exit");
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::SetConfigByPath(const std::string& path, const std::string& value)
{
    BATTERY_HILOGI(FEATURE_BATT_INFO, "SetConfigByPath enter, path: %{public}s, value:%{public}s",
        path.c_str(), value.c_str());
    if (path.empty()) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "the featurePath is empty");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t fd = open(path.c_str(), O_TRUNC | O_WRONLY);
    if (fd < NUM_ZERO) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "failed to open file %{public}s, errno: %{public}d",
            path.c_str(), errno);
        return HDF_ERR_IO;
    }

    ssize_t size = static_cast<ssize_t>(value.length());
    if (write(fd, value.c_str(), size) != size) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "failed to write file %{public}s, errno: %{public}d",
            path.c_str(), errno);
        close(fd);
        return HDF_ERR_IO;
    }
    close(fd);

    BATTERY_HILOGD(FEATURE_BATT_INFO, "SetConfigByPath exit");
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::GetConfigByPath(const std::string& path, std::string& result)
{
    if (path.empty()) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "the featurePath is empty");
        result = "";
        return HDF_ERR_INVALID_PARAM;
    }

    char buf[MAX_BUFF_SIZE] = {0};
    int32_t ret = ReadBatterySysfsToBuff(path.c_str(), buf, sizeof(buf));
    if (ret != HDF_SUCCESS) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "read config failed, path: %{public}s", path.c_str());
        result = "";
        return ret;
    }
    Trim(buf);
    result = buf;
    BATTERY_HILOGI(FEATURE_BATT_INFO, "GetConfigByPath(%{public}s) exit, value:%{public}s",
        path.c_str(), result.c_str());
    return HDF_SUCCESS;
}

int32_t PowerSupplyProvider::CheckPathExists(const std::string& path, bool& result)
{
    if (path.empty()) {
        BATTERY_HILOGE(FEATURE_BATT_INFO, "the path is empty");
        result = false;
        return HDF_ERR_INVALID_PARAM;
    }
    result = access(path.c_str(), F_OK) == 0;
    BATTERY_HILOGI(FEATURE_BATT_INFO, "CheckPathExists(%{public}s) exit, value:%{public}d", path.c_str(), result);
    return HDF_SUCCESS;
}
}  // namespace V2_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
