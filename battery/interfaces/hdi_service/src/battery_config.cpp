/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "battery_config.h"

#include "battery_log.h"
#include <climits>
#include "string_ex.h"
#include "config_policy_utils.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V2_0 {
namespace {
constexpr const char* BATTERY_CONFIG_PATH = "etc/battery/battery_config.json";
constexpr const char* SYSTEM_BATTERY_CONFIG_PATH = "/system/etc/battery/battery_config.json";
constexpr const char* VENDOR_BATTERY_CONFIG_PATH = "/vendor/etc/battery/battery_config.json";
constexpr const char* VENDOR_BATTERY_SPLIT_CONFIG_PATH = "/vendor/etc/battery/charge_config.json";
constexpr const char* BATTERY_CONFIG_EXCEPTION_PATH = "";
constexpr int32_t MAP_KEY_INDEX = 0;
constexpr int32_t BEGIN_SOC_INDEX = 0;
constexpr int32_t END_SOC_INDEX = 1;
constexpr int32_t MAX_SOC_RANGE = 2;
constexpr int32_t RED_INDEX = 0;
constexpr int32_t GREEN_INDEX = 1;
constexpr int32_t BLUE_INDEX = 2;
constexpr int32_t MAX_RGB_RANGE = 3;
constexpr int32_t MAX_DEPTH = 5;
constexpr int32_t MIN_DEPTH = 1;
constexpr uint32_t MOVE_LEFT_16 = 16;
constexpr uint32_t MOVE_LEFT_8 = 8;
constexpr uint32_t SYSTEM_PATH_CHECK = 4;
constexpr uint32_t DATA_PATH_CHECK = 5;
}
std::shared_ptr<BatteryConfig> BatteryConfig::instance_ = nullptr;
std::mutex BatteryConfig::mutex_;

BatteryConfig& BatteryConfig::GetInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<BatteryConfig>();
    }
    return *(instance_.get());
}

bool BatteryConfig::ParseConfig()
{
    char buf[MAX_PATH_LEN];
    char* path = GetOneCfgFile(BATTERY_CONFIG_PATH, buf, MAX_PATH_LEN);
    if (path == nullptr || *path == '\0') {
        BATTERY_HILOGW(COMP_HDI, "GetOneCfgFile battery_config.json is NULL");
        path = const_cast<char*>(BATTERY_CONFIG_EXCEPTION_PATH);
    }
    BATTERY_HILOGD(COMP_HDI, "GetOneCfgFile battery_config.json");

    Json::CharReaderBuilder readerBuilder;
    std::ifstream ifsConf;
    Json::Value config;
    readerBuilder["collectComments"] = false;
    JSONCPP_STRING errs;

    ifsConf.open(VENDOR_BATTERY_SPLIT_CONFIG_PATH);
    bool isOpen = ifsConf.is_open();
    if (isOpen) {
        if (parseFromStream(readerBuilder, ifsConf, &config, &errs) && !config.empty()) {
            ParseConfSplit(config);
        }
        ifsConf.close();

        if (!OpenFile(ifsConf, path)) {
            return false;
        }
        if (parseFromStream(readerBuilder, ifsConf, &config, &errs) && !config.empty()) {
            ParseConfInner(config);
        }
    } else {
        if (!OpenFile(ifsConf, path)) {
            return false;
        }
        if (parseFromStream(readerBuilder, ifsConf, &config, &errs) && !config.empty()) {
            ParseConfInner(config);
            ParseConfSplit(config);
        }
    }

    ifsConf.close();
    return true;
}

const std::vector<BatteryConfig::LightConfig>& BatteryConfig::GetLightConfig() const
{
    return lightConfig_;
}

const BatteryConfig::ChargerConfig& BatteryConfig::GetChargerConfig() const
{
    return chargerConfig_;
}

const std::map<std::string, BatteryConfig::ChargeSceneConfig>& BatteryConfig::GetChargeSceneConfigMap() const
{
    return chargeSceneConfigMap_;
}

const UeventMap& BatteryConfig::GetUeventList() const
{
    return ueventMap_;
}

void BatteryConfig::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    instance_ = nullptr;
}

bool BatteryConfig::OpenFile(std::ifstream& ifsConf, const std::string& configPath)
{
    bool isOpen = false;
    if (!configPath.empty()) {
        ifsConf.open(configPath);
        isOpen = ifsConf.is_open();
        BATTERY_HILOGD(COMP_HDI, "open file is %{public}d", isOpen);
    }
    if (isOpen) {
        return true;
    }

    ifsConf.open(VENDOR_BATTERY_CONFIG_PATH);
    isOpen = ifsConf.is_open();
    BATTERY_HILOGI(COMP_HDI, "open then vendor battery_config.json is %{public}d", isOpen);

    if (isOpen) {
        return true;
    }

    ifsConf.open(SYSTEM_BATTERY_CONFIG_PATH);
    isOpen = ifsConf.is_open();
    BATTERY_HILOGI(FEATURE_CHARGING, "open then system battery_config.json is %{public}d", isOpen);
    return isOpen;
}

void BatteryConfig::ParseConfInner(const Json::Value& config)
{
    BATTERY_HILOGI(COMP_HDI, "start parse battery config inner");
    ParseLightConfig(GetValue(config, "light"));
    ParseChargerConfig(GetValue(config, "charger"));
}

void BatteryConfig::ParseConfSplit(const Json::Value& config)
{
    BATTERY_HILOGI(COMP_HDI, "start parse split config inner");
    ParseChargeSceneConfig(GetValue(config, "charge_scene"));
    ParseUeventConfig(GetValue(config, "uevent"));
}

void BatteryConfig::ParseChargerConfig(const Json::Value& chargerConfig)
{
    if (chargerConfig.isNull() || !chargerConfig.isObject()) {
        BATTERY_HILOGW(COMP_HDI, "chargerConfig is invalid");
        return;
    }

    Json::Value currentPath = GetValue(chargerConfig, "current_limit.path");
    if (isValidJsonString(currentPath)) {
        chargerConfig_.currentPath = currentPath.asString();
    }

    Json::Value voltagePath = GetValue(chargerConfig, "voltage_limit.path");
    if (isValidJsonString(voltagePath)) {
        chargerConfig_.voltagePath = voltagePath.asString();
    }

    Json::Value chargeTypePath = GetValue(chargerConfig, "type.path");
    if (isValidJsonString(chargeTypePath)) {
        chargerConfig_.chargeTypePath = chargeTypePath.asString();
    }
    BATTERY_HILOGI(COMP_HDI, "The battery charger configuration parse succeed");
}

void BatteryConfig::ParseLightConfig(const Json::Value& lightConfig)
{
    if (lightConfig.isNull() || !lightConfig.isObject()) {
        BATTERY_HILOGW(COMP_HDI, "lightConf is invalid");
        return;
    }
    lightConfig_.clear();
    Json::Value::Members members = lightConfig.getMemberNames();
    for (auto iter = members.begin(); iter != members.end(); iter++) {
        std::string key = *iter;
        Json::Value valueObj = lightConfig[key];
        if (valueObj.isNull() || !valueObj.isObject()) {
            BATTERY_HILOGW(COMP_HDI, "The light conf is invalid, key=%{public}s", key.c_str());
            continue;
        }

        Json::Value soc = GetValue(valueObj, "soc");
        Json::Value rgb = GetValue(valueObj, "rgb");
        if (!soc.isArray() || !rgb.isArray()) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s configuration is invalid.", key.c_str());
            continue;
        }
        if (soc.size() != MAX_SOC_RANGE || !soc[BEGIN_SOC_INDEX].isInt() || !soc[END_SOC_INDEX].isInt()) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s soc data type error.", key.c_str());
            continue;
        }
        if (rgb.size() != MAX_RGB_RANGE || !rgb[RED_INDEX].isUInt() || !rgb[GREEN_INDEX].isUInt() ||
            !rgb[BLUE_INDEX].isUInt()) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s rgb data type error.", key.c_str());
            continue;
        }
        
        BatteryConfig::LightConfig tempLightConfig = {
            .beginSoc = soc[BEGIN_SOC_INDEX].asInt(),
            .endSoc = soc[END_SOC_INDEX].asInt(),
            .rgb = (rgb[RED_INDEX].asUInt() << MOVE_LEFT_16) |
                (rgb[GREEN_INDEX].asUInt() << MOVE_LEFT_8) |
                rgb[BLUE_INDEX].asUInt()
        };
        lightConfig_.push_back(tempLightConfig);
    }
    BATTERY_HILOGI(COMP_HDI, "The battery light configuration size %{public}d",
        static_cast<int32_t>(lightConfig_.size()));
}

void BatteryConfig::ParseChargeSceneConfig(const Json::Value& chargeSceneConfig)
{
    if (chargeSceneConfig.isNull() || !chargeSceneConfig.isObject()) {
        BATTERY_HILOGW(COMP_HDI, "chargeSceneConfig is invalid");
        return;
    }

    chargeSceneConfigMap_.clear();
    Json::Value::Members members = chargeSceneConfig.getMemberNames();
    for (auto iter = members.begin(); iter != members.end(); iter++) {
        std::string key = *iter;
        Json::Value valueObj = chargeSceneConfig[key];
        if (!IsValidChargeSceneConfig(key, valueObj)) {
            continue;
        }

        BatteryConfig::ChargeSceneConfig tempChargeSceneConfig;
        bool parseSupportPathResult = ParseChargeSceneSupport(valueObj, tempChargeSceneConfig);
        bool parseSetPathResult = ParseChargeSceneSet(valueObj, tempChargeSceneConfig);
        bool parseGetPathResult = ParseChargeSceneGet(valueObj, tempChargeSceneConfig);
        if (parseSupportPathResult || parseSetPathResult || parseGetPathResult) {
            chargeSceneConfigMap_.insert(std::make_pair(key, tempChargeSceneConfig));
        }
    }

    BATTERY_HILOGI(COMP_HDI, "The charge scene config size: %{public}d",
        static_cast<int32_t>(chargeSceneConfigMap_.size()));
}

bool BatteryConfig::IsValidChargeSceneConfig(const std::string& key, const Json::Value& valueObj)
{
    if (key.empty() || valueObj.isNull() || !valueObj.isObject()) {
        BATTERY_HILOGW(COMP_HDI, "The charge scene config is invalid, key=%{public}s", key.c_str());
        return false;
    }

    Json::Value supportPath = GetValue(valueObj, "support.path");
    Json::Value setPath = GetValue(valueObj, "set.path");
    Json::Value getPath = GetValue(valueObj, "get.path");
    if (!isValidJsonString(supportPath) && !isValidJsonString(setPath) && !isValidJsonString(getPath)) {
        BATTERY_HILOGW(COMP_HDI, "The charge scene config path is invalid, key=%{public}s", key.c_str());
        return false;
    }

    return true;
}

bool BatteryConfig::ParseChargeSceneSupport(const Json::Value& valueObj, BatteryConfig::ChargeSceneConfig& config)
{
    Json::Value supportPath = GetValue(valueObj, "support.path");
    Json::Value type = GetValue(valueObj, "support.type");
    Json::Value expectValue = GetValue(valueObj, "support.expect_value");
    if (isValidJsonString(supportPath)) {
        std::string path = supportPath.asString();
        if (IsValidSysPath(path)) {
            config.supportPath = path;
            config.type = isValidJsonString(type) ? type.asString() : "";
            config.expectValue = isValidJsonString(expectValue) ? expectValue.asString() : "";
            return true;
        }
    }
    return false;
}

bool BatteryConfig::ParseChargeSceneSet(const Json::Value& valueObj, BatteryConfig::ChargeSceneConfig& config)
{
    Json::Value setPath = GetValue(valueObj, "set.path");
    if (isValidJsonString(setPath)) {
        std::string path = setPath.asString();
        if (IsValidSysPath(path)) {
            config.setPath = path;
            return true;
        }
    }
    return false;
}

bool BatteryConfig::ParseChargeSceneGet(const Json::Value& valueObj, BatteryConfig::ChargeSceneConfig& config)
{
    Json::Value getPath = GetValue(valueObj, "get.path");
    if (isValidJsonString(getPath)) {
        std::string path = getPath.asString();
        if (IsValidSysPath(path)) {
            config.getPath = path;
            return true;
        }
    }
    return false;
}

bool BatteryConfig::IsValidSysPath(const std::string& path)
{
    char resolvedPath[PATH_MAX] = {};
    if ((realpath(path.c_str(), resolvedPath) == nullptr) ||
        ((strncmp(resolvedPath, "/sys", SYSTEM_PATH_CHECK) != 0) &&
        (strncmp(resolvedPath, "/data", DATA_PATH_CHECK) != 0))) {
        return false;
    }
    return true;
}

void BatteryConfig::ParseUeventConfig(const Json::Value& ueventConfig)
{
    if (ueventConfig.isNull() || !ueventConfig.isObject()) {
        BATTERY_HILOGW(COMP_HDI, "ueventConfig is invalid");
        return;
    }
    ueventMap_.clear();
    Json::Value::Members members = ueventConfig.getMemberNames();
    for (auto iter = members.begin(); iter != members.end(); iter++) {
        std::string key = *iter;
        Json::Value valueObj = ueventConfig[key];
        if (valueObj.isNull() || !valueObj.isObject()) {
            BATTERY_HILOGW(COMP_HDI, "The uevent conf is invalid, key=%{public}s", key.c_str());
            continue;
        }
        std::vector<std::pair<std::string, std::string>> ueventList;
        Json::Value::Members ObjMembers = valueObj.getMemberNames();
        for (auto it = ObjMembers.begin(); it != ObjMembers.end(); it++) {
            std::string event = *it;
            if (!valueObj[event].isString()) {
                BATTERY_HILOGW(COMP_SVC, "The uevent conf is invalid, key=%{public}s", key.c_str());
            }
            std::string act = valueObj[event].asString();
            ueventList.push_back(std::make_pair(event, act));
        }
        ueventMap_.emplace(*iter, ueventList);
        BATTERY_HILOGI(COMP_HDI, "%{public}s size: %{public}d", key.c_str(),
            static_cast<int32_t>(ueventList.size()));
    }
    BATTERY_HILOGI(COMP_HDI, "The uevent config size: %{public}d", static_cast<int32_t>(ueventMap_.size()));
}

bool BatteryConfig::SplitKey(const std::string& key, std::vector<std::string>& keys) const
{
    SplitStr(TrimStr(key), ".", keys);
    return (keys.size() < MIN_DEPTH || keys.size() > MAX_DEPTH) ? false : true;
}

Json::Value BatteryConfig::GetValue(const Json::Value& config, std::string key) const
{
    std::vector<std::string> keys;
    if (!SplitKey(key, keys)) {
        BATTERY_HILOGW(COMP_HDI, "The key does not meet the. key=%{public}s", key.c_str());
        return Json::Value();
    }

    std::string firstKey = keys[MAP_KEY_INDEX];
    Json::Value value = (config.isObject() && config.isMember(firstKey)) ? config[firstKey] : Json::Value();
    if (value.isNull()) {
        BATTERY_HILOGW(COMP_HDI, "Value is empty. key=%{public}s", keys[MAP_KEY_INDEX].c_str());
        return value;
    }

    for (size_t i = 1; i < keys.size(); ++i) {
        if (!value.isObject() || !value.isMember(keys[i])) {
            BATTERY_HILOGW(COMP_HDI, "The key is not configured. key=%{public}s", keys[i].c_str());
            break;
        }
        value = value[keys[i]];
    }
    return value;
}

bool BatteryConfig::isValidJsonString(const Json::Value& config) const
{
    return !config.isNull() && config.isString();
}
}  // namespace V2_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
