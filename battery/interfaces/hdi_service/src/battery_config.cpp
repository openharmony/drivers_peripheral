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
#include "hdf_battery_json_utils.h"

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

cJSON* BatteryConfig::ParseJsonStream(std::istream& ifsConf)
{
    std::string content((std::istreambuf_iterator<char>(ifsConf)), std::istreambuf_iterator<char>());
    cJSON* config = cJSON_Parse(content.c_str());
    if (config == nullptr) {
        const char* errorPtr = cJSON_GetErrorPtr();
        BATTERY_HILOGE(COMP_HDI, "cJSON parse error: in %{public}s",
            (errorPtr != nullptr) ? errorPtr : "unknown error");
        return nullptr;
    }
    if (HdfBatteryJsonUtils::IsEmptyJsonParse(config)) {
        cJSON_Delete(config);
        BATTERY_HILOGW(COMP_HDI, "cJSON parse result is empty, battery config is %{public}s", content.c_str());
        return nullptr;
    }
    return config;
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

    cJSON* config = nullptr;
    std::ifstream ifsConf;
    ifsConf.open(VENDOR_BATTERY_SPLIT_CONFIG_PATH);
    bool isOpen = ifsConf.is_open();
    if (isOpen) {
        config = ParseJsonStream(ifsConf);
        if (config) {
            ParseConfSplit(config);
            cJSON_Delete(config);
        }
        ifsConf.close();
        config = nullptr;

        if (!OpenFile(ifsConf, path)) {
            return false;
        }
        config = ParseJsonStream(ifsConf);
        if (config) {
            ParseConfInner(config);
            cJSON_Delete(config);
        }
    } else {
        if (!OpenFile(ifsConf, path)) {
            return false;
        }
        config = ParseJsonStream(ifsConf);
        if (config) {
            ParseConfInner(config);
            ParseConfSplit(config);
            cJSON_Delete(config);
        }
    }
    ifsConf.close();
    config = nullptr;
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

void BatteryConfig::ParseConfInner(const cJSON* config)
{
    BATTERY_HILOGI(COMP_HDI, "start parse battery config inner");
    ParseLightConfig(GetValue(config, "light"));
    ParseChargerConfig(GetValue(config, "charger"));
}

void BatteryConfig::ParseConfSplit(const cJSON* config)
{
    BATTERY_HILOGI(COMP_HDI, "start parse split config inner");
    ParseChargeSceneConfig(GetValue(config, "charge_scene"));
    ParseUeventConfig(GetValue(config, "uevent"));
}

void BatteryConfig::ParseChargerConfig(const cJSON* chargerConfig)
{
    if (!HdfBatteryJsonUtils::IsValidJsonObject(chargerConfig)) {
        BATTERY_HILOGW(COMP_HDI, "chargerConfig is invalid");
        return;
    }

    cJSON* currentPath = GetValue(chargerConfig, "current_limit.path");
    if (HdfBatteryJsonUtils::IsValidJsonString(currentPath)) {
        chargerConfig_.currentPath = currentPath->valuestring;
    }

    cJSON* voltagePath = GetValue(chargerConfig, "voltage_limit.path");
    if (HdfBatteryJsonUtils::IsValidJsonString(voltagePath)) {
        chargerConfig_.voltagePath = voltagePath->valuestring;
    }

    cJSON* chargeTypePath = GetValue(chargerConfig, "type.path");
    if (HdfBatteryJsonUtils::IsValidJsonString(chargeTypePath)) {
        chargerConfig_.chargeTypePath = chargeTypePath->valuestring;
    }
    BATTERY_HILOGI(COMP_HDI, "The battery charger configuration parse succeed");
}

void BatteryConfig::ParseLightConfig(const cJSON* lightConfig)
{
    if (!HdfBatteryJsonUtils::IsValidJsonObject(lightConfig)) {
        BATTERY_HILOGW(COMP_HDI, "lightConf is invalid");
        return;
    }
    lightConfig_.clear();
    SaveJsonResult(lightConfig);
    BATTERY_HILOGI(COMP_HDI, "The battery light configuration size %{public}d",
        static_cast<int32_t>(lightConfig_.size()));
}

void BatteryConfig::SaveJsonResult(const cJSON* lightConfig)
{
    cJSON* valueObj = nullptr;
    cJSON_ArrayForEach(valueObj, lightConfig) {
        if (valueObj->string == nullptr) {
            BATTERY_HILOGW(COMP_HDI, "Found null key in light config");
            continue;
        }
        const std::string key = valueObj->string;
        if (cJSON_IsNull(valueObj) || !cJSON_IsObject(valueObj)) {
            BATTERY_HILOGW(COMP_HDI, "The light conf is invalid, key=%{public}s", key.c_str());
            continue;
        }
        cJSON* soc = GetValue(valueObj, "soc");
        cJSON* rgb = GetValue(valueObj, "rgb");
        if (!HdfBatteryJsonUtils::IsValidJsonArray(soc) || !HdfBatteryJsonUtils::IsValidJsonArray(rgb)) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s configuration is invalid.", key.c_str());
            continue;
        }
        if (cJSON_GetArraySize(soc) != MAX_SOC_RANGE) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s soc data length error.", key.c_str());
            continue;
        }
        cJSON* beginSocItem = cJSON_GetArrayItem(soc, BEGIN_SOC_INDEX);
        cJSON* endSocItem = cJSON_GetArrayItem(soc, END_SOC_INDEX);
        if (!HdfBatteryJsonUtils::IsValidJsonNumber(beginSocItem) ||
            !HdfBatteryJsonUtils::IsValidJsonNumber(endSocItem)) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s soc data type error.", key.c_str());
            continue;
        }
        if (cJSON_GetArraySize(rgb) != MAX_RGB_RANGE) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s rgb data length error.", key.c_str());
            continue;
        }
        cJSON* redItem = cJSON_GetArrayItem(rgb, RED_INDEX);
        cJSON* greenItem = cJSON_GetArrayItem(rgb, GREEN_INDEX);
        cJSON* blueItem = cJSON_GetArrayItem(rgb, BLUE_INDEX);
        if (!HdfBatteryJsonUtils::IsValidJsonNumber(redItem) || !HdfBatteryJsonUtils::IsValidJsonNumber(greenItem) ||
            !HdfBatteryJsonUtils::IsValidJsonNumber(blueItem)) {
            BATTERY_HILOGW(COMP_HDI, "The battery light %{public}s rgb data type error.", key.c_str());
            continue;
        }
        BatteryConfig::LightConfig tempLightConfig = {
            .beginSoc = static_cast<int32_t>(beginSocItem->valueint),
            .endSoc = static_cast<int32_t>(endSocItem->valueint),
            .rgb = (static_cast<uint32_t>(redItem->valueint) << MOVE_LEFT_16) |
                (static_cast<uint32_t>(greenItem->valueint) << MOVE_LEFT_8) | static_cast<uint32_t>(blueItem->valueint)
        };
        lightConfig_.push_back(tempLightConfig);
    }
}

void BatteryConfig::ParseChargeSceneConfig(const cJSON* chargeSceneConfig)
{
    if (!HdfBatteryJsonUtils::IsValidJsonObject(chargeSceneConfig)) {
        BATTERY_HILOGW(COMP_HDI, "chargeSceneConfig is invalid");
        return;
    }

    chargeSceneConfigMap_.clear();
    cJSON* valueObj = nullptr;
    cJSON_ArrayForEach(valueObj, chargeSceneConfig) {
        if (valueObj->string == nullptr) {
            BATTERY_HILOGW(COMP_HDI, "Found null key in charge scene config");
            continue;
        }
        const std::string key = valueObj->string;
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

bool BatteryConfig::IsValidChargeSceneConfig(const std::string& key, const cJSON* valueObj)
{
    if (key.empty() || !HdfBatteryJsonUtils::IsValidJsonObject(valueObj)) {
        BATTERY_HILOGW(COMP_HDI, "The charge scene config is invalid, key=%{public}s", key.c_str());
        return false;
    }

    cJSON* supportPath = GetValue(valueObj, "support.path");
    cJSON* setPath = GetValue(valueObj, "set.path");
    cJSON* getPath = GetValue(valueObj, "get.path");
    if (!HdfBatteryJsonUtils::IsValidJsonString(supportPath) && !HdfBatteryJsonUtils::IsValidJsonString(setPath) &&
        !HdfBatteryJsonUtils::IsValidJsonString(getPath)) {
        BATTERY_HILOGW(COMP_HDI, "The charge scene config path is invalid, key=%{public}s", key.c_str());
        return false;
    }

    return true;
}

bool BatteryConfig::ParseChargeSceneSupport(const cJSON* valueObj, BatteryConfig::ChargeSceneConfig& config)
{
    cJSON* supportPath = GetValue(valueObj, "support.path");
    cJSON* type = GetValue(valueObj, "support.type");
    cJSON* expectValue = GetValue(valueObj, "support.expect_value");
    if (HdfBatteryJsonUtils::IsValidJsonString(supportPath)) {
        std::string path = supportPath->valuestring;
        if (IsValidSysPath(path)) {
            config.supportPath = path;
            config.type = HdfBatteryJsonUtils::IsValidJsonString(type) ? type->valuestring : "";
            config.expectValue = HdfBatteryJsonUtils::IsValidJsonString(expectValue) ? expectValue->valuestring : "";
            return true;
        }
    }
    return false;
}

bool BatteryConfig::ParseChargeSceneSet(const cJSON* valueObj, BatteryConfig::ChargeSceneConfig& config)
{
    cJSON* setPath = GetValue(valueObj, "set.path");
    if (HdfBatteryJsonUtils::IsValidJsonString(setPath)) {
        std::string path = setPath->valuestring;
        if (IsValidSysPath(path)) {
            config.setPath = path;
            return true;
        }
    }
    return false;
}

bool BatteryConfig::ParseChargeSceneGet(const cJSON* valueObj, BatteryConfig::ChargeSceneConfig& config)
{
    cJSON* getPath = GetValue(valueObj, "get.path");
    if (HdfBatteryJsonUtils::IsValidJsonString(getPath)) {
        std::string path = getPath->valuestring;
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

void BatteryConfig::ParseUeventConfig(const cJSON* ueventConfig)
{
    if (!HdfBatteryJsonUtils::IsValidJsonObject(ueventConfig)) {
        BATTERY_HILOGW(COMP_HDI, "ueventConfig is invalid");
        return;
    }
    ueventMap_.clear();
    cJSON* valueObj = nullptr;
    cJSON_ArrayForEach(valueObj, ueventConfig) {
        if (valueObj->string == nullptr) {
            BATTERY_HILOGW(COMP_HDI, "Found null key in uevent config");
            continue;
        }
        const std::string key = valueObj->string;
        if (cJSON_IsNull(valueObj) || !cJSON_IsObject(valueObj)) {
            BATTERY_HILOGW(COMP_HDI, "The uevent conf is invalid, key=%{public}s", key.c_str());
            continue;
        }

        std::vector<std::pair<std::string, std::string>> ueventList;
        cJSON* subChild = nullptr;
        cJSON_ArrayForEach(subChild, valueObj) {
            if (subChild->string == nullptr) {
                BATTERY_HILOGW(COMP_SVC, "Found null key in uevent conf");
                continue;
            }
            const std::string event = subChild->string;
            if (!HdfBatteryJsonUtils::IsValidJsonString(subChild)) {
                BATTERY_HILOGW(COMP_SVC, "The uevent conf is invalid, key=%{public}s", key.c_str());
                continue;
            }
            std::string act = subChild->valuestring;
            ueventList.emplace_back(std::make_pair(event, act));
        }

        ueventMap_.emplace(key, ueventList);
        BATTERY_HILOGI(COMP_HDI, "%{public}s size: %{public}d", key.c_str(), static_cast<int32_t>(ueventList.size()));
    }
    BATTERY_HILOGI(COMP_HDI, "The uevent config size: %{public}d", static_cast<int32_t>(ueventMap_.size()));
}

bool BatteryConfig::SplitKey(const std::string& key, std::vector<std::string>& keys) const
{
    SplitStr(TrimStr(key), ".", keys);
    return (keys.size() < MIN_DEPTH || keys.size() > MAX_DEPTH) ? false : true;
}

cJSON* BatteryConfig::GetValue(const cJSON* config, std::string key) const
{
    std::vector<std::string> keys;
    if (!SplitKey(key, keys)) {
        BATTERY_HILOGW(COMP_HDI, "The key does not meet the. key=%{public}s", key.c_str());
        return nullptr;
    }

    std::string firstKey = keys[MAP_KEY_INDEX];
    cJSON* value = (config && cJSON_IsObject(config) && cJSON_HasObjectItem(config, firstKey.c_str())) ?
        cJSON_GetObjectItemCaseSensitive(config, firstKey.c_str()) : nullptr;
    if (!value || cJSON_IsNull(value)) {
        BATTERY_HILOGD(COMP_HDI, "Value is empty. key=%{public}s", key.c_str());
        return value;
    }

    for (size_t i = 1; i < keys.size(); ++i) {
        if (!cJSON_IsObject(value) || !cJSON_HasObjectItem(value, keys[i].c_str())) {
            BATTERY_HILOGW(COMP_HDI, "The key is not configured. key=%{public}s", keys[i].c_str());
            break;
        }
        value = cJSON_GetObjectItemCaseSensitive(value, keys[i].c_str());
    }
    return value;
}
}  // namespace V2_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
