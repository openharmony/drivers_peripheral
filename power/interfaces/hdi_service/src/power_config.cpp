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

#include "power_config.h"
#include "string_ex.h"
#include "config_policy_utils.h"
#include "power_hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
namespace {
constexpr const char* POWER_CONFIG_PATH = "etc/power_config/power_config.json";
constexpr const char* SYSTEM_POWER_CONFIG_PATH = "/system/etc/power_config/power_config.json";
constexpr const char* VENDOR_POWER_CONFIG_PATH = "/vendor/etc/power_config/power_config.json";
constexpr const char* POWER_CONFIG_EXCEPTION_PATH = "";
constexpr int32_t MAP_KEY_INDEX = 0;
constexpr int32_t MAX_DEPTH = 5;
constexpr int32_t MIN_DEPTH = 1;
}

std::shared_ptr<PowerConfig> PowerConfig::instance_ = nullptr;
std::mutex PowerConfig::mutex_;

PowerConfig& PowerConfig::GetInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<PowerConfig>();
    }
    return *(instance_.get());
}

void PowerConfig::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    instance_ = nullptr;
}

const std::map<std::string, PowerConfig::PowerSceneConfig>& PowerConfig::GetPowerSceneConfigMap() const
{
    return sceneConfigMap_;
}

bool PowerConfig::ParseConfig()
{
    char buf[MAX_PATH_LEN];
    char* path = GetOneCfgFile(POWER_CONFIG_PATH, buf, MAX_PATH_LEN);
    if (path == nullptr || *path == '\0') {
        HDF_LOGW("GetOneCfgFile power_config.json is NULL");
        path = const_cast<char*>(POWER_CONFIG_EXCEPTION_PATH);
    }
    HDF_LOGI("GetOneCfgFile power_config.json");

    Json::CharReaderBuilder readerBuilder;
    std::ifstream ifsConf;

    if (!OpenFile(ifsConf, path)) {
        return false;
    }

    Json::Value config;
    readerBuilder["collectComments"] = false;
    JSONCPP_STRING errs;

    if (parseFromStream(readerBuilder, ifsConf, &config, &errs) && !config.empty()) {
        ParseConfInner(config);
    }
    ifsConf.close();
    return true;
}

bool PowerConfig::OpenFile(std::ifstream& ifsConf, const std::string& configPath)
{
    bool isOpen = false;
    if (!configPath.empty()) {
        ifsConf.open(configPath);
        isOpen = ifsConf.is_open();
        HDF_LOGI("path is %{public}s", configPath.c_str());
        HDF_LOGI("open file is %{public}d", isOpen);
    }
    if (isOpen) {
        return true;
    }

    ifsConf.open(VENDOR_POWER_CONFIG_PATH);
    isOpen = ifsConf.is_open();
    HDF_LOGI("open then vendor battery_config.json is %{public}d", isOpen);

    if (isOpen) {
        return true;
    }

    ifsConf.open(SYSTEM_POWER_CONFIG_PATH);
    isOpen = ifsConf.is_open();
    HDF_LOGI("open then system battery_config.json is %{public}d", isOpen);
    return isOpen;
}

void PowerConfig::ParseConfInner(const Json::Value& config)
{
    HDF_LOGI("start parse power config inner");
    ParseSceneConfig(GetValue(config, "scene"));
}

bool PowerConfig::SplitKey(const std::string& key, std::vector<std::string>& keys) const
{
    SplitStr(TrimStr(key), ".", keys);
    return (keys.size() < MIN_DEPTH || keys.size() > MAX_DEPTH) ? false : true;
}

Json::Value PowerConfig::GetValue(const Json::Value& config, std::string key) const
{
    std::vector<std::string> keys;
    if (!SplitKey(key, keys)) {
        HDF_LOGW("The key does not meet the. key=%{public}s", key.c_str());
        return Json::Value();
    }

    std::string firstKey = keys[MAP_KEY_INDEX];
    Json::Value value = (config.isObject() && config.isMember(firstKey)) ? config[firstKey] : Json::Value();
    if (value.isNull()) {
        HDF_LOGW("Value is empty. key=%{public}s", keys[MAP_KEY_INDEX].c_str());
        return value;
    }

    for (size_t i = 1; i < keys.size(); ++i) {
        if (!value.isObject() || !value.isMember(keys[i])) {
            HDF_LOGW("The key is not configured. key=%{public}s", keys[i].c_str());
            break;
        }
        value = value[keys[i]];
    }
    return value;
}

void PowerConfig::ParseSceneConfig(const Json::Value& sceneConfig)
{
    if (sceneConfig.isNull() || !sceneConfig.isObject()) {
        HDF_LOGW("sceneConfig is invalid");
        return;
    }

    sceneConfigMap_.clear();
    Json::Value::Members members = sceneConfig.getMemberNames();
    for (auto iter = members.begin(); iter != members.end(); iter++) {
        std::string key = *iter;
        Json::Value valueObj = sceneConfig[key];
        if (key.empty() || valueObj.isNull() || !valueObj.isObject()) {
            HDF_LOGW("The scene config is invalid, key=%{public}s", key.c_str());
            continue;
        }

        PowerConfig::PowerSceneConfig tempPowerSceneConfig;
        Json::Value getPath = GetValue(valueObj, "get.path");
        Json::Value setPath = GetValue(valueObj, "set.path");
        if (isValidJsonString(getPath)) {
            tempPowerSceneConfig.getPath = getPath.asString();
            HDF_LOGI("getPath key=%{public}s", tempPowerSceneConfig.getPath.c_str());
        }
        if (isValidJsonString(setPath)) {
            tempPowerSceneConfig.setPath = setPath.asString();
            HDF_LOGI("setPath key=%{public}s", tempPowerSceneConfig.setPath.c_str());
        }

        sceneConfigMap_.insert(std::make_pair(key, tempPowerSceneConfig));
    }
    HDF_LOGI("The charge scene config size: %{public}d",
        static_cast<int32_t>(sceneConfigMap_.size()));
}

bool PowerConfig::isValidJsonString(const Json::Value& config) const
{
    return !config.isNull() && config.isString();
}

} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS