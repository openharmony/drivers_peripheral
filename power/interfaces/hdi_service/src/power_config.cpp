/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
namespace V1_2 {
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

cJSON* PowerConfig::ParseJsonStream(std::istream& ifsConf)
{
    std::string content((std::istreambuf_iterator<char>(ifsConf)), std::istreambuf_iterator<char>());
    cJSON* config = cJSON_Parse(content.c_str());
    if (config == nullptr) {
        const char *errorPtr = cJSON_GetErrorPtr();
        HDF_LOGW("cJSON parse error: in %{public}s", (errorPtr != nullptr) ? errorPtr : "unknown error");
        return nullptr;
    }
    if (cJSON_IsNull(config) || (cJSON_IsObject(config) && (config->child == nullptr)) ||
        (cJSON_IsArray(config) && (cJSON_GetArraySize(config) == 0))) {
        cJSON_Delete(config);
        return nullptr;
    }
    return config;
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

    std::ifstream ifsConf;
    if (!OpenFile(ifsConf, path)) {
        return false;
    }

    cJSON* config = ParseJsonStream(ifsConf);
    ifsConf.close();
    if (!config) {
        HDF_LOGE("Failed to parse JSON");
        return false;
    }

    ParseConfInner(config);
    cJSON_Delete(config);
    config = nullptr;
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

void PowerConfig::ParseConfInner(const cJSON* config)
{
    HDF_LOGI("start parse power config inner");
    cJSON* sceneNode = GetValue(config, "scene");
    ParseSceneConfig(sceneNode);
}

bool PowerConfig::SplitKey(const std::string& key, std::vector<std::string>& keys) const
{
    SplitStr(TrimStr(key), ".", keys);
    return (keys.size() < MIN_DEPTH || keys.size() > MAX_DEPTH) ? false : true;
}

cJSON* PowerConfig::GetValue(const cJSON* config, std::string key) const
{
    std::vector<std::string> keys;
    if (!SplitKey(key, keys)) {
        HDF_LOGW("The key does not meet the. key=%{public}s", key.c_str());
        return nullptr;
    }

    std::string firstKey = keys[MAP_KEY_INDEX];
    cJSON* value = (config && cJSON_IsObject(config) && cJSON_HasObjectItem(config, firstKey.c_str())) ?
        cJSON_GetObjectItemCaseSensitive(config, firstKey.c_str()) : nullptr;
    if (!value || cJSON_IsNull(value)) {
        HDF_LOGW("Value is empty. key=%{public}s", key.c_str());
        return value;
    }
    for (size_t i = 1; i < keys.size(); ++i) {
        if (!cJSON_IsObject(value) || !cJSON_HasObjectItem(value, keys[i].c_str())) {
            HDF_LOGW("Invalid JSON type for key: %{public}s", keys[i].c_str());
            break;
        }
        value = cJSON_GetObjectItemCaseSensitive(value, keys[i].c_str());
    }
    return value;
}

void PowerConfig::ParseSceneConfig(const cJSON* sceneConfig)
{
    if (cJSON_IsNull(sceneConfig) || !cJSON_IsObject(sceneConfig)) {
        HDF_LOGW("sceneConfig is invalid");
        return;
    }

    sceneConfigMap_.clear();
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, sceneConfig)
    {
        if (!cJSON_IsObject(item))
            continue;

        const char* key = item->string;
        if (key == nullptr || strlen(key) == 0) {
            HDF_LOGW("Invalid scene key");
            continue;
        }

        PowerSceneConfig tempConfig;
        cJSON* getPath = GetValue(item, "get.path");
        cJSON* setPath = GetValue(item, "set.path");

        if (isValidJsonString(getPath)) {
            tempConfig.getPath = cJSON_GetStringValue(getPath);
            HDF_LOGI("getPath key=%{public}s", tempConfig.getPath.c_str());
        }
        if (isValidJsonString(setPath)) {
            tempConfig.setPath = cJSON_GetStringValue(setPath);
            HDF_LOGI("setPath key=%{public}s", tempConfig.setPath.c_str());
        }

        sceneConfigMap_.emplace(key, tempConfig);
    }
    HDF_LOGI("The charge scene config size: %{public}d", static_cast<int32_t>(sceneConfigMap_.size()));
}

bool PowerConfig::isValidJsonString(const cJSON* config) const
{
    return !cJSON_IsNull(config) && cJSON_IsString(config);
}

} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS
