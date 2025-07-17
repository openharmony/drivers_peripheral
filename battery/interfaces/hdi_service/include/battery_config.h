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

#ifndef BATTERY_CONFIG_H
#define BATTERY_CONFIG_H

#include <fstream>
#include <memory>
#include <mutex>
#include <vector>
#include <string>
#include <map>

#include <cJSON.h>
#include "nocopyable.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V2_0 {
using UeventMap = std::map<std::string, std::vector<std::pair<std::string, std::string>>>;
class BatteryConfig : public NoCopyable {
public:
    struct LightConfig {
        int32_t beginSoc;
        int32_t endSoc;
        uint32_t rgb;
    };

    struct ChargerConfig {
        std::string currentPath;
        std::string voltagePath;
        std::string chargeTypePath;
    };

    struct ChargeSceneConfig {
        std::string supportPath;
        std::string type;
        std::string expectValue;
        std::string getPath;
        std::string setPath;
    };
    static BatteryConfig& GetInstance();
    static void DestroyInstance();
    bool ParseConfig();
    const std::vector<LightConfig>& GetLightConfig() const;
    const BatteryConfig::ChargerConfig& GetChargerConfig() const;
    const std::map<std::string, BatteryConfig::ChargeSceneConfig>& GetChargeSceneConfigMap() const;
    const UeventMap& GetUeventList() const;

private:
    bool OpenFile(std::ifstream& ifsConf, const std::string& configPath);
    void ParseConfInner(const cJSON* config);
    void ParseConfSplit(const cJSON* config);
    void ParseLightConfig(const cJSON* lightConfig);
    void ParseChargeSceneConfig(const cJSON* chargeSceneConfig);
    bool IsValidChargeSceneConfig(const std::string& key, const cJSON* valueObj);
    bool ParseChargeSceneSupport(const cJSON* valueObj, BatteryConfig::ChargeSceneConfig& config);
    bool ParseChargeSceneSet(const cJSON* valueObj, BatteryConfig::ChargeSceneConfig& config);
    bool ParseChargeSceneGet(const cJSON* valueObj, BatteryConfig::ChargeSceneConfig& config);
    bool IsValidSysPath(const std::string& path);
    void ParseChargerConfig(const cJSON* chargerConfig);
    void ParseUeventConfig(const cJSON* ueventConfig);
    cJSON* ParseJsonStream(std::istream& ifsConf);
    bool SplitKey(const std::string& key, std::vector<std::string>& keys) const;
    cJSON* GetValue(const cJSON* config, std::string key) const;
    void SaveJsonResult(const cJSON* lightConfig);
    std::vector<BatteryConfig::LightConfig> lightConfig_;
    BatteryConfig::ChargerConfig chargerConfig_;
    std::map<std::string, BatteryConfig::ChargeSceneConfig> chargeSceneConfigMap_;
    static std::mutex mutex_;
    static std::shared_ptr<BatteryConfig> instance_;
    UeventMap ueventMap_;
};
}  // namespace V2_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
#endif
