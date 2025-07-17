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

#ifndef OHOS_HDI_POWER_V1_2_POWER_CONFIG_H
#define OHOS_HDI_POWER_V1_2_POWER_CONFIG_H

#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <cJSON.h>
#include "nocopyable.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
class PowerConfig : public NoCopyable {
public:
    struct PowerSceneConfig {
        std::string getPath;
        std::string setPath;
    };
    static PowerConfig& GetInstance();
    static void DestroyInstance();
    bool ParseConfig();
    const std::map<std::string, PowerConfig::PowerSceneConfig>& GetPowerSceneConfigMap() const;

private:
    bool OpenFile(std::ifstream& ifsConf, const std::string& configPath);
    void ParseConfInner(const cJSON* config);
    bool SplitKey(const std::string& key, std::vector<std::string>& keys) const;
    cJSON* GetValue(const cJSON* config, std::string key) const;
    void ParseSceneConfig(const cJSON* sceneConfig);
    cJSON* ParseJsonStream(std::istream& ifsConf);
    bool IsValidJsonString(const cJSON* config) const;
    bool IsValidJsonObject(const cJSON* jsonValue) const;
    std::map<std::string, PowerConfig::PowerSceneConfig> sceneConfigMap_;
    static std::mutex mutex_;
    static std::shared_ptr<PowerConfig> instance_;
};
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_POWER_V1_2_POWER_CONFIG_H