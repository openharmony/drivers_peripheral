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

#include "battery_config.h"
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG BatteryConfig

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_0 {
const std::string CONFIG_FILE = "/system/etc/ledconfig/led_config.json";
const int DEFAULT_CAPACITY_CONF = 3;
const int DEFAULT_UPPER_TEMP_CONF = 600;
const int DEFAULT_LOWER_TEMP_CONF = -100;
const int DEFAULT_CAPACITY_BEGIN_CONF = 0;
const int DEFAULT_CAPACITY_END_CONF = 100;
const int DEFAULT_LED_COLOR_CONF = 4;
const int DEFAULT_BRIGHTNESS_CONF = 255;

int32_t BatteryConfig::Init()
{
    return ParseConfig(CONFIG_FILE);
}

std::vector<BatteryConfig::LedConf> BatteryConfig::GetLedConf()
{
    return ledConf_;
}

BatteryConfig::TempConf BatteryConfig::GetTempConf()
{
    return tempConf_;
}

int BatteryConfig::GetCapacityConf()
{
    return capacityConf_;
}

int32_t BatteryConfig::ParseLedConf(Json::Value& root)
{
    struct LedConf ledConf;
    int size = root["led"]["table"].size();
    if (size == 0) {
        HDF_LOGW("%{public}s: read json file fail.", __func__);
        ledConf.capacityBegin = DEFAULT_CAPACITY_BEGIN_CONF;
        ledConf.capacityEnd = DEFAULT_CAPACITY_END_CONF;
        ledConf.color = DEFAULT_LED_COLOR_CONF;
        ledConf.brightness = DEFAULT_BRIGHTNESS_CONF;
        ledConf_.emplace_back(ledConf);
        return HDF_ERR_INVALID_OBJECT;
    }
    ledConf_.clear();

    for (int i = 0; i < size; ++i) {
        ledConf.capacityBegin = root["led"]["table"][i][INDEX_ZERO].asInt();
        ledConf.capacityEnd = root["led"]["table"][i][INDEX_ONE].asInt();
        ledConf.color = root["led"]["table"][i][INDEX_TWO].asInt();
        ledConf.brightness = root["led"]["table"][i][INDEX_THREE].asInt();
        ledConf_.emplace_back(ledConf);
    }
    return HDF_SUCCESS;
}

int32_t BatteryConfig::ParseTempConf(Json::Value& root)
{
    int size = root["temperature"]["table"].size();
    if (size == 0) {
        HDF_LOGW("%{public}s parse temperature config file fail.", __func__);
        tempConf_.lower = DEFAULT_LOWER_TEMP_CONF;
        tempConf_.upper = DEFAULT_UPPER_TEMP_CONF;
        return HDF_ERR_INVALID_OBJECT;
    }

    tempConf_.lower = root["temperature"]["table"][INDEX_ZERO].asInt();
    tempConf_.upper = root["temperature"]["table"][INDEX_ONE].asInt();
    return HDF_SUCCESS;
}

int32_t BatteryConfig::ParseCapacityConf(Json::Value& root)
{
    int size = root["soc"]["table"].size();
    if (size == 0) {
        HDF_LOGW("%{public}s parse capacity config file fail.", __func__);
        capacityConf_ = DEFAULT_CAPACITY_CONF;
        return HDF_ERR_INVALID_OBJECT;
    }

    capacityConf_ = root["soc"]["table"][INDEX_ZERO].asInt();
    return HDF_SUCCESS;
}

int32_t BatteryConfig::ParseConfig(const std::string filename)
{
    Json::Value root;
    Json::CharReaderBuilder readerBuilder;

    std::ifstream ledConfig;
    ledConfig.open(filename);

    root.clear();
    readerBuilder["collectComments"] = false;
    JSONCPP_STRING errs;

    if (parseFromStream(readerBuilder, ledConfig, &root, &errs)) {
        int32_t ret = ParseLedConf(root);
        if (ret != HDF_SUCCESS) {
            HDF_LOGI("%{public}s: parse led config fail.", __func__);
        }

        ret = ParseTempConf(root);
        if (ret != HDF_SUCCESS) {
            HDF_LOGI("%{public}s: parse temperature config fail.", __func__);
        }

        ret = ParseCapacityConf(root);
        if (ret != HDF_SUCCESS) {
            HDF_LOGI("%{public}s: parse soc config fail.", __func__);
        }
    }
    ledConfig.close();
    return HDF_SUCCESS;
}
}  // namespace V1_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
