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
namespace {
const std::string CONFIG_FILE = "/system/etc/ledconfig/led_config.json";
constexpr int32_t DEFAULT_CAPACITY_CONF = 3;
constexpr int32_t DEFAULT_UPPER_TEMP_CONF = 600;
constexpr int32_t DEFAULT_LOWER_TEMP_CONF = -100;
constexpr int32_t DEFAULT_CAPACITY_BEGIN_CONF = 0;
constexpr int32_t DEFAULT_CAPACITY_END_CONF = 100;
constexpr int32_t DEFAULT_LED_COLOR_CONF = 4;
constexpr int32_t DEFAULT_BRIGHTNESS_CONF = 255;
}

void BatteryConfig::Init()
{
    ParseConfig(CONFIG_FILE);
}

std::vector<BatteryConfig::LedConf> BatteryConfig::GetLedConf()
{
    return ledConf_;
}

BatteryConfig::TempConf BatteryConfig::GetTempConf()
{
    return tempConf_;
}

int32_t BatteryConfig::GetCapacityConf()
{
    return capacityConf_;
}

int32_t BatteryConfig::ParseLedConf(Json::Value& root)
{
    struct LedConf ledConf = {0};
    size_t size = root["led"]["table"].size();
    HDF_LOGI("%{public}s: size = %{public}zu", __func__, size);
    if (size == 0) {
        HDF_LOGW("%{public}s: read json file fail, use default led config", __func__);
        ledConf.capacityBegin = DEFAULT_CAPACITY_BEGIN_CONF;
        ledConf.capacityEnd = DEFAULT_CAPACITY_END_CONF;
        ledConf.color = DEFAULT_LED_COLOR_CONF;
        ledConf.brightness = DEFAULT_BRIGHTNESS_CONF;
        ledConf_.emplace_back(ledConf);
        return HDF_ERR_INVALID_OBJECT;
    }
    ledConf_.clear();

    const size_t COLOR_SIZE = 4;
    for (int32_t i = 0; i < size; ++i) {
        size_t colorSize = root["led"]["table"][i].size();
        if (colorSize != COLOR_SIZE) {
            HDF_LOGW("%{public}s: read json file fail, color size error, size=%{public}zu", __func__, colorSize);
            return HDF_ERR_INVALID_OBJECT;
        }
        ledConf.capacityBegin = root["led"]["table"][i][INDEX_ZERO].asInt();
        ledConf.capacityEnd = root["led"]["table"][i][INDEX_ONE].asInt();
        ledConf.color = root["led"]["table"][i][INDEX_TWO].asInt();
        ledConf.brightness = root["led"]["table"][i][INDEX_THREE].asInt();
        HDF_LOGI("%{public}s: capacityBegin= %{public}d, capacityEnd=%{public}d, color=%{public}d, \
            brightness=%{public}d", __func__, ledConf.capacityBegin, ledConf.capacityEnd, ledConf.color, \
            ledConf.brightness);
        ledConf_.emplace_back(ledConf);
    }
    return HDF_SUCCESS;
}

int32_t BatteryConfig::ParseTemperatureConf(Json::Value& root)
{
    const size_t TABLE_SIZE = 2;
    size_t size = root["temperature"]["table"].size();
    if (size != TABLE_SIZE) {
        HDF_LOGW("%{public}s parse temperature config file fail, use default temperature config, size=%{public}zu",
                 __func__, size);
        tempConf_.lower = DEFAULT_LOWER_TEMP_CONF;
        tempConf_.upper = DEFAULT_UPPER_TEMP_CONF;
        return HDF_ERR_INVALID_OBJECT;
    }
    tempConf_.lower = root["temperature"]["table"][INDEX_ZERO].asInt();
    tempConf_.upper = root["temperature"]["table"][INDEX_ONE].asInt();
    HDF_LOGI("%{public}s: tempConf_.lower=%{public}d, tempConf_.upper=%{public}d", __func__, \
        tempConf_.lower, tempConf_.upper);

    return HDF_SUCCESS;
}

int32_t BatteryConfig::ParseCapacityConf(Json::Value& root)
{
    const size_t TABLE_SIZE = 1;
    size_t size = root["soc"]["table"].size();
    if (size != TABLE_SIZE) {
        HDF_LOGW("%{public}s parse capacity config file fail, use default capacity config, size=%{public}zu",
                 __func__, size);
        capacityConf_ = DEFAULT_CAPACITY_CONF;
        return HDF_ERR_INVALID_OBJECT;
    }
    capacityConf_ = root["soc"]["table"][INDEX_ZERO].asInt();
    HDF_LOGI("%{public}s: capacityConf_ = %{public}d", __func__, capacityConf_);
    return HDF_SUCCESS;
}

void BatteryConfig::ParseConfig(const std::string& filename)
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
            HDF_LOGW("%{public}s: parse led config fail.", __func__);
        }

        ret = ParseTemperatureConf(root);
        if (ret != HDF_SUCCESS) {
            HDF_LOGW("%{public}s: parse temperature config fail.", __func__);
        }

        ret = ParseCapacityConf(root);
        if (ret != HDF_SUCCESS) {
            HDF_LOGW("%{public}s: parse soc config fail.", __func__);
        }
    }
    ledConfig.close();
}
}  // namespace V1_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
