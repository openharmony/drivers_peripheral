/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "battery_led.h"

#include <hdf_base.h>
#include <fstream>
#include <memory>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include "battery_log.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_0 {
const int CAPACITY_FULL = 100;
const int MKDIR_WAIT_TIME = 1;
const int LED_COLOR_GREEN = 2;
const int LED_COLOR_RED = 4;
const int LED_COLOR_YELLOW = 6;
std::vector<std::string> g_ledsNodeName;
const std::string LEDS_BASE_PATH = "/sys/class/leds";
std::string g_redLedsNode = "red";
std::string g_greenLedsNode = "green";
std::string g_blueLedsNode = "blue";

void BatteryLed::TraversalNode()
{
    BATTERY_HILOGD(FEATURE_CHARGING, "enter");
    std::string::size_type idx;

    for (auto iter = g_ledsNodeName.begin(); iter != g_ledsNodeName.end(); ++iter) {
        idx = iter->find(g_redLedsNode);
        if (idx == std::string::npos) {
            BATTERY_HILOGD(FEATURE_CHARGING, "not found red leds node");
        } else {
            g_redLedsNode = *iter;
            BATTERY_HILOGD(FEATURE_CHARGING, "red leds node is %{public}s", iter->c_str());
        }

        idx = iter->find(g_greenLedsNode);
        if (idx == std::string::npos) {
            BATTERY_HILOGD(FEATURE_CHARGING, "not found green leds node");
        } else {
            g_greenLedsNode = *iter;
            BATTERY_HILOGD(FEATURE_CHARGING, "green leds node is %{public}s", iter->c_str());
        }

        idx = iter->find(g_blueLedsNode);
        if (idx == std::string::npos) {
            BATTERY_HILOGD(FEATURE_CHARGING, "not found blue leds node");
        } else {
            g_blueLedsNode = *iter;
            BATTERY_HILOGD(FEATURE_CHARGING, "blue leds node is %{public}s", iter->c_str());
        }
    }

    BATTERY_HILOGD(FEATURE_CHARGING, "exit");
}

int32_t BatteryLed::InitLedsSysfs()
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start init leds sysfs");
    DIR* dir = nullptr;
    struct dirent* entry = nullptr;
    int32_t index = 0;
    int maxSize = 64;

    dir = opendir(LEDS_BASE_PATH.c_str());
    if (dir == nullptr) {
        BATTERY_HILOGE(FEATURE_CHARGING, "leds base path is not exist");
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
            BATTERY_HILOGI(FEATURE_CHARGING, "init leds info of %{public}s", entry->d_name);
            if (index >= maxSize) {
                BATTERY_HILOGE(FEATURE_CHARGING, "too many leds types");
                break;
            }
            g_ledsNodeName.emplace_back(entry->d_name);
            index++;
        }
    }

    TraversalNode();
    BATTERY_HILOGD(FEATURE_CHARGING, "leds index is %{public}d", index);
    closedir(dir);

    BATTERY_HILOGD(FEATURE_CHARGING, "finish init leds sysfs");
    return HDF_SUCCESS;
}

void BatteryLed::TurnOffLed()
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start turn off led");
    WriteLedInfoToSys(0, 0, 0);

    BATTERY_HILOGD(FEATURE_CHARGING, "finish turn off led");
    return;
}

void BatteryLed::UpdateLedColor(const int32_t& chargestate, const int32_t& capacity)
{
    if ((chargestate == PowerSupplyProvider::CHARGE_STATE_NONE) ||
        (chargestate == PowerSupplyProvider::CHARGE_STATE_RESERVED)) {
        TurnOffLed();
        BATTERY_HILOGD(FEATURE_CHARGING, "not in charging state, turn off led");
        return;
    }

    std::unique_ptr<BatteryConfig> batteryConfig = std::make_unique<BatteryConfig>();
    if (batteryConfig == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "make_unique BatteryConfig return nullptr");
        return;
    }
    batteryConfig->Init();

    auto ledConf = batteryConfig->GetLedConf();
    for (auto it = ledConf.begin(); it != ledConf.end(); ++it) {
        BATTERY_HILOGD(FEATURE_CHARGING, "capacity=%{public}d, ledConf.begin()=%{public}d, ledConf.end()=%{public}d",
            capacity, it->capacityBegin, it->capacityEnd);
        if ((capacity >= it->capacityBegin) && (capacity < it->capacityEnd)) {
            switch (it->color) {
                case (LED_COLOR_GREEN): {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display green");
                    WriteLedInfoToSys(0, it->brightness, 0);
                    break;
                }
                case (LED_COLOR_RED): {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display red");
                    WriteLedInfoToSys(it->brightness, 0, 0);
                    break;
                }
                case (LED_COLOR_YELLOW): {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display yellow");
                    WriteLedInfoToSys(it->brightness, it->brightness, 0);
                    break;
                }
                default: {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display error.");
                    break;
                }
            }
            break;
        }

        if (capacity == CAPACITY_FULL) {
            BATTERY_HILOGD(FEATURE_CHARGING, "led color display green");
            WriteLedInfoToSys(0, it->brightness, 0);
            break;
        }
    }

    return;
}

void BatteryLed::WriteLedInfoToSys(const int redbrightness, const int greenbrightness, const int bluebrightness)
{
    FILE* file = nullptr;
    std::string redLedPath = LEDS_BASE_PATH + "/" + g_redLedsNode + "/" + "brightness";
    std::string greenLedPath = LEDS_BASE_PATH + "/" + g_greenLedsNode + "/" + "brightness";
    std::string blueLedPath = LEDS_BASE_PATH + "/" + g_blueLedsNode + "/" + "brightness";
    BATTERY_HILOGD(FEATURE_CHARGING, "redLedPath is %{public}s, greenLedPath is %{public}s, blueLedPath is %{public}s",
        redLedPath.c_str(), greenLedPath.c_str(), blueLedPath.c_str());
    InitMockLedFile(redLedPath, greenLedPath, blueLedPath);

    file = fopen(redLedPath.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "red led file open failed");
        return;
    }
    int ret = fprintf(file, "%d\n", redbrightness);
    if (ret < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "red led file fprintf failed");
    }
    ret = fclose(file);
    if (ret < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "red led file close failed");
        return;
    }

    file = fopen(greenLedPath.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "green led file open failed");
        return;
    }
    ret = fprintf(file, "%d\n", greenbrightness);
    if (ret < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "green led file fprintf failed.");
    }
    ret = fclose(file);
    if (ret < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "green led file close failed");
        return;
    }

    file = fopen(blueLedPath.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "blue led file open failed");
        return;
    }
    ret = fprintf(file, "%d\n", bluebrightness);
    if (ret < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "blue led file fprintf failed");
    }
    ret = fclose(file);
    if (ret < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "blue led file close failed");
        return;
    }
    return;
}

std::string BatteryLed::CreateFile(std::string path, std::string content) const
{
    BATTERY_HILOGI(FEATURE_CHARGING, "enter");
    std::ofstream stream(path.c_str());
    if (!stream.is_open()) {
        BATTERY_HILOGD(FEATURE_CHARGING, "Cannot create file %{public}s", path.c_str());
        return nullptr;
    }
    stream << content.c_str() << std::endl;
    stream.close();
    return path;
}

void BatteryLed::InitMockLedFile(std::string& redPath, std::string& greenPath, std::string& bluePath) const
{
    BATTERY_HILOGI(FEATURE_CHARGING, "enter");
    std::string mockLedsPath = "/data/local/tmp/leds";
    std::string sysLedsPath = "/sys/class/leds";
    std::string redLedPath = "/data/local/tmp/leds/sc27xx:red";
    std::string greenLedPath = "/data/local/tmp/leds/sc27xx:green";
    std::string blueLedPath = "/data/local/tmp/leds/sc27xx:blue";

    if (access(sysLedsPath.c_str(), F_OK) == 0) {
        BATTERY_HILOGD(FEATURE_CHARGING, "system leds path exist.");
        return;
    } else {
        redPath = "/data/local/tmp/leds/sc27xx:red/brightness";
        greenPath = "/data/local/tmp/leds/sc27xx:green/brightness";
        bluePath = "/data/local/tmp/leds/sc27xx:blue/brightness";
    }

    if (access(mockLedsPath.c_str(), 0) == -1) {
        int ret = mkdir("/data/local/tmp/leds", S_IRWXU);
        if (ret == -1) {
            BATTERY_HILOGD(FEATURE_CHARGING, "create leds path fail.");
            return;
        }
        sleep(MKDIR_WAIT_TIME);
    }

    InitRedLedPath(redLedPath);
    InitGreenLedPath(greenLedPath);
    InitBlueLedPath(blueLedPath);

    BATTERY_HILOGE(FEATURE_CHARGING, "create mock path for Hi3516DV300");
    CreateFile("/data/local/tmp/leds/sc27xx:red/brightness", "0");
    CreateFile("/data/local/tmp/leds/sc27xx:green/brightness", "0");
    CreateFile("/data/local/tmp/leds/sc27xx:blue/brightness", "0");
}

void BatteryLed::InitRedLedPath(std::string& redLedPath) const
{
    BATTERY_HILOGI(FEATURE_CHARGING, "enter");
    if (access(redLedPath.c_str(), 0) == -1) {
        int ret = mkdir("/data/local/tmp/leds/sc27xx:red", S_IRWXU);
        if (ret == -1) {
            BATTERY_HILOGD(FEATURE_CHARGING, "create red led path fail.");
            return;
        }
        sleep(MKDIR_WAIT_TIME);
    }

    BATTERY_HILOGI(FEATURE_CHARGING, "exit");
}

void BatteryLed::InitGreenLedPath(std::string& greenLedPath) const
{
    BATTERY_HILOGI(FEATURE_CHARGING, "enter");
    if (access(greenLedPath.c_str(), 0) == -1) {
        int ret = mkdir("/data/local/tmp/leds/sc27xx:green", S_IRWXU);
        if (ret == -1) {
            BATTERY_HILOGD(FEATURE_CHARGING, "create green led path fail.");
            return;
        }
        sleep(MKDIR_WAIT_TIME);
    }

    BATTERY_HILOGI(FEATURE_CHARGING, "exit");
}

void BatteryLed::InitBlueLedPath(std::string& blueLedPath) const
{
    BATTERY_HILOGI(FEATURE_CHARGING, "enter");
    if (access(blueLedPath.c_str(), 0) == -1) {
        int ret = mkdir("/data/local/tmp/leds/sc27xx:blue", S_IRWXU);
        if (ret == -1) {
            BATTERY_HILOGD(FEATURE_CHARGING, "create blue led path fail.");
            return;
        }
        sleep(MKDIR_WAIT_TIME);
    }

    BATTERY_HILOGI(FEATURE_CHARGING, "exit");
}
}  // namespace V1_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
