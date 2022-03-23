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

#include "battery_vibrate.h"

#include <unistd.h>
#include "sys/stat.h"
#include "battery_log.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_0 {
const std::string VIBRATOR_PLAYMODE_PATH = "/sys/class/leds/vibrator/play_mode";
const std::string VIBRATOR_DURATIONMODE_PATH = "/sys/class/leds/vibrator/duration";
const std::string VIBRATOR_ACTIVATEMODE_PATH = "/sys/class/leds/vibrator/activate";
const int VIBRATION_PLAYMODE = 0;
const int VIBRATION_DURATIONMODE = 1;
const int VIBRATE_DELAY_MS = 5;
const int USEC_TO_MSEC = 1000;

int BatteryVibrate::VibrateInit()
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start init vibrate");
    struct stat st {};

    if (!stat(VIBRATOR_PLAYMODE_PATH.c_str(), &st)) {
        BATTERY_HILOGD(FEATURE_CHARGING, "vibrate path is play mode path");
        vibrateMode_ = VIBRATION_PLAYMODE;
        return 0;
    }

    if (!stat(VIBRATOR_DURATIONMODE_PATH.c_str(), &st)) {
        BATTERY_HILOGD(FEATURE_CHARGING, "vibrate path is duration path");
        vibrateMode_ = VIBRATION_DURATIONMODE;
        return 0;
    }

    BATTERY_HILOGI(FEATURE_CHARGING, "not support vibrate path");
    return -1;
}

FILE* BatteryVibrate::HandlePlayModePath() const
{
    FILE* file = nullptr;

    file = fopen(VIBRATOR_PLAYMODE_PATH.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "play mode path open failed.");
        return nullptr;
    }
    if (fprintf(file, "%s\n", "direct") < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "fprintf direct failed.");
    }
    if (fclose(file) < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "fclose failed.");
        return nullptr;
    }

    return file;
}

void BatteryVibrate::HandlePlayMode(const int time) const
{
    FILE* file = nullptr;

    file = HandlePlayModePath();
    if (file == nullptr) {
        return;
    }

    file = fopen(VIBRATOR_DURATIONMODE_PATH.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "duration mode path open failed.");
        return;
    }
    if (fprintf(file, "%d\n", time) < 0) {
        BATTERY_HILOGD(FEATURE_CHARGING, "duration mode fprintf time failed.");
    }
    if (fclose(file) < 0) {
        BATTERY_HILOGD(FEATURE_CHARGING, "duration mode fclose failed.");
        return;
    }

    file = fopen(VIBRATOR_ACTIVATEMODE_PATH.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "activate mode path open failed.");
        return;
    }
    if (fprintf(file, "%d\n", 1) < 0) {
        BATTERY_HILOGD(FEATURE_CHARGING, "activate mode fprintf 1 failed.");
    }
    if (fclose(file) < 0) {
        BATTERY_HILOGD(FEATURE_CHARGING, "activate mode fclose failed.");
        return;
    }

    usleep((time + VIBRATE_DELAY_MS) * USEC_TO_MSEC);
    file = fopen(VIBRATOR_PLAYMODE_PATH.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "play mode path open failed.");
        return;
    }
    if (fprintf(file, "%s\n", "audio") < 0) {
        BATTERY_HILOGD(FEATURE_CHARGING, "play mode fprintf audio failed.");
    }
    if (fclose(file) < 0) {
        BATTERY_HILOGD(FEATURE_CHARGING, "play mode fclose failed.");
        return;
    }
}

void BatteryVibrate::HandleDurationMode(const int time) const
{
    FILE* file = nullptr;

    file = fopen(VIBRATOR_DURATIONMODE_PATH.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "duration mode path open failed.");
        return;
    }
    if (fprintf(file, "%d\n", time) < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "duration mode fprintf time failed.");
    }
    if (fclose(file) < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "duration mode fclose failed.");
        return;
    }

    file = fopen(VIBRATOR_ACTIVATEMODE_PATH.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "activate mode path open failed.");
        return;
    }
    if (fprintf(file, "%d\n", 1) < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "activate mode fprintf 1 failed.");
    }
    if (fclose(file) < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "activate mode fclose failed.");
        return;
    }

    usleep((time + VIBRATE_DELAY_MS) * USEC_TO_MSEC);
    file = fopen(VIBRATOR_ACTIVATEMODE_PATH.c_str(), "w");
    if (file == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "activate mode path open failed.");
        return;
    }
    if (fprintf(file, "%d\n", 0) < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "activate mode fprintf 0 failed.");
    }
    if (fclose(file) < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "activate mode fclose failed.");
        return;
    }
}

void BatteryVibrate::HandleVibrate(const int time)
{
    switch (vibrateMode_) {
        case VIBRATION_PLAYMODE: {
            BATTERY_HILOGD(FEATURE_CHARGING, "vibrate play mode");
            HandlePlayMode(time);
            break;
        }
        case VIBRATION_DURATIONMODE: {
            BATTERY_HILOGD(FEATURE_CHARGING, "vibrate duration mode");
            HandleDurationMode(time);
            break;
        }
        default: {
            BATTERY_HILOGD(FEATURE_CHARGING, "vibrate unknown mode");
            break;
        }
    }

    return;
}
}  // namespace V1_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
