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

#include "charger_thread.h"

#include <parameters.h>
#include <securec.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <cinttypes>
#include "updater_ui.h"
#include "text_label.h"
#include "view.h"
#include "input_manager.h"
#include "power_mgr_client.h"
#include "battery_log.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_0 {
struct KeyState {
    bool up;
    bool down;
    int64_t timestamp;
};

constexpr int SHUTDOWN_TIME_MS = 2000;
constexpr long long MAX_INT64 = 9223372036854775807;
constexpr int SEC_TO_MSEC = 1000;
constexpr int NSEC_TO_MSEC = 1000000;
constexpr int REBOOT_TIME = 2000;
constexpr int BACKLIGHT_OFF_TIME_MS = 10000;
constexpr uint32_t INIT_DEFAULT_VALUE = 255;
constexpr int VIBRATE_TIME_MS = 75;
constexpr int MAX_IMGS = 62;
constexpr int MAX_IMGS_NAME_SIZE = 255;
constexpr int LOOP_TOP_PICTURES = 10;

Frame* g_hosFrame;
Frame* g_updateFrame;
AnimationLabel* g_animationLabel;
TextLabel* g_updateInfoLabel;
TextLabel* g_logLabel;
TextLabel* g_logResultLabel;
IInputInterface* g_inputInterface;
InputEventCb g_callback;
struct KeyState g_keys[KEY_MAX + 1] = {};

int64_t ChargerThread::keyWait_ = -1;
int64_t ChargerThread::backlightWait_ = -1;
int32_t ChargerThread::capacity_ = -1;

static int64_t GetCurrentTime()
{
    timespec tm {};
    clock_gettime(CLOCK_MONOTONIC, &tm);
    return tm.tv_sec * SEC_TO_MSEC + (tm.tv_nsec / NSEC_TO_MSEC);
}

void ChargerThread::HandleStates()
{
    HandleChargingState();
    HandlePowerKeyState();
    HandleScreenState();

    return;
}

int ChargerThread::UpdateWaitInterval()
{
    int64_t currentTime = GetCurrentTime();
    int64_t nextWait = MAX_INT64;
    int64_t timeout;

    if (pluginWait_ != -1) {
        nextWait = pluginWait_ - currentTime;
    }

    if (keyWait_ != -1 && keyWait_ < nextWait) {
        nextWait = keyWait_;
    }

    if (backlightWait_ != -1 && backlightWait_ < nextWait) {
        nextWait = backlightWait_;
    }

    if (nextWait != -1 && nextWait != MAX_INT64) {
        if (nextWait - currentTime > 0) {
            timeout = nextWait - currentTime;
        } else {
            timeout = 0;
        }
    } else {
        timeout = -1;
    }

    return timeout;
}

void ChargerThread::AnimationInit()
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start init animation");
    constexpr char alpha = 0xff;
    int screenH = 0;
    int screenW = 0;
    auto* sfDev = new SurfaceDev(SurfaceDev::DevType::DRM_DEVICE);
    sfDev->GetScreenSize(screenW, screenH);
    View::BRGA888Pixel bgColor {0x00, 0x00, 0x00, alpha};

    g_hosFrame = new Frame(screenW, screenH, View::PixelFormat::BGRA888, sfDev);
    g_hosFrame->SetBackgroundColor(&bgColor);

    g_animationLabel = new AnimationLabel(90, 240, 360, 960 >> 1, g_hosFrame);
    g_animationLabel->SetBackgroundColor(&bgColor);
    LoadImgs(g_animationLabel);

    g_updateInfoLabel = new TextLabel(screenW / 3, 340, screenW / 3, HEIGHT5, g_hosFrame);
    g_updateInfoLabel->SetOutLineBold(false, false);
    g_updateInfoLabel->SetBackgroundColor(&bgColor);

    BATTERY_HILOGD(FEATURE_CHARGING, "finish init animation");
    return;
}

void ChargerThread::LoadImgs(AnimationLabel* g_animationLabel)
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start load images");
    char nameBuf[MAX_IMGS_NAME_SIZE];
    for (int i = 0; i < MAX_IMGS; i++) {
        if (memset_s(nameBuf, MAX_IMGS_NAME_SIZE + 1, 0, MAX_IMGS_NAME_SIZE) != EOK) {
            BATTERY_HILOGW(FEATURE_CHARGING, "memset_s failed");
            return;
        }

        if (i < LOOP_TOP_PICTURES) {
            if (snprintf_s(nameBuf, MAX_IMGS_NAME_SIZE, MAX_IMGS_NAME_SIZE - 1,
                "/system/etc/resources/loop0000%d.png", i) == -1) {
                BATTERY_HILOGW(FEATURE_CHARGING, "snprintf_s failed, index=%{public}d", i);
                return;
            }
        } else {
            if (snprintf_s(nameBuf, MAX_IMGS_NAME_SIZE, MAX_IMGS_NAME_SIZE - 1,
                "/system/etc/resources/loop000%d.png", i) == -1) {
                BATTERY_HILOGW(FEATURE_CHARGING, "snprintf_s failed, index=%{public}d", i);
                return;
            }
        }

        g_animationLabel->AddImg(nameBuf);
    }
    g_animationLabel->AddStaticImg(nameBuf);
}

void ChargerThread::UpdateAnimation(const int32_t& capacity)
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start update animation, capacity=%{public}d", capacity);
    AnimationLabel::needStop_ = false;

    struct FocusInfo info {false, false};
    struct Bold bold {false, false};
    View::BRGA888Pixel bgColor {0x00, 0x00, 0x00, 0xff};
    std::string displaySoc = "  " + std::to_string(capacity) + "%";
    TextLabelInit(g_updateInfoLabel, displaySoc, bold, info, bgColor);
    g_animationLabel->UpdateLoop();

    return;
}

void ChargerThread::CycleMatters()
{
    if (!started_) {
        started_ = true;
        backlightWait_ = GetCurrentTime() - 1;
    }

    provider_->ParseCapacity(&capacity_);
    provider_->ParseChargeState(&chargeState_);
    BATTERY_HILOGI(FEATURE_CHARGING, "chargeState_=%{public}d, capacity_=%{public}d", chargeState_, capacity_);

    UpdateEpollInterval(chargeState_);

    return;
}

void ChargerThread::UpdateBatteryInfo(void* arg, char* msg)
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start update battery info by uevent msg");
    std::unique_ptr<BatterydInfo> batteryInfo = std::make_unique<BatterydInfo>();
    if (batteryInfo == nullptr) {
        BATTERY_HILOGE(FEATURE_CHARGING, "make_unique BatterydInfo return nullptr");
        return;
    }

    provider_->ParseUeventToBatterydInfo(msg, batteryInfo.get());

    capacity_ = batteryInfo->capacity_;
    chargeState_ = batteryInfo->chargeState_;

    HandleCapacity(capacity_);
    HandleTemperature(batteryInfo->temperature_);

    led_->UpdateLedColor(chargeState_, capacity_);
    if (backlight_->GetScreenState()) {
        UpdateAnimation(capacity_);
    }

    BATTERY_HILOGD(FEATURE_CHARGING, "finish update battery info");
    return;
}

void ChargerThread::UpdateBatteryInfo(void* arg)
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start update battery info by provider");
    int32_t temperature = 0;
    provider_->ParseTemperature(&temperature);
    provider_->ParseCapacity(&capacity_);
    provider_->ParseChargeState(&chargeState_);
    BATTERY_HILOGD(FEATURE_CHARGING, "temperature=%{public}d, capacity_=%{public}d, chargeState_=%{public}d",
        temperature, capacity_, chargeState_);

    HandleTemperature(temperature);
    HandleCapacity(capacity_);

    led_->UpdateLedColor(chargeState_, capacity_);
    if (backlight_->GetScreenState()) {
        UpdateAnimation(capacity_);
    }

    return;
}

void ChargerThread::HandleCapacity(const int32_t& capacity)
{
    auto lowCapacity = batteryConfig_->GetCapacityConf();
    BATTERY_HILOGD(FEATURE_CHARGING, "capacity=%{public}d, lowCapacity=%{public}d", capacity, lowCapacity);
    auto& powerMgrClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
    if ((capacity <= lowCapacity) &&
        ((chargeState_ == PowerSupplyProvider::CHARGE_STATE_NONE) ||
        (chargeState_ == PowerSupplyProvider::CHARGE_STATE_RESERVED))) {
        BATTERY_HILOGW(FEATURE_CHARGING, "low capacity, shutdown device");
        std::string reason = "LowCapacity";
        powerMgrClient.ShutDownDevice(reason);
    }

    return;
}

void ChargerThread::HandleTemperature(const int32_t& temperature)
{
    auto tempConf = batteryConfig_->GetTempConf();
    BATTERY_HILOGD(FEATURE_CHARGING, "temperature=%{public}d, tempConf.lower=%{public}d, tempConf.upper=%{public}d",
        temperature, tempConf.lower, tempConf.upper);

    auto& powerMgrClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
    if (((temperature <= tempConf.lower) || (temperature >= tempConf.upper)) &&
        (tempConf.lower != tempConf.upper)) {
        BATTERY_HILOGW(FEATURE_CHARGING, "temperature out of range, shutdown device");
        std::string reason = "TemperatureOutOfRange";
        powerMgrClient.ShutDownDevice(reason);
    }

    return;
}

void ChargerThread::SetKeyWait(struct KeyState& key, int64_t timeout)
{
    int64_t nextMoment = key.timestamp + timeout;
    if (keyWait_ == -1 || nextMoment < keyWait_) {
        keyWait_ = nextMoment;
    }

    return;
}

void ChargerThread::HandleChargingState()
{
    int64_t now = GetCurrentTime();
    BATTERY_HILOGD(FEATURE_CHARGING, "chargeState_=%{public}d, now=%{public}" PRId64 "", chargeState_, now);
    auto& powerMgrClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();

    if ((chargeState_ == PowerSupplyProvider::CHARGE_STATE_NONE) ||
        (chargeState_ == PowerSupplyProvider::CHARGE_STATE_RESERVED)) {
        if (pluginWait_ == -1) {
            BATTERY_HILOGD(FEATURE_CHARGING, "wait plugin");
            backlightWait_ = now - 1;
            backlight_->TurnOnScreen();
            led_->TurnOffLed();
            AnimationLabel::needStop_ = true;
            pluginWait_ = now + SHUTDOWN_TIME_MS;
        } else if (now >= pluginWait_) {
            BATTERY_HILOGI(FEATURE_CHARGING, "shutdown device, pluginWait_=%{public}" PRId64 "", pluginWait_);
            std::string reason = "charger unplugged";
            powerMgrClient.ShutDownDevice(reason);
        } else {
            BATTERY_HILOGD(FEATURE_CHARGING, "ShutDownDevice timer already in scheduled.");
        }
    } else {
        if (pluginWait_ != -1) {
            BATTERY_HILOGI(FEATURE_CHARGING, "update capacity_=%{public}d", capacity_);
            backlightWait_ = now - 1;
            backlight_->TurnOnScreen();
            led_->UpdateLedColor(chargeState_, capacity_);
            AnimationLabel::needStop_ = true;
            UpdateAnimation(capacity_);
        }
        pluginWait_ = -1;
    }

    return;
}

void ChargerThread::HandleScreenState()
{
    if (backlightWait_ != -1 && GetCurrentTime() > backlightWait_ + BACKLIGHT_OFF_TIME_MS) {
        BATTERY_HILOGI(FEATURE_CHARGING, "turn off screen");
        backlight_->TurnOffScreen();
        AnimationLabel::needStop_ = true;
        backlightWait_ = -1;
    }

    return;
}

int ChargerThread::SetKeyState(int code, int value, int64_t now)
{
    BATTERY_HILOGD(FEATURE_CHARGING, "now=%{public}" PRId64 "", now);
    bool down;
    if (!!value) {
        down = true;
    } else {
        down = false;
    }

    if (code > KEY_MAX) {
        return -1;
    }

    if (g_keys[code].down == down) {
        return 0;
    }

    if (down) {
        g_keys[code].timestamp = now;
    }

    g_keys[code].down = down;
    g_keys[code].up = true;

    return 0;
}

void ChargerThread::HandlePowerKeyState()
{
    auto now = GetCurrentTime();
    BATTERY_HILOGD(FEATURE_CHARGING, "now=%{public}" PRId64 "", now);
    HandlePowerKey(KEY_POWER, now);

    BATTERY_HILOGD(FEATURE_CHARGING, "keyWait_=%{public}" PRId64 "", keyWait_);
    if (keyWait_ != -1 && now > keyWait_) {
        keyWait_ = -1;
    }

    return;
}

void ChargerThread::HandlePowerKey(int keycode, int64_t now)
{
    auto& powerMgrClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
    KeyState key = g_keys[keycode];
    if (keycode == KEY_POWER) {
        if (key.down) {
            BATTERY_HILOGD(FEATURE_CHARGING, "power key down");
            int64_t rebootTime = key.timestamp + REBOOT_TIME;
            if (now >= rebootTime) {
                BATTERY_HILOGD(FEATURE_CHARGING, "reboot machine");
                backlight_->TurnOffScreen();
                AnimationLabel::needStop_ = true;
                vibrate_->HandleVibrate(VIBRATE_TIME_MS);
                std::string reason = "Reboot";
                powerMgrClient.RebootDevice(reason);
            } else {
                SetKeyWait(key, REBOOT_TIME);
                backlight_->TurnOnScreen();
                AnimationLabel::needStop_ = true;
                UpdateAnimation(capacity_);
                backlightWait_ = now - 1;
                BATTERY_HILOGD(FEATURE_CHARGING, "turn on the screen");
            }
        } else {
            if (key.up) {
                BATTERY_HILOGD(FEATURE_CHARGING, "power key up");
                backlight_->TurnOnScreen();
                AnimationLabel::needStop_ = true;
                UpdateAnimation(capacity_);
                backlightWait_ = now - 1;
            }
        }
    }
    key.up = false;

    return;
}

void ChargerThread::HandleInputEvent(const struct input_event* iev)
{
    input_event ev {};
    ev.type = iev->type;
    ev.code = iev->code;
    ev.value = iev->value;
    BATTERY_HILOGD(FEATURE_CHARGING, "ev.type=%{public}d, ev.code=%{public}d, ev.value=%{public}d",
        ev.type, ev.code, ev.value);

    if (ev.type != EV_KEY) {
        return;
    }
    SetKeyState(ev.code, ev.value, GetCurrentTime());

    return;
}

void ChargerThread::EventPkgCallback(const EventPackage** pkgs, const uint32_t count, uint32_t devIndex)
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start key event callback");
    if (pkgs == nullptr || *pkgs == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "pkgs or *pkgs is nullptr");
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        struct input_event ev = {
            .type = static_cast<__u16>(pkgs[i]->type),
            .code = static_cast<__u16>(pkgs[i]->code),
            .value = pkgs[i]->value,
        };
        HandleInputEvent(&ev);
    }

    return;
}


int ChargerThread::InputInit()
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start init input");
    int ret = GetInputInterface(&g_inputInterface);
    if (ret != INPUT_SUCCESS) {
        BATTERY_HILOGW(FEATURE_CHARGING, "get input driver interface failed.");
        return ret;
    }

    ret = g_inputInterface->iInputManager->OpenInputDevice(1);
    if (ret) {
        BATTERY_HILOGD(FEATURE_CHARGING, "open device1 failed.");
        return ret;
    }

    uint32_t devType = 0;
    ret = g_inputInterface->iInputController->GetDeviceType(1, &devType);
    if (ret) {
        BATTERY_HILOGW(FEATURE_CHARGING, "get device1's type failed.");
        return ret;
    }

    g_callback.EventPkgCallback = EventPkgCallback;
    ret  = g_inputInterface->iInputReporter->RegisterReportCallback(1, &g_callback);
    if (ret) {
        BATTERY_HILOGW(FEATURE_CHARGING, "register callback failed for device 1.");
        return ret;
    }

    devType = INIT_DEFAULT_VALUE;
    ret = g_inputInterface->iInputController->GetDeviceType(1, &devType);

    BATTERY_HILOGD(FEATURE_CHARGING, "finish init input");
    return 0;
}

void ChargerThread::Init()
{
    BATTERY_HILOGD(FEATURE_CHARGING, "start init charger thread");
    batteryConfig_ = std::make_unique<BatteryConfig>();
    if (batteryConfig_ == nullptr) {
        BATTERY_HILOGE(FEATURE_CHARGING, "make_unique BatteryConfig return nullptr");
        return;
    }
    batteryConfig_->Init();

    provider_ = std::make_unique<PowerSupplyProvider>();
    if (provider_ == nullptr) {
        BATTERY_HILOGE(FEATURE_CHARGING, "make_unique PowerSupplyProvider return nullptr");
        return;
    }
    provider_->InitBatteryPath();
    provider_->InitPowerSupplySysfs();

    vibrate_ = std::make_unique<BatteryVibrate>();
    if (vibrate_ == nullptr) {
        BATTERY_HILOGE(FEATURE_CHARGING, "make_unique BatteryVibrate return nullptr");
        return;
    }

    if (vibrate_->VibrateInit() < 0) {
        BATTERY_HILOGE(FEATURE_CHARGING, "VibrateInit failed, vibration does not work");
    }

    backlight_ = std::make_unique<BatteryBacklight>();
    if (backlight_ == nullptr) {
        BATTERY_HILOGE(FEATURE_CHARGING, "make_unique BatteryBacklight return nullptr");
        return;
    }
    backlight_->InitBacklightSysfs();
    backlight_->TurnOnScreen();

    led_ = std::make_unique<BatteryLed>();
    if (led_ == nullptr) {
        BATTERY_HILOGE(FEATURE_CHARGING, "make_unique BatteryLed return nullptr");
        return;
    }
    led_->InitLedsSysfs();
    led_->TurnOffLed();

    AnimationInit();
    InputInit();
}

void ChargerThread::Run(void* service)
{
    BATTERY_HILOGI(FEATURE_CHARGING, "start run charger thread");
    Init();

    std::make_unique<std::thread>(&ChargerThread::LoopingThreadEntry, this, service)->join();
}
}  // namespace V1_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
