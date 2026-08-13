/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>

#include "off_find_log.h"
#include "h4_protocol.h"
#include "common_timer_errors.h"
#include "parameters.h"
#include "vendor_interface.h"
#include "thread_util.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace OffFind {
namespace V1_0 {

// disable off find cmd
#ifdef SEND_DISABLE_OFF_FIND_DLI
constexpr uint8_t DLI_DISABLE_OFFFIDN_CMD = 0x16;
constexpr uint8_t DLI_DISABLE_OFFFIDN_PARAM = 0x19;
#endif

// Opcode
constexpr uint16_t DLI_SWITCH_HOST = 0xFC92;
constexpr uint16_t DLI_SET_POWER_OFF_PARAM = 0xFC91;

// Power off parm
constexpr size_t DLI_PACKET_MIN_SIZE = 8;
constexpr size_t DLI_PACKET_HEADER_SIZE = 5;
constexpr size_t DLI_DATA_LEN_SIZE = 3;
constexpr size_t DLI_ADVTIME_SIZE = 4;
constexpr size_t ADV_FLAG_SIZE = 2; // ble and sle adv enable flag 1 on 0 off

// User and device Id len LIMIT
constexpr size_t DEVICE_ID_LEN = 64;
constexpr size_t USER_ID_LEN = 32;

// Advtising data len limit
constexpr size_t ADV_KEY_LEN = 32;
constexpr size_t ADV_CMAC_LEN = 2;

constexpr int OFFSET_EIGHT_BITS = 8;

// battery and correspond pwoerTime
constexpr int BATTERY_ENTRY = 3;
constexpr int BATTERY_HIGH_ENTRY = 10;  // 关机七天可找电池阈值

constexpr int HIGH_POWER_TIME = 168;  // 关机七天 7 day = 7*24h
constexpr int UP_POWER_TIME = 48;
constexpr int DOWN_POWER_TIME = 12;
constexpr int AIR_OTA_POWER_TIME = 168;  // 隔空升级 7 day = 7*24h
constexpr int AIR_OTA_DATE_LEN = 2;
constexpr size_t DEFAULT_ADV_DATA_LEN = 3;  // 关机3d下发广播数组长度
constexpr size_t SEVEN_DAYS_ADV_DATA_LEN = 8;  // 关机7d下发广播数组长度
// Data len dli position
constexpr int THIRD_BYTE = 3;
constexpr int FOURTH_BYTE = 4;
constexpr int FIFTH_BYTE = 5;
constexpr int SIXTH_BYTE = 6;
constexpr int OFFSET_STATUS = 3;

// Data len limit
constexpr size_t DATA_LEN_BYTE = 2;

constexpr int TIME_OUT_MAX = 3000;

// Timeot ms
constexpr int TIME_OUT_INIT_CHMOD = 500;

typedef struct InternalCommand {
    uint16_t cbsh;
    uint16_t cbofp;
    uint16_t opcode;
} InternalCommand;

InternalCommand g_internalCommand = {0, 0, 0};

constexpr size_t SLE_VENDOR_INVALID_DATA_LEN = 0;

VendorInterface::VendorInterface()
{
    timer_ = std::make_unique<OHOS::Utils::Timer>("NearlinkOffFindTimer");
    timer_->Setup();
    offFindTimerId_ = 0;
}

VendorInterface::~VendorInterface()
{
    if (timer_) {
        timer_->Shutdown();
    }
    CleanUp();
}

bool VendorInterface::SetSwitchHostTimer()
{
    if (timer_ == nullptr) {
        HDF_LOGE("timer_ is nulptr");
        return false;
    }
    auto func = []() {
        HDF_LOGI("SetSwitchHost TimeOut");
        VendorInterface::GetInstance()->OnInitCallback(OFF_FIND_FAIL);
    };
    uint32_t timeOut = TIME_OUT_MAX;
    if (LoadVendorCommonLibrary() == OFF_FIND_SUCCESS &&
        vendorCommInterface_->getRegisterTimerDuration != nullptr) {
        timeOut = vendorCommInterface_->getRegisterTimerDuration(chipType_);
    }
    uint32_t ret = timer_->Register(func, timeOut, true); // only support once timer now
    if (ret == OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
        HDF_LOGE("Register timer failed");
        return false;
    }
    offFindTimerId_ = ret;
    HDF_LOGI("offFindTimerId_ set: %{public}u", offFindTimerId_);
    return true;
}

void VendorInterface::DliPacketHearderGet(uint16_t paramLen)
{
    offFindDli_.push_back(DLI_PACKET_TYPE_SLE_CMD);
    offFindDli_.push_back(static_cast<uint8_t>(DLI_SET_POWER_OFF_PARAM));
    offFindDli_.push_back(static_cast<uint8_t>((DLI_SET_POWER_OFF_PARAM) >> OFFSET_EIGHT_BITS));

    // Total data len in header
    offFindDli_.push_back(static_cast<uint8_t>(paramLen - DLI_PACKET_HEADER_SIZE));
    offFindDli_.push_back(static_cast<uint8_t>((paramLen - DLI_PACKET_HEADER_SIZE) >> OFFSET_EIGHT_BITS));

    // Total data len in data head
    offFindDli_.push_back(static_cast<uint8_t>(paramLen - DLI_PACKET_HEADER_SIZE));
    offFindDli_.push_back(static_cast<uint8_t>((paramLen - DLI_PACKET_HEADER_SIZE) >> OFFSET_EIGHT_BITS));
}

#ifdef SEND_DISABLE_OFF_FIND_DLI
void VendorInterface::DisableDliPacketHearderGet()
{
    // disable offfind cmd
    offFindDli_.push_back(DLI_PACKET_TYPE_SLE_CMD);
    offFindDli_.push_back(DLI_DISABLE_OFFFIDN_CMD);
    offFindDli_.push_back(DLI_DISABLE_OFFFIDN_PARAM);
}
#endif

uint8_t VendorInterface::GetSleCapability(int power)
{
    uint8_t sleCapability = power <= BATTERY_ENTRY ? 0 : OF_SLE_ADV_ENABLE;
    if (OHOS::system::GetBoolParameter("const.nearlink.support.off_ring", false) && sleCapability != 0) {
        sleCapability = sleCapability | OF_SLE_RING_SUPPORT;
    }
    return sleCapability;
}

bool VendorInterface::PowerOffDliGet(
    const std::vector<OffFindParam>& data, const OffFindExtraInfo& info, size_t paramsCnt)
{
    HDF_LOGI("data[%{public}zu]udid[%{public}zu]uid[%{public}zu]", data.size(), info.udid.size(), info.uid.size());
    if (data.size() != paramsCnt || info.udid.size() > DEVICE_ID_LEN || info.uid.size() > USER_ID_LEN) {
        return false;
    }
    uint8_t sleCapability = GetSleCapability(info.battery);
    HDF_LOGI("power[%{public}d] sle[%{public}d]", info.battery, sleCapability);
    uint16_t paramLen = DLI_PACKET_HEADER_SIZE + ADV_FLAG_SIZE + DLI_DATA_LEN_SIZE + info.udid.size() + info.uid.size()
    + data.size() * DLI_DATA_LEN_SIZE;
    uint16_t dataLen = 0;
    offFindDli_.reserve(static_cast<int>(paramLen));
    DliPacketHearderGet(paramLen);
    offFindDli_.push_back(1); // ble adv flag (default on)
    offFindDli_.push_back(sleCapability); // sle capability
    offFindDli_.push_back(info.udid.size());
    offFindDli_.insert(offFindDli_.end(), info.udid.begin(), info.udid.end());
    offFindDli_.push_back(info.uid.size());
    offFindDli_.insert(offFindDli_.end(), info.uid.begin(), info.uid.end());
    offFindDli_.insert(offFindDli_.end(), data.size());
    for (size_t i = 0; i < data.size(); i++) {
        HDF_LOGI("advertising key or cmac len [%{public}zu][%{public}zu][%{public}zu]",
            data[i].publicKey.size(), data[i].cmac.size(), data[i].aesKey.size());
        if (data[i].publicKey.size() > ADV_KEY_LEN || data[i].cmac.size() > ADV_CMAC_LEN ||
            data[i].aesKey.size() > ADV_KEY_LEN) {
            return false;
        }
        offFindDli_.push_back(data[i].publicKey.size());
        offFindDli_.insert(offFindDli_.end(), data[i].publicKey.begin(), data[i].publicKey.end());
        offFindDli_.push_back(data[i].cmac.size());
        offFindDli_.insert(offFindDli_.end(), data[i].cmac.begin(), data[i].cmac.end());
        offFindDli_.push_back(data[i].aesKey.size());
        offFindDli_.insert(offFindDli_.end(), data[i].aesKey.begin(), data[i].aesKey.end());
        std::vector<uint8_t> advTime(DLI_ADVTIME_SIZE);
        for (size_t j = 0; j < DLI_ADVTIME_SIZE; j++) {
            advTime[DLI_ADVTIME_SIZE - j - 1] =
                (data[i].advTime >> ((DLI_ADVTIME_SIZE-1 - j) * OFFSET_EIGHT_BITS)) & 0xFF;
        }
        offFindDli_.insert(offFindDli_.end(), advTime.begin(), advTime.end());
        dataLen += data[i].publicKey.size() + data[i].cmac.size() + data[i].aesKey.size() + DLI_ADVTIME_SIZE;
    }
    offFindDli_[THIRD_BYTE] = static_cast<uint8_t>(paramLen + dataLen + DATA_LEN_BYTE - DLI_PACKET_HEADER_SIZE);
    offFindDli_[FOURTH_BYTE] = static_cast<uint8_t>(
        (paramLen + dataLen + DATA_LEN_BYTE - DLI_PACKET_HEADER_SIZE) >> OFFSET_EIGHT_BITS);
    offFindDli_[FIFTH_BYTE] = static_cast<uint8_t>(paramLen + dataLen - DLI_PACKET_HEADER_SIZE);
    offFindDli_[SIXTH_BYTE] = static_cast<uint8_t>(
        (paramLen + dataLen - DLI_PACKET_HEADER_SIZE) >> OFFSET_EIGHT_BITS);
    return true;
}

void VendorInterface::SwitchHostDliGet(std::vector<uint8_t>& data)
{
    data.push_back(DLI_PACKET_TYPE_SLE_CMD);
    data.push_back(static_cast<uint8_t>(DLI_SWITCH_HOST));
    data.push_back(static_cast<uint8_t>((DLI_SWITCH_HOST) >> OFFSET_EIGHT_BITS));
    data.push_back(0x00);
    data.push_back(0x00);
    g_internalCommand.cbsh = 1;
    g_internalCommand.opcode = DLI_SWITCH_HOST;
}

bool VendorInterface::WatchDliChannel()
{
    int channel[DLI_MAX_CHANNEL] = {0};
    int channelCount = vendorInterface_->op(OffFindOpcodeT::SLE_OP_DLI_CHANNEL_OPEN, static_cast<void *>(channel));
    if (channelCount < 1 || channelCount > DLI_MAX_CHANNEL) {
        HDF_LOGE("vendorInterface_->op SLE_OP_DLI_CHANNEL_OPEN failed ret:%{public}d.", channelCount);
        return false;
    }
    if (channelCount == 1) {
        auto h4 = std::make_shared<OffFind::H4Protocol>(channel[0],
            std::bind(&VendorInterface::OnEventReceived, this, std::placeholders::_1));
        watcher_.AddFdToWatcher(channel[0], std::bind(&OffFind::H4Protocol::ReadData, h4, std::placeholders::_1));
        dli_ = h4;
    } else {
        HDF_LOGE("invalid channel count:%d.", channelCount);
        return false;
    }
    return true;
}

void VendorInterface::SetReservedPower()
{
    if (isInitialized_.load()) {
        HDF_LOGE("already Initialized");
        return;
    }
    std::lock_guard<ffrt::recursive_mutex> lock(processMutex_);
    if (vendorHandle_ == nullptr || vendorInterface_ == nullptr) {
        vendorHandle_ = dlopen(GetFullVendorName(), RTLD_NOW);
        if (vendorHandle_ == nullptr) {
            HDF_LOGE("VendorInterface dlopen %{public}s failed, error code: %{public}s", offFindVendorName_.c_str(),
                dlerror());
            return;
        }
        vendorInterface_ =
            reinterpret_cast<OffFindVendorInterfaceT *>(dlsym(vendorHandle_, OFF_FIND_VENDOR_INTERFACE_SYMBOL_NAME));
        if (vendorInterface_ == nullptr) {
            HDF_LOGE("VendorInterface dlsym %{public}s failed.", OFF_FIND_VENDOR_INTERFACE_SYMBOL_NAME);
            return;
        }
    }

    // dev_offfind node init time sometimes later than findnetwork process init when startup
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_OUT_INIT_CHMOD));
    vendorInterface_->init();
    int powerSetFlag = SET_RESERVED_POWER;
    vendorInterface_->op(OffFindOpcodeT::SLE_OP_RESERVERD_POWER_SET, static_cast<void *>(&powerSetFlag));
    CleanUp();
}

bool VendorInterface::IsAirOta(const OffFindExtraInfo& info)
{
    bool isAirOta = std::all_of(info.uid.begin(), info.uid.end(), [](unsigned char c) {
        return c == 0xFF;
    });
    return !info.uid.empty() && isAirOta;
}

int VendorInterface::GetPowerTimeParameter(const OffFindExtraInfo& info, size_t paramsCnt)
{
    int power = info.battery <= BATTERY_ENTRY ?
        OHOS::system::GetIntParameter<int>("const.nearlink.off_find.low_battery_time", DOWN_POWER_TIME)
        : OHOS::system::GetIntParameter<int>("const.nearlink.off_find.high_battery_time", UP_POWER_TIME);

    if (paramsCnt == SEVEN_DAYS_ADV_DATA_LEN && info.battery > BATTERY_HIGH_ENTRY) {
        power = HIGH_POWER_TIME;
    }

    if (IsAirOta(info)) {
        power = AIR_OTA_POWER_TIME;
    }
    return power;
}

OffFindErrorCode VendorInterface::OpenAndSymDl()
{
    if (vendorHandle_ == nullptr || vendorInterface_ == nullptr) {
        vendorHandle_ = dlopen(GetFullVendorName(), RTLD_NOW);
        if (vendorHandle_ == nullptr) {
            HDF_LOGE("dlopen %{public}s failed, error code: %{public}s", offFindVendorName_.c_str(), dlerror());
            return OFF_FIND_SYNC_FAIL;
        }
        vendorInterface_ =
            reinterpret_cast<OffFindVendorInterfaceT *>(dlsym(vendorHandle_, OFF_FIND_VENDOR_INTERFACE_SYMBOL_NAME));
        if (vendorInterface_ == nullptr) {
            HDF_LOGE("VendorInterface dlsym %{public}s failed.", OFF_FIND_VENDOR_INTERFACE_SYMBOL_NAME);
            return OFF_FIND_SYNC_FAIL;
        }
    }
    return OFF_FIND_SUCCESS;
}

OffFindErrorCode VendorInterface::LoadVendorCommonLibrary()
{
    if (vendorCommHandle_ != nullptr && vendorCommInterface_ != nullptr) {
        return OFF_FIND_SUCCESS;
    }
    vendorCommHandle_ = dlopen(OFF_FIND_VENDOR_COMMON_NAME, RTLD_NOW);
    if (vendorCommHandle_ == nullptr) {
        HDF_LOGE("dlopen %{public}s failed, errCode: %{public}s", OFF_FIND_VENDOR_COMMON_NAME, dlerror());
        return OFF_FIND_SYNC_FAIL;
    }
    vendorCommInterface_ = reinterpret_cast<OffFindVendorCommInterfaceT *>(dlsym(vendorCommHandle_,
        OFF_FIND_VENDOR_COMMON_INTERFACE_SYMBOL_NAME));
    if (vendorCommInterface_ == nullptr) {
        HDF_LOGE("dlsym failed %{public}s, err: %{public}s", OFF_FIND_VENDOR_COMMON_INTERFACE_SYMBOL_NAME, dlerror());
        dlclose(vendorCommHandle_);
        return OFF_FIND_SYNC_FAIL;
    }
    HDF_LOGI("LoadVendorCommonLibrary success %{public}s", OFF_FIND_VENDOR_COMMON_NAME);
    return OFF_FIND_SUCCESS;
}

OffFindErrorCode VendorInterface::EnableOffFindMode(InitializeCompleteCallback initializeCompleteCallback,
    const std::vector<OffFindParam>& data, const OffFindExtraInfo& info)
{
    std::lock_guard<ffrt::recursive_mutex> lock(processMutex_);
    size_t paramsCnt =
        OHOS::system::GetUintParameter<size_t>("const.findnetwork.shutdown_params.count", DEFAULT_ADV_DATA_LEN);
    HDF_LOGI("EnableOffFindMode Begin, %{public}zu params", paramsCnt);
    if (IsAirOta(info)) {
        paramsCnt = AIR_OTA_DATE_LEN;
    }
    if (!PowerOffDliGet(data, info, paramsCnt)) {
        HDF_LOGE("PowerOffDliGet ERROR");
        return OFF_FIND_SYNC_FAIL;
    }
    initializeCompleteCallback_ = initializeCompleteCallback;
    if (OpenAndSymDl() != OFF_FIND_SUCCESS || LoadVendorCommonLibrary() != OFF_FIND_SUCCESS) {
        return OFF_FIND_SYNC_FAIL;
    }
    vendorInterface_->init();
    int powerSetFlag = SET_RESERVED_POWER;
    vendorInterface_->op(OffFindOpcodeT::SLE_OP_RESERVERD_POWER_SET, static_cast<void *>(&powerSetFlag));
    if (!WatchDliChannel()) {
        HDF_LOGE("WatchDliChannel Init Fail");
        return OFF_FIND_SYNC_FAIL;
    }
    if (vendorCommInterface_->isNeedWatcherStart != nullptr &&
        vendorCommInterface_->isNeedWatcherStart(chipType_) && !watcher_.Start()) {
        HDF_LOGE("watcher start failed.");
        return OFF_FIND_SYNC_FAIL;
    }
    int powerTime = GetPowerTimeParameter(info, paramsCnt);
    HDF_LOGI("battery[%{public}d] and powerTime[%{public}d]", info.battery, powerTime);

    if (vendorCommInterface_->modifyPowerProtect != nullptr &&
        vendorCommInterface_->modifyPowerProtect(powerTime, info.battery) != OFF_FIND_SUCCESS) {
        HDF_LOGE("modifyPowerProtect failed");
        return OFF_FIND_SYNC_FAIL;
    }

    if (!SetSwitchHostTimer()) {
        HDF_LOGE("OffFind Mode SetTimer failed");
        return OFF_FIND_SYNC_FAIL;
    }
    int ret = vendorInterface_->op(OffFindOpcodeT::SLE_OP_OFF_FIND_MODE_ENABLE, static_cast<void *>(&powerTime));
    if (ret < 0) {
        HDF_LOGE("OffFind Mode Enable failed");
        return OFF_FIND_FAIL;
    }
    g_internalCommand.cbofp = 1;
    dliCompleteFlag_ = false;
    dli_->SendPacket(offFindDli_);
    offFindDli_.clear();
    return OFF_FIND_SUCCESS;
}

void VendorInterface::RegisterClearOffFindCallback(ClearIpcCallback clearIpcCallback)
{
    clearIpcCallback_ = clearIpcCallback;
}

bool VendorInterface::Initialize(InitializeCompleteCallback initializeCompleteCallback,
    const std::vector<OffFindParam>& data, const OffFindExtraInfo& info)
{
    if (isInitialized_.load()) {
        HDF_LOGE("already Initialized");
        return false;
    }
    isInitialized_.store(true);
    OffFindErrorCode ret = OFF_FIND_SUCCESS;
    ret = EnableOffFindMode(initializeCompleteCallback, data, info);
    if (ret == OFF_FIND_SUCCESS) {
        return true;
    }
    OnInitCallback(ret);
    return false;
}

const char* VendorInterface::GetFullVendorName()
{
    if (offFindVendorName_ != "") {
        return offFindVendorName_.c_str();
    }
    offFindVendorName_ = OFF_FIND_VENDOR_NAME;
    std::string sleChipType = OHOS::system::GetParameter(SLE_OFF_FIND_CHIP_TYPE, "");
    HDF_LOGI("sleChipType is %{public}s", sleChipType.c_str());
    if (!sleChipType.empty()) {
        offFindVendorName_.append("_");
        offFindVendorName_.append(sleChipType.c_str());
        chipType_.append(sleChipType);
    }
    offFindVendorName_.append(".z.so");
    HDF_LOGI("vendor name is %{public}s", offFindVendorName_.c_str());
    return offFindVendorName_.c_str();
}

void VendorInterface::DisableOffFindMode()
{
    std::lock_guard<ffrt::recursive_mutex> lock(processMutex_);
    if (vendorHandle_ == nullptr || vendorInterface_ == nullptr) {
        vendorHandle_ = dlopen(GetFullVendorName(), RTLD_NOW);
        if (vendorHandle_ == nullptr) {
            HDF_LOGE("VendorInterface dlopen %{public}s failed, error code: %{public}s", offFindVendorName_.c_str(),
                dlerror());
            return;
        }
        vendorInterface_ =
            reinterpret_cast<OffFindVendorInterfaceT *>(dlsym(vendorHandle_, OFF_FIND_VENDOR_INTERFACE_SYMBOL_NAME));
        if (vendorInterface_ == nullptr) {
            HDF_LOGE("VendorInterface dlsym %{public}s failed.", OFF_FIND_VENDOR_INTERFACE_SYMBOL_NAME);
            return;
        }
    }
    vendorInterface_->init();
#ifdef SEND_DISABLE_OFF_FIND_DLI
    if (!WatchDliChannel()) {
        HDF_LOGE("WatchDliChannel Init Fail");
    }
    DisableDliPacketHearderGet();
    if (dli_ != nullptr) {
        dli_->SendPacket(offFindDli_);
    }
    offFindDli_.clear();
    vendorInterface_->op(OffFindOpcodeT::SLE_OP_DLI_CHANNEL_CLOSE, nullptr);
#endif
    int powerSetFlag = CLEAR_RESERVED_POWER;
    vendorInterface_->op(OffFindOpcodeT::SLE_OP_RESERVERD_POWER_SET, static_cast<void *>(&powerSetFlag));
    isInitialized_.store(false);
    vendorInterface_->op(OffFindOpcodeT::SLE_OP_OFF_FIND_MODE_DISABLE, nullptr);
    vendorInterface_->close();
    CleanUp();
}

void VendorInterface::CleanUp()
{
    std::lock_guard<ffrt::recursive_mutex> lock(processMutex_);
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("VendorInterface::CleanUp, vendorInterface_ is nullptr.");
        return;
    }
    HDF_LOGI("off find clean up");
    watcher_.Stop();
    dli_ = nullptr;
    vendorInterface_ = nullptr;
    initializeCompleteCallback_ = nullptr;
    eventDataCallback_ = nullptr;
    dlclose(vendorHandle_);
    vendorCommInterface_ = nullptr;
    dlclose(vendorCommHandle_);
}

size_t VendorInterface::SendPacket(const std::vector<uint8_t> &packet)
{
    if (vendorInterface_ == nullptr || dli_ == nullptr) {
        HDF_LOGE("VendorInterface::SendPacket, vendorInterface_ is nullptr.");
        return SLE_VENDOR_INVALID_DATA_LEN;
    }

    watcher_.SetTimeout(std::chrono::milliseconds(lpmTimer_), std::bind(&VendorInterface::WatcherTimeout, this));

    return dli_->SendPacket(packet);
}

void VendorInterface::OnInitCallback(OffFindErrorCode result)
{
    HDF_LOGI("OnInitCallback %{public}d", result);
    OffFindSwitchResult status = OffFindSwitchResult::INITIALIZATION_ERROR;
    if (result != OFF_FIND_SYNC_FAIL) {
        if (offFindTimerId_ == 0) {
            HDF_LOGE("offFindTimerId_ is 0, no registered timer");
        } else {
            HDF_LOGI("OnInitCallback offFindTimerId_: %{public}d", offFindTimerId_);
            if (timer_ == nullptr) {
                HDF_LOGE("timer_ is nulptr");
            } else {
                timer_->Unregister(offFindTimerId_);
            }
        }
        if (result == OFF_FIND_SUCCESS) {
            status = OffFindSwitchResult::SUCCESS;
        } else {
            vendorInterface_->op(OffFindOpcodeT::SLE_OP_OFF_FIND_MODE_DISABLE, nullptr);
        }
    }
    isInitialized_.store(false);
    if (initializeCompleteCallback_) {
        initializeCompleteCallback_(status);
        initializeCompleteCallback_ = nullptr;
        if (clearIpcCallback_) {
            clearIpcCallback_();
        }
    }
    CleanUp();
}

bool VendorInterface::EventReceivedHandler(const std::vector<uint8_t> &data)
{
    if (data.size() < DLI_PACKET_MIN_SIZE) {
        HDF_LOGE("packet len err , [%{public}zu]", data.size());
        return false;
    }
    uint16_t eventOpcode = data[0] | (data[1] << OFFSET_EIGHT_BITS);
    // 如果 eventOpcode 不是 SLE_DLI_COMMAND_COMPLETE_EVENT，可能是残留数据不做任何处理，直接返回 true，后续正常的COMPLETE_EVENT会继续返回
    if (eventOpcode != SLE_DLI_COMMAND_COMPLETE_EVENT) {
        HDF_LOGW("eventOpcode[%{public}04X] is not complete event", eventOpcode);
        return true;
    }
    size_t opcodeOffset = dli_->GetPacketHeaderInfo(DLI_PACKET_TYPE_SLE_EVENT).headerSize;
    uint16_t opcode = data[opcodeOffset] + (data[opcodeOffset + 1] << OFFSET_EIGHT_BITS);
    HDF_LOGI("opcode[%{public}04X], cbofp[%{public}d], cbsh[%{public}d], status[%{public}d]",
        opcode, g_internalCommand.cbofp, g_internalCommand.cbsh, data[opcodeOffset + OFFSET_STATUS]);
    if (g_internalCommand.cbofp != 0 && opcode == DLI_SET_POWER_OFF_PARAM) {
        if (data[opcodeOffset + OFFSET_STATUS] != 0) {
            HDF_LOGE("set param event status[%{public}d] error", data[opcodeOffset + OFFSET_STATUS]);
            return false;
        }
        g_internalCommand.cbofp = 0;
        g_internalCommand.cbsh = 1;
        g_internalCommand.opcode = DLI_SWITCH_HOST;
        std::vector<uint8_t> switchHostDli;
        switchHostDli.reserve(DLI_PACKET_HEADER_SIZE);
        SwitchHostDliGet(switchHostDli);
        dli_->SendPacket(switchHostDli);
        return true;
    } else if (g_internalCommand.cbsh != 0 && opcode == DLI_SWITCH_HOST) {
        if (data[opcodeOffset + OFFSET_STATUS] != 0) {
            HDF_LOGE("switch host status[%{public}d] error", data[opcodeOffset + OFFSET_STATUS]);
            return false;
        }
        int ret = vendorInterface_->op(OffFindOpcodeT::SLE_OP_OFF_FIND_POWER_PROTECT_ENABLE, nullptr);
        if (ret < 0) {
            HDF_LOGE("OffFind power cfg config failed");
            return false;
        }
        dliCompleteFlag_ = true;
        g_internalCommand.cbsh = 0;
        return true;
    } else {
        HDF_LOGE("unknown dli");
        return false;
    }
}

void VendorInterface::OnEventReceived(const std::vector<uint8_t> &data)
{
    Nearlink::DoInDliThread([this, acbData = data]() {
        this->OnEventReceivedTask(acbData);
    });
    return;
}

void VendorInterface::OnEventReceivedTask(const std::vector<uint8_t> &data)
{
    HDF_LOGI("OnEventReceivedTask");
    bool ret = EventReceivedHandler(data);
    if (ret && dliCompleteFlag_) {
        OnInitCallback(OFF_FIND_SUCCESS);
    } else if (!ret) {
        OnInitCallback(OFF_FIND_FAIL);
    } else {
        return ;
    }
}

void VendorInterface::WatcherTimeout()
{
    HDF_LOGI("fd wait out of time, no data ready");
}
}  // namespace V1_0
}  // namespace OffFind
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS