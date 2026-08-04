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

#ifndef OHOS_HDI_NEARLINK_OFF_FIND_V1_0_VENDOR_INTERFACE_H
#define OHOS_HDI_NEARLINK_OFF_FIND_V1_0_VENDOR_INTERFACE_H

#include <functional>
#include <vector>
#include "timer.h"
#include "singleton.h"
#include "off_find_hdi_constant.h"
#include "dli_internal.h"
#include "dli_protocol.h"
#include "dli_watcher.h"
#include "ffrt_inner.h"
#include "v1_0/off_find_types.h"
#include "ohos_off_find_vendor_lib.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace OffFind {
namespace V1_0 {
class VendorInterface : public DelayedSingleton<VendorInterface> {
public:
    using InitializeCompleteCallback = std::function<void(int32_t result)>;
    using ClearIpcCallback = std::function<void()>;
    using ReceiveDataCallback = DliProtocol::DliDataCallback;
    void SetReservedPower();
    void RegisterClearOffFindCallback(ClearIpcCallback clearIpcCallback
    );
    bool Initialize(InitializeCompleteCallback initializeCompleteCallback, const std::vector<OffFindParam>& data,
    const OffFindExtraInfo& info);
    void DisableOffFindMode();
    void CleanUp();
    size_t SendPacket(const std::vector<uint8_t> &packet);
    void SetSleAddress(uint8_t *localSleAddr);
    uint8_t *SetAddress(uint8_t *addr);
private:
    OffFindErrorCode EnableOffFindMode(InitializeCompleteCallback initializeCompleteCallback,
        const std::vector<OffFindParam>& data, const OffFindExtraInfo& info);
    OffFindErrorCode OpenAndSymDl();
    OffFindErrorCode LoadVendorCommonLibrary();
    bool EventReceivedHandler(const std::vector<uint8_t> &data);
    void OnInitCallback(OffFindErrorCode result);
    void OnEventReceived(const std::vector<uint8_t> &data);
    void OnEventReceivedTask(const std::vector<uint8_t> &data);
    bool WatchDliChannel();
    bool IsAirOta(const OffFindExtraInfo& info);
    void WatcherTimeout();    
    InitializeCompleteCallback initializeCompleteCallback_;
    ClearIpcCallback clearIpcCallback_;
    ReceiveDataCallback eventDataCallback_;
    void* vendorHandle_ = nullptr;
    OffFindVendorInterfaceT *vendorInterface_ = nullptr;
    void* vendorCommHandle_ = nullptr;
    OffFindVendorCommInterfaceT *vendorCommInterface_ = nullptr;
    DliWatcher watcher_;
    std::shared_ptr<DliProtocol> dli_ = nullptr;
    std::vector<uint8_t> offFindDli_;
    uint16_t vendorSentOpcode_ = 0;
    uint32_t lpmTimer_ = 0;
    std::unique_ptr<OHOS::Utils::Timer> timer_ {nullptr};
    uint32_t offFindTimerId_;
    std::string offFindVendorName_ = "";
    std::string chipType_ = "";
    bool dliCompleteFlag_ = false;
    void DliPacketHearderGet(uint16_t paramLen);
#ifdef SEND_DISABLE_OFF_FIND_DLI
    void DisableDliPacketHearderGet();
#endif
    bool SetSwitchHostTimer();
    uint8_t GetSleCapability(int power);
    bool PowerOffDliGet(const std::vector<OffFindParam>& data, const OffFindExtraInfo& info, size_t paramsCnt);
    void SwitchHostDliGet(std::vector<uint8_t>& data);
    int GetPowerTimeParameter(const OffFindExtraInfo& info, size_t paramsCnt);
    DECLARE_DELAYED_SINGLETON(VendorInterface);
    DISALLOW_COPY_AND_MOVE(VendorInterface);
    ffrt::recursive_mutex processMutex_;
    const char* GetFullVendorName();
    std::atomic_bool isInitialized_ = false;
};
}  // namespace V1_0
}  // namespace OffFind
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS
#endif /* OHOS_HDI_NEARLINK_OFF_FIND_V1_0_VENDOR_INTERFACE_H */