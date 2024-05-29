/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef WIFI_H
#define WIFI_H

#include "v1_0/ichip_controller.h"
#include "v1_0/iconcrete_chip.h"
#include "v1_0/chip_types.h"
#include "iface_tool.h"
#include "wifi_vendor_hal_list.h"
#include "wifi_chip_modes.h"
#include "callback_handler.h"
#include "wifi_chip.h"
#include "remote_death_recipient.h"
#include "iface_util.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
class Wifi : public IChipController {
public:
    Wifi();

    ~Wifi();

    bool IsValid();

    int32_t RegisterWifiEventCallback(const sptr<IChipControllerCallback>& eventCallback) override;

    int32_t IsInit(bool& inited) override;

    int32_t Init() override;

    int32_t Release() override;

    int32_t GetAvailableChips(std::vector<uint32_t>& chipIds) override;

    int32_t GetChipService(uint32_t chipId, sptr<IConcreteChip>& chip) override;

private:
    enum class RunState { STOPPED, STARTED, STOPPING };
    ErrorCode InitializVendorHal();
    ErrorCode StopVendorHal(std::unique_lock<std::recursive_mutex>* lock);
    uint32_t GetChipIdFromWifiChip(sptr <WifiChip>& chip);
    void OnRemoteDied(const wptr<IRemoteObject>& object);
    int32_t AddWifiDeathRecipient(const sptr<IChipControllerCallback>& eventCallback);
    int32_t RemoveWifiDeathRecipient(const sptr<IChipControllerCallback>& eventCallback);

    std::shared_ptr<IfaceTool> ifaceTool_;
    std::shared_ptr<WifiVendorHalList> vendorHalList_;
    std::vector<std::shared_ptr<WifiVendorHal>> vendorHals_;
    std::shared_ptr<WifiChipModes> chipModes_;
    RunState runState_;
    std::vector<sptr<WifiChip>> chips_;
    CallbackHandler<IChipControllerCallback> cbHandler_;
    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
};
}
}
}
}
}
#endif //WIFI_H_