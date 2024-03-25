/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved
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

#include "v1_0/iwifi.h"
#include "v1_0/iwifi_chip.h"
#include "v1_0/wlan_types_common.h"
#include "interface_tool.h"
#include "wifi_vendor_hal_list.h"
#include "wifi_chip_modes.h"
#include "callback_handler.h"
#include "wifi_chip.h"
#include "remote_death_recipient.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
class Wifi : public IWifi {
public:
    Wifi();

    ~Wifi();

    bool IsValid();

    int32_t RegisterWifiEventCallback(const sptr<IWifiEventCallback>& eventCallback) override;

    int32_t IsInit(bool& inited) override;

    int32_t Init() override;

    int32_t Release() override;

    int32_t GetAvailableChips(std::vector<uint32_t>& chipIds) override;

    int32_t GetChipService(uint32_t chipId, sptr<IWifiChip>& chip) override;

private:
    enum class RunState { STOPPED, STARTED, STOPPING };
    WifiStatus InitializVendorHal();
    WifiStatus StopVendorHal(std::unique_lock<std::recursive_mutex>* lock);
    int32_t GetChipIdFromWifiChip(sptr <WifiChip>& chip);
    void OnRemoteDied(const wptr<IRemoteObject>& object);
    int32_t AddWifiDeathRecipient(const sptr<IWifiEventCallback>& eventCallback);
    int32_t RemoveWifiDeathRecipient(const sptr<IWifiEventCallback>& eventCallback);

    std::shared_ptr<IfaceTool> ifaceTool_;
    std::shared_ptr<WifiVendorHalList> vendorHalList_;
    std::vector<std::shared_ptr<WifiVendorHal>> vendorHals_;
    std::shared_ptr<WifiChipModes> chipModes_;
    RunState runState_;
    std::vector<sptr<WifiChip>> chips_;
    CallbackHandler<IWifiEventCallback> cbHandler_;
    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
};
}
}
}
}
}
#endif //WIFI_H_