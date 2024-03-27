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

#ifndef WIFI_LEGACY_HAL_H
#define WIFI_LEGACY_HAL_H

#include <condition_variable>
#include <functional>
#include <map>
#include <thread>
#include <vector>

#include "wifi_hal.h"
#include "interface_tool.h"
#include "hdi_sync_util.h"
#include "v1_0/chip_types.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

using OnSubsystemRestartCallback = std::function<void(const std::string&)>;
class WifiVendorHal {
public:
    WifiVendorHal(const std::weak_ptr<IfaceTool> ifaceTool,
        const WifiHalFn& fn, bool isPrimary);
    virtual ~WifiVendorHal() = default;

    virtual WifiError Initialize();

    WifiError Start();

    virtual WifiError Stop(std::unique_lock<std::recursive_mutex>* lock,
        const std::function<void()>& on_complete_callback);

    WifiError GetSupportedIfaceName(uint32_t ifaceType, std::string& ifname);

    WifiError CreateVirtualInterface(const std::string& ifname, WifiInterfaceType iftype);

    WifiError DeleteVirtualInterface(const std::string& ifname);

    std::pair<WifiError, std::vector<uint32_t>> GetValidFrequenciesForBand(
        const std::string& ifaceName, BandType band);

    WifiError SetDfsFlag(const std::string& ifaceName, bool dfsOn);

    WifiError RegisterRestartCallback(
        const OnSubsystemRestartCallback& onRestartCallback);

private:
    WifiError RetrieveIfaceHandles();
    wifiInterfaceHandle GetIfaceHandle(const std::string& ifaceName);
    void RunEventLoop();
    void Invalidate();
    WifiError HandleIfaceChangeStatus(const std::string& ifname, WifiError status);
    WifiHalFn globalFuncTable_;
    wifiHandle globalHandle_;
    std::map<std::string, wifiInterfaceHandle> ifaceNameHandle_;
    std::atomic<bool> awaitingEventLoopTermination_;
    std::condition_variable_any stopWaitCv_;
    bool isInited_;
    std::weak_ptr<IfaceTool> ifaceTool_;
    bool isPrimary_;
};
    
} // namespace v1_0
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS

#endif
