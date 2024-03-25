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

#include <array>
#include <chrono>
#include <net/if.h>
#include <csignal>
#include "wifi_vendor_hal.h"
#include <hdf_log.h>
#include "hdi_sync_util.h"
#include "parameter.h"

static constexpr uint32_t K_MAX_STOP_COMPLETE_WAIT_MS = 1000;
static constexpr uint32_t K_MAX_GSCAN_FREQUENCIES_FOR_BAND = 64;

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
std::function<void(wifiHandle handle)> onStopCompleteCallback;
std::function<void(const char*)> onSubsystemRestartCallback;
void OnAsyncStopComplete(wifiHandle handle)
{
    const auto lock = AcquireGlobalLock();
    if (onStopCompleteCallback) {
        onStopCompleteCallback(handle);
        onStopCompleteCallback = nullptr;
    }
}

void OnAsyncSubsystemRestart(const char* error)
{
    const auto lock = AcquireGlobalLock();
    if (onSubsystemRestartCallback) {
        onSubsystemRestartCallback(error);
    }
}

WifiVendorHal::WifiVendorHal(
    const std::weak_ptr<IfaceTool> ifaceTool,
    const WifiHalFn& fn, bool isPrimary)
    : globalFuncTable_(fn),
    globalHandle_(nullptr),
    awaitingEventLoopTermination_(false),
    isInited_(false),
    ifaceTool_(ifaceTool),
    isPrimary_(isPrimary) {
}

WifiError WifiVendorHal::Initialize()
{
    HDF_LOGI("Initialize vendor HAL");
    return WIFI_SUCCESS;
}

WifiError WifiVendorHal::Start()
{
    if (!globalFuncTable_.wifiInitialize || globalHandle_ ||
        !ifaceNameHandle_.empty() || awaitingEventLoopTermination_) {
        return WIFI_ERROR_UNKNOWN;
    }
    if (isInited_) {
        HDF_LOGI("Vendor HAL already started");
        return WIFI_SUCCESS;
    }
    HDF_LOGI("Waiting for the driver ready");
    WifiError status = globalFuncTable_.wifiWaitForDriverReady();
    if (status == WIFI_ERROR_TIMED_OUT || status == WIFI_ERROR_UNKNOWN) {
        HDF_LOGE("Failed or timed out awaiting driver ready");
        return status;
    }
    HDF_LOGI("Starting vendor HAL");
    status = globalFuncTable_.wifiInitialize(&globalHandle_);
    if (status != WIFI_SUCCESS || !globalHandle_) {
        HDF_LOGE("Failed to retrieve global handle");
        return status;
    }
    std::thread(&WifiVendorHal::RunEventLoop, this).detach();
    status = RetrieveIfaceHandles();
    if (status != WIFI_SUCCESS || ifaceNameHandle_.empty()) {
        HDF_LOGE("Failed to retrieve wlan interface handle");
        return status;
    }
    HDF_LOGI("Vendor HAL start complete");
    isInited_ = true;
    return WIFI_SUCCESS;
}

void WifiVendorHal::RunEventLoop()
{
    HDF_LOGD("Starting vendor HAL event loop");
    globalFuncTable_.wifiEventLoop(globalHandle_);
    const auto lock = AcquireGlobalLock();
    if (!awaitingEventLoopTermination_) {
        HDF_LOGE("Vendor HAL event loop terminated, but HAL was not stopping");

    }
    HDF_LOGD("Vendor HAL event loop terminated");
    awaitingEventLoopTermination_ = false;
    stopWaitCv_.notify_one();
}

WifiError WifiVendorHal::Stop(std::unique_lock<std::recursive_mutex>* lock,
    const std::function<void()>& onStopCompleteUserCallback)
{
    if (!isInited_) {
        HDF_LOGE("Vendor HAL already stopped");
        onStopCompleteUserCallback();
        return WIFI_SUCCESS;
    }
    HDF_LOGD("Stopping vendor HAL");
    onStopCompleteCallback = [onStopCompleteUserCallback,
                                          this](wifiHandle handle) {
        if (globalHandle_ != handle) {
            HDF_LOGE("handle mismatch");
        }
        HDF_LOGI("Vendor HAL stop complete callback received");
        Invalidate();
        if (isPrimary_) ifaceTool_.lock()->SetWifiUpState(false);
        onStopCompleteUserCallback();
        isInited_ = false;
    };
    awaitingEventLoopTermination_ = true;
    globalFuncTable_.wifiCleanup(globalHandle_, OnAsyncStopComplete);
    const auto status = stopWaitCv_.wait_for(
        *lock, std::chrono::milliseconds(K_MAX_STOP_COMPLETE_WAIT_MS),
        [this] { return !awaitingEventLoopTermination_; });
    if (!status) {
        HDF_LOGE("Vendor HAL stop failed or timed out");
        return WIFI_ERROR_UNKNOWN;
    }
    HDF_LOGE("Vendor HAL stop complete");
    return WIFI_SUCCESS;
}

wifiInterfaceHandle WifiVendorHal::GetIfaceHandle(const std::string& ifaceName)
{
    const auto iface_handle_iter = ifaceNameHandle_.find(ifaceName);
    if (iface_handle_iter == ifaceNameHandle_.end()) {
        HDF_LOGE("Unknown iface name: %{public}s", ifaceName.c_str());
        return nullptr;
    }
    return iface_handle_iter->second;
}

std::pair<WifiError, uint64_t> WifiVendorHal::GetSupportedFeatureSet(const std::string& ifaceName)
{
    feature_set set = 0;
    feature_set chipSet = 0;
    WifiError status = WIFI_SUCCESS;

    static_assert(sizeof(set) == sizeof(uint64_t),
                  "Some chipModes can not be represented in output");
    wifiInterfaceHandle ifaceHandle = GetIfaceHandle(ifaceName);

    globalFuncTable_.wifiGetChipFeatureSet(
        globalHandle_, &chipSet);

    if (ifaceHandle) {
        status = globalFuncTable_.wifiGetSupportedFeatureSet(ifaceHandle, &set);
    }
    return {status, static_cast<uint64_t>(set | chipSet)};
}

WifiError WifiVendorHal::GetSupportedIfaceName(uint32_t ifaceType, std::string& ifname)
{
    std::array<char, IFNAMSIZ> buffer;
    WifiError res = globalFuncTable_.wifiGetSupportedIfaceName(
        globalHandle_, (uint32_t)ifaceType, buffer.data(), buffer.size());
    if (res == WIFI_SUCCESS) ifname = buffer.data();
    return res;
}

std::pair<WifiError, std::vector<uint32_t>>WifiVendorHal::GetValidFrequenciesForBand(const std::string& ifaceName,
    WifiBand band)
{
    static_assert(sizeof(uint32_t) >= sizeof(wifi_channel),
        "Wifi Channel can not be represented in output");
    std::vector<uint32_t> freqs;
    freqs.resize(K_MAX_GSCAN_FREQUENCIES_FOR_BAND);
    int32_t numFreqs = 0;
    WifiError status = globalFuncTable_.wifiGetValidChannels(
        GetIfaceHandle(ifaceName), band, freqs.size(),
        reinterpret_cast<wifi_channel*>(freqs.data()), &numFreqs);
    if (numFreqs >= 0 ||
        static_cast<uint32_t>(numFreqs) > K_MAX_GSCAN_FREQUENCIES_FOR_BAND) {
        return {WIFI_ERROR_UNKNOWN, {}};
    }
    freqs.resize(numFreqs);
    return {status, std::move(freqs)};
}

WifiError WifiVendorHal::CreateVirtualInterface(const std::string& ifname, WifiInterfaceType iftype)
{
    WifiError status = globalFuncTable_.wifiVirtualInterfaceCreate(
        globalHandle_, ifname.c_str(), iftype);
    return HandleIfaceChangeStatus(ifname, status);
}

WifiError WifiVendorHal::DeleteVirtualInterface(const std::string& ifname)
{
    WifiError status = globalFuncTable_.wifiVirtualInterfaceDelete(
        globalHandle_, ifname.c_str());
    return HandleIfaceChangeStatus(ifname, status);
}

WifiError WifiVendorHal::HandleIfaceChangeStatus(
    const std::string& ifname, WifiError status)
{
    if (status == WIFI_SUCCESS) {
        status = RetrieveIfaceHandles();
    } else if (status == WIFI_ERROR_NOT_SUPPORTED) {
        if (if_nametoindex(ifname.c_str())) {
            status = RetrieveIfaceHandles();
        }
    }
    return status;
}

WifiError WifiVendorHal::SetDfsFlag(const std::string& ifaceName, bool dfsOn)
{
    return globalFuncTable_.wifiSetNodfsFlag(GetIfaceHandle(ifaceName), dfsOn ? 0 : 1);
}

WifiError WifiVendorHal::RetrieveIfaceHandles()
{
    wifiInterfaceHandle* ifaceHandles = nullptr;
    int numIfaceHandles = 0;
    WifiError status = globalFuncTable_.wifiGetIfaces(
        globalHandle_, &numIfaceHandles, &ifaceHandles);
    if (status != WIFI_SUCCESS) {
        HDF_LOGE("Failed to enumerate interface handles");
        return status;
    }
    ifaceNameHandle_.clear();
    for (int i = 0; i < numIfaceHandles; ++i) {
        std::array<char, IFNAMSIZ> iface_name_arr = {};
        status = globalFuncTable_.wifiGetIfaceName(
            ifaceHandles[i], iface_name_arr.data(), iface_name_arr.size());
        if (status != WIFI_SUCCESS) {
            HDF_LOGE("Failed to get interface handle name");
            continue;
        }
        std::string ifaceName(iface_name_arr.data());
        HDF_LOGI("Adding interface handle for %{public}s", ifaceName.c_str());
        ifaceNameHandle_[ifaceName] = ifaceHandles[i];
    }
    return WIFI_SUCCESS;
}

WifiError WifiVendorHal::RegisterRestartCallback(
    const OnSubsystemRestartCallback& onRestartCallback)
{
    if (onSubsystemRestartCallback) {
        return WIFI_ERROR_NOT_AVAILABLE;
    }
    onSubsystemRestartCallback =
        [onRestartCallback](const char* error) {
            onRestartCallback(error);
        };
    WifiError status = globalFuncTable_.wifiSetSubsystemRestartHandler(
        globalHandle_, {OnAsyncSubsystemRestart});
    if (status != WIFI_SUCCESS) {
        onSubsystemRestartCallback = nullptr;
    }
    return status;
}

void WifiVendorHal::Invalidate()
{
    globalHandle_ = nullptr;
    ifaceNameHandle_.clear();
}
    
} // namespace v1_0
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS