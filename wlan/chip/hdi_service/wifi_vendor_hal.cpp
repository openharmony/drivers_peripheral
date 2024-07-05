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

#include <array>
#include <chrono>
#include <net/if.h>
#include <csignal>
#include "wifi_vendor_hal.h"
#include <hdf_log.h>
#include "hdi_sync_util.h"
#include "parameter.h"
#include "wifi_sta_iface.h"

static constexpr uint32_t K_MAX_STOP_COMPLETE_WAIT_MS = 1000;

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
std::function<void(wifiHandle handle)> onStopCompleteCallback;
std::function<void(const char*)> onVendorHalRestartCallback;
std::function<void(int)> onFullScanResultCallback;

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
    if (onVendorHalRestartCallback) {
        onVendorHalRestartCallback(error);
    }
}

CallbackHandler<IChipIfaceCallback> WifiVendorHal::vendorHalCbHandler_;
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
    return HAL_SUCCESS;
}

WifiError WifiVendorHal::Start()
{
    if (!globalFuncTable_.vendorHalInit || globalHandle_ ||
        !ifaceNameHandle_.empty() || awaitingEventLoopTermination_) {
        return HAL_UNKNOWN;
    }
    if (isInited_) {
        HDF_LOGI("Vendor HAL already started");
        return HAL_SUCCESS;
    }
    HDF_LOGI("Waiting for the driver ready");
    WifiError status = globalFuncTable_.waitDriverStart();
    if (status == HAL_TIMED_OUT || status == HAL_UNKNOWN) {
        HDF_LOGE("Failed or timed out awaiting driver ready");
        return status;
    }
    HDF_LOGI("Starting vendor HAL");
    status = globalFuncTable_.vendorHalInit(&globalHandle_);
    if (status != HAL_SUCCESS || !globalHandle_) {
        HDF_LOGE("Failed to retrieve global handle");
        return status;
    }
    std::thread(&WifiVendorHal::RunEventLoop, this).detach();
    status = RetrieveIfaceHandles();
    if (status != HAL_SUCCESS || ifaceNameHandle_.empty()) {
        HDF_LOGE("Failed to retrieve wlan interface handle");
        return status;
    }
    HDF_LOGI("Vendor HAL start complete");
    isInited_ = true;
    return HAL_SUCCESS;
}

void WifiVendorHal::RunEventLoop()
{
    HDF_LOGD("Starting vendor HAL event loop");
    globalFuncTable_.startHalLoop(globalHandle_);
    const auto lock = AcquireGlobalLock();
    if (!awaitingEventLoopTermination_) {
        HDF_LOGE("Vendor HAL event loop terminated, but HAL was not stopping");
    }
    HDF_LOGD("Vendor HAL event loop terminated");
    awaitingEventLoopTermination_ = false;
    stopWaitCv_.notify_one();
}

void WifiVendorHal::OnAsyncGscanFullResult(int event)
{
    const auto lock = AcquireGlobalLock();

    HDF_LOGD("OnAsyncGscanFullResult::OnScanResultsCallback");
    for (const auto& callback : vendorHalCbHandler_.GetCallbacks()) {
        if (callback) {
            callback->OnScanResultsCallback(event);
        }
    }
}

void WifiVendorHal::OnAsyncRssiReport(int32_t index, int32_t c0Rssi, int32_t c1Rssi)
{
    const auto lock = AcquireGlobalLock();

    HDF_LOGD("OnAsyncRssiReport::OnRssiReport");
    for (const auto& callback : vendorHalCbHandler_.GetCallbacks()) {
        if (callback) {
            callback->OnRssiReport(index, c0Rssi, c1Rssi);
        }
    }
}

WifiError WifiVendorHal::Stop(std::unique_lock<std::recursive_mutex>* lock,
    const std::function<void()>& onStopCompleteUserCallback)
{
    if (!isInited_) {
        HDF_LOGE("Vendor HAL already stopped");
        onStopCompleteUserCallback();
        return HAL_SUCCESS;
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
    globalFuncTable_.vendorHalExit(globalHandle_, OnAsyncStopComplete);
    const auto status = stopWaitCv_.wait_for(
        *lock, std::chrono::milliseconds(K_MAX_STOP_COMPLETE_WAIT_MS),
        [this] { return !awaitingEventLoopTermination_; });
    if (!status) {
        HDF_LOGE("Vendor HAL stop failed or timed out");
        return HAL_UNKNOWN;
    }
    HDF_LOGE("Vendor HAL stop complete");
    return HAL_SUCCESS;
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

WifiError WifiVendorHal::GetChipCaps(const std::string& ifaceName, uint32_t& capabilities)
{
    capabilities = globalFuncTable_.getChipCaps(ifaceName.c_str());
    if (capabilities == 0) {
        return HAL_UNKNOWN;
    }
    return HAL_SUCCESS;
}

WifiError WifiVendorHal::GetSupportedFeatureSet(const std::string& ifaceName, uint32_t& capabilities)
{
    capabilities = globalFuncTable_.wifiGetSupportedFeatureSet(ifaceName.c_str());
    if (capabilities == 0) {
        return HAL_UNKNOWN;
    }
    return HAL_SUCCESS;
}

std::pair<WifiError, std::vector<uint32_t>>WifiVendorHal::GetValidFrequenciesForBand(
    const std::string& ifaceName, int band)
{
    std::vector<uint32_t> freqs;

    WifiError status = globalFuncTable_.vendorHalGetChannelsInBand(
        GetIfaceHandle(ifaceName), band, freqs);
    return {status, std::move(freqs)};
}

WifiError WifiVendorHal::CreateVirtualInterface(const std::string& ifname, HalIfaceType iftype)
{
    WifiError status = globalFuncTable_.vendorHalCreateIface(
        globalHandle_, ifname.c_str(), iftype);
    status = HandleIfaceChangeStatus(ifname, status);
    if (status == HAL_SUCCESS && iftype == HalIfaceType::HAL_TYPE_STA) {
        ifaceTool_.lock()->SetUpState(ifname.c_str(), true);
    }
    return status;
}

WifiError WifiVendorHal::DeleteVirtualInterface(const std::string& ifname)
{
    WifiError status = globalFuncTable_.vendorHalDeleteIface(
        globalHandle_, ifname.c_str());
    return HandleIfaceChangeStatus(ifname, status);
}

WifiError WifiVendorHal::HandleIfaceChangeStatus(
    const std::string& ifname, WifiError status)
{
    if (status == HAL_SUCCESS) {
        status = RetrieveIfaceHandles();
    } else if (status == HAL_NOT_SUPPORTED) {
        if (if_nametoindex(ifname.c_str())) {
            status = RetrieveIfaceHandles();
        }
    }
    return status;
}

WifiError WifiVendorHal::RetrieveIfaceHandles()
{
    wifiInterfaceHandle* ifaceHandles = nullptr;
    int numIfaceHandles = 0;
    WifiError status = globalFuncTable_.vendorHalGetIfaces(
        globalHandle_, &numIfaceHandles, &ifaceHandles);
    if (status != HAL_SUCCESS) {
        HDF_LOGE("Failed to enumerate interface handles");
        return status;
    }
    ifaceNameHandle_.clear();
    for (int i = 0; i < numIfaceHandles; ++i) {
        std::array<char, IFNAMSIZ> iface_name_arr = {};
        status = globalFuncTable_.vendorHalGetIfName(
            ifaceHandles[i], iface_name_arr.data(), iface_name_arr.size());
        if (status != HAL_SUCCESS) {
            HDF_LOGE("Failed to get interface handle name");
            continue;
        }
        std::string ifaceName(iface_name_arr.data());
        HDF_LOGI("Adding interface handle for %{public}s", ifaceName.c_str());
        ifaceNameHandle_[ifaceName] = ifaceHandles[i];
    }
    return HAL_SUCCESS;
}

WifiError WifiVendorHal::RegisterRestartCallback(
    const OnVendorHalRestartCallback& onRestartCallback)
{
    if (onVendorHalRestartCallback) {
        return HAL_NOT_AVAILABLE;
    }
    onVendorHalRestartCallback =
        [onRestartCallback](const char* error) {
            onRestartCallback(error);
        };
    WifiError status = globalFuncTable_.vendorHalSetRestartHandler(
        globalHandle_, {OnAsyncSubsystemRestart});
    if (status != HAL_SUCCESS) {
        onVendorHalRestartCallback = nullptr;
    }
    return status;
}

void WifiVendorHal::Invalidate()
{
    globalHandle_ = nullptr;
    ifaceNameHandle_.clear();
    vendorHalCbHandler_.Invalidate();
}

WifiError WifiVendorHal::SetCountryCode(const std::string& ifaceName, const std::string& code)
{
    return globalFuncTable_.wifiSetCountryCode(GetIfaceHandle(ifaceName), code.c_str());
}

WifiError WifiVendorHal::GetSignalPollInfo(const std::string& ifaceName,
    SignalPollResult& signalPollResult)
{
    return globalFuncTable_.getSignalPollInfo(GetIfaceHandle(ifaceName), signalPollResult);
}

std::pair<WifiError, int> WifiVendorHal::GetPowerMode(const std::string& ifaceName)
{
    int mode;
    WifiError status = globalFuncTable_.getPowerMode(ifaceName.c_str(), &mode);
    return {status, mode};
}

WifiError WifiVendorHal::SetPowerMode(const std::string& ifaceName, int mode)
{
    return globalFuncTable_.setPowerMode(ifaceName.c_str(), mode);
}

WifiError WifiVendorHal::EnablePowerMode(const std::string& ifaceName, int mode)
{
    return globalFuncTable_.enablePowerMode(ifaceName.c_str(), mode);
}

WifiError WifiVendorHal::StartScan(
    const std::string& ifaceName, const ScanParams& params)
{
    WifiError status = globalFuncTable_.wifiStartScan(GetIfaceHandle(ifaceName), params);
    return status;
}

WifiError WifiVendorHal::StartPnoScan(const std::string& ifaceName, const PnoScanParams& pnoParams)
{
    WifiError status = globalFuncTable_.wifiStartPnoScan(GetIfaceHandle(ifaceName), pnoParams);
    return status;
}

WifiError WifiVendorHal::StopPnoScan(const std::string& ifaceName)
{
    WifiError status = globalFuncTable_.wifiStopPnoScan(GetIfaceHandle(ifaceName));
    return status;
}

WifiError WifiVendorHal::GetScanInfos(const std::string& ifaceName,
    std::vector<ScanResultsInfo>& scanResultsInfo)
{
    WifiError status = globalFuncTable_.getScanResults(GetIfaceHandle(ifaceName), scanResultsInfo);
    return status;
}

WifiError WifiVendorHal::SetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable)
{
    return globalFuncTable_.setDpiMarkRule(uid, protocol, enable);
}

WifiError WifiVendorHal::RegisterIfaceCallBack(const std::string& ifaceName,
    const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    vendorHalCbHandler_.AddCallback(chipIfaceCallback);
    WifiCallbackHandler handler = {OnAsyncGscanFullResult, OnAsyncRssiReport};
    globalFuncTable_.registerIfaceCallBack(ifaceName.c_str(), handler);
    return HAL_SUCCESS;
}

WifiError WifiVendorHal::UnRegisterIfaceCallBack(const std::string& ifaceName,
    const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    WifiCallbackHandler handler = {};
    globalFuncTable_.registerIfaceCallBack(ifaceName.c_str(), handler);
    vendorHalCbHandler_.Invalidate(); // instead of RemoveCallback temporarily
    return HAL_SUCCESS;
}

WifiError WifiVendorHal::SetTxPower(const std::string& ifaceName, int mode)
{
    return globalFuncTable_.setTxPower(ifaceName.c_str(), mode);
}

} // namespace v1_0
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS