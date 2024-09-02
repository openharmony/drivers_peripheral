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

#include "wifi_sta_iface.h"
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

WifiStaIface::WifiStaIface(
    const std::string& ifname,
    const std::weak_ptr<WifiVendorHal> vendorHal,
    const std::weak_ptr<IfaceUtil> ifaceUtil)
    : ifname_(ifname),
      vendorHal_(vendorHal),
      ifaceUtil_(ifaceUtil),
      isValid_(true)
{}

void WifiStaIface::Invalidate()
{
    vendorHal_.reset();
    isValid_ = false;
}

bool WifiStaIface::IsValid()
{
    return isValid_;
}

std::string WifiStaIface::GetName()
{
    return ifname_;
}

int32_t WifiStaIface::GetIfaceType(IfaceType& type)
{
    type = IfaceType::STA;
    return HDF_SUCCESS;
}

int32_t WifiStaIface::GetIfaceName(std::string& name)
{
    name = ifname_;
    return HDF_SUCCESS;
}

int32_t WifiStaIface::GetSupportFreqs(int band, std::vector<uint32_t>& frequencies)
{
    WifiError status;
    std::vector<uint32_t> validFrequencies;
    std::tie(status, validFrequencies) = vendorHal_.lock()->GetValidFrequenciesForBand(
        ifname_, band);
    frequencies = validFrequencies;
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::GetIfaceCap(uint32_t& capabilities)
{
    WifiError status = vendorHal_.lock()->GetSupportedFeatureSet(ifname_, capabilities);
    if (status != HAL_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WifiStaIface::SetMacAddress(const std::string& mac)
{
    bool status = ifaceUtil_.lock()->SetMacAddress(ifname_, mac);
    if (!status) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WifiStaIface::SetCountryCode(const std::string& code)
{
    WifiError status = vendorHal_.lock()->SetCountryCode(ifname_, code);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::GetPowerMode(int32_t& powerMode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiStaIface::SetPowerMode(int32_t powerMode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiStaIface::RegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    if (chipIfaceCallback == nullptr) {
        HDF_LOGE("chipIfaceCallback is null");
        return HDF_FAILURE;
    }
    HDF_LOGI("register sta callback");
    vendorHal_.lock()->RegisterIfaceCallBack(ifname_, chipIfaceCallback);
    return HDF_SUCCESS;
}

int32_t WifiStaIface::UnRegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    if (chipIfaceCallback == nullptr) {
        HDF_LOGE("chipIfaceCallback is null");
        return HDF_FAILURE;
    }
    HDF_LOGI("unregister sta callback");
    vendorHal_.lock()->UnRegisterIfaceCallBack(ifname_, chipIfaceCallback);
    return HDF_SUCCESS;
}

int32_t WifiStaIface::StartScan(const ScanParams& scanParam)
{
    HDF_LOGD("StartScan");
    WifiError status = vendorHal_.lock()->StartScan(ifname_, scanParam);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::GetScanInfos(std::vector<ScanResultsInfo>& scanResultsInfo)
{
    HDF_LOGD("GetScanInfos");
    WifiError status = vendorHal_.lock()->GetScanInfos(ifname_, scanResultsInfo);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::StartPnoScan(const PnoScanParams& pnoParams)
{
    HDF_LOGD("StartPnoScan");
    WifiError status = vendorHal_.lock()->StartPnoScan(ifname_, pnoParams);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::StopPnoScan()
{
    HDF_LOGD("StopPnoScan");
    WifiError status = vendorHal_.lock()->StopPnoScan(ifname_);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::GetSignalPollInfo(SignalPollResult& signalPollResult)
{
    WifiError status = vendorHal_.lock()->GetSignalPollInfo(ifname_, signalPollResult);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::EnablePowerMode(int32_t mode)
{
    HDF_LOGD("EnablePowerMode");
    if (ifaceUtil_.lock()->GetUpState(ifname_)) {
        HDF_LOGE("EnablePowerMode interface state is not OK.");
        return HDF_FAILURE;
    }
    WifiError status = vendorHal_.lock()->EnablePowerMode(ifname_, mode);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::SetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable)
{
    WifiError status = vendorHal_.lock()->SetDpiMarkRule(uid, protocol, enable);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::SetTxPower(int32_t power)
{
    WifiError status = vendorHal_.lock()->SetTxPower(ifname_, power);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::SetIfaceState(bool state)
{
    if (ifaceUtil_.lock()->SetUpState(ifname_, state)) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}
}
}
}
}
}