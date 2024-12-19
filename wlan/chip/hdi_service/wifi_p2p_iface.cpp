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

#include "wifi_p2p_iface.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
WifiP2pIface::WifiP2pIface(
    const std::string& ifname, const std::weak_ptr<WifiVendorHal> vendorHal,
    const std::weak_ptr<IfaceUtil> ifaceUtil)
    : ifname_(ifname),
      vendorHal_(vendorHal),
      ifaceUtil_(ifaceUtil),
      isValid_(true) {}

void WifiP2pIface::Invalidate()
{
    vendorHal_.reset();
    isValid_ = false;
}

bool WifiP2pIface::IsValid()
{
    return isValid_;
}

std::string WifiP2pIface::GetName()
{
    return ifname_;
}

int32_t WifiP2pIface::GetIfaceType(IfaceType& type)
{
    type = IfaceType::P2P;
    return HDF_SUCCESS;
}

int32_t WifiP2pIface::GetIfaceName(std::string& name)
{
    name = ifname_;
    return HDF_SUCCESS;
}

int32_t WifiP2pIface::GetSupportFreqs(int band, std::vector<uint32_t>& frequencies)
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

int32_t WifiP2pIface::GetIfaceCap(uint32_t& capabilities)
{
    return HDF_SUCCESS;
}

int32_t WifiP2pIface::SetMacAddress(const std::string& mac)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::SetCountryCode(const std::string& code)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::GetPowerMode(int32_t& powerMode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::SetPowerMode(int32_t powerMode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::RegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::UnRegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::StartScan(const ScanParams& scanParam)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::GetScanInfos(std::vector<ScanResultsInfo>& scanResultsInfo)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::StartPnoScan(const PnoScanParams& pnoParams)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::StopPnoScan()
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::GetSignalPollInfo(SignalPollResult& signalPollResult)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::EnablePowerMode(int32_t mode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::SetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::SetTxPower(int32_t power)
{
{
    WifiError status = vendorHal_.lock()->SetTxPower(ifname_, power);
    return status;
}
}

int32_t WifiP2pIface::SetIfaceState(bool state)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::SendCmdToDriver(const std::string& ifName, int32_t cmdId, const std::vector<int8_t>& paramBuf)
{
    WifiError status = vendorHal_.lock()->SendCmdToDriver(ifName, cmdId, paramBuf);
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiP2pIface::SendActionFrame(const std::string& ifName, uint32_t freq, const std::vector<uint8_t>& frameData)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::RegisterActionFrameReceiver(const std::string& ifName, const std::vector<uint8_t>& match)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiP2pIface::GetCoexictenceChannelList(const std::string& ifName, std::vector<uint8_t>& paramBuf)
{
    return HDF_ERR_NOT_SUPPORT;
}

}
}
}
}
}