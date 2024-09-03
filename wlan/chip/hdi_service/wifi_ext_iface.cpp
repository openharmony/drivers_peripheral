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

#include "wifi_ext_iface.h"
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
WifiExtIface::WifiExtIface(
    const std::string& ifName,
    const std::weak_ptr<WifiVendorHal> vendorHal,
    const std::weak_ptr<IfaceUtil> ifaceUtil)
    : ifName_(ifName),
      vendorHal_(vendorHal),
      ifaceUtil_(ifaceUtil),
      isValid_(true) {}

void WifiExtIface::Invalidate()
{
    vendorHal_.reset();
    isValid_ = false;
}

bool WifiExtIface::IsValid()
{
    return isValid_;
}

std::string WifiExtIface::GetName()
{
    return ifName_;
}

int32_t WifiExtIface::GetIfaceType(IfaceType& type)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::GetIfaceName(std::string& name)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::GetSupportFreqs(int band, std::vector<uint32_t>& frequencies)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::GetIfaceCap(uint32_t& capabilities)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SetMacAddress(const std::string& mac)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SetCountryCode(const std::string& code)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::GetPowerMode(int32_t& powerMode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SetPowerMode(int32_t powerMode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::RegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::UnRegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::StartScan(const ScanParams& scanParam)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::GetScanInfos(std::vector<ScanResultsInfo>& scanResultsInfo)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::StartPnoScan(const PnoScanParams& pnoParams)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::StopPnoScan()
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::GetSignalPollInfo(SignalPollResult& signalPollResult)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::EnablePowerMode(int32_t mode)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SetTxPower(int32_t power)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SetIfaceState(bool state)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SendCmdToDriver(const std::string& ifName, int32_t cmdId, const std::vector<int8_t>& paramBuf)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::SendActionFrame(const std::string& ifName, uint32_t freq, const std::vector<uint8_t>& frameData)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::RegisterActionFrameReceiver(const std::string& ifName, const std::vector<uint8_t>& match)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t WifiExtIface::GetCoexictenceChannelList(const std::string& ifName, std::vector<uint8_t>& paramBuf)
{
    return HDF_ERR_NOT_SUPPORT;
}

}
}
}
}
}