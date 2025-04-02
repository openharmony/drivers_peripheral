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

#include "wifi_chip_modes.h"
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V2_0 {
#define STA IfaceType::STA
#define AP IfaceType::AP
#define P2P IfaceType::P2P
constexpr int STA_MAX_NUM = 3;

WifiChipModes::WifiChipModes(
    const std::weak_ptr<WifiVendorHal> vendorHal)
    : vendorHal_(vendorHal)
{}

UsableMode WifiChipModes::MakeComModes(int staNum, int apNum, int p2pNum, int modeId)
{
    std::vector<IfaceType> staTypes = {};
    std::vector<IfaceType> apTypes = {};
    std::vector<IfaceType> p2pTypes = {};
    std::vector<ComboIface> chipComb = {};
    IfaceLimit staChipIfaceComb;
    IfaceLimit apChipIfaceComb;
    IfaceLimit p2pChipIfaceComb;

    staTypes.push_back(STA);
    staChipIfaceComb.types = staTypes;
    staChipIfaceComb.ifaceNum = staNum;
    apTypes.push_back(AP);
    apChipIfaceComb.types = apTypes;
    apChipIfaceComb.ifaceNum = apNum;
    p2pTypes.push_back(P2P);
    p2pChipIfaceComb.types = p2pTypes;
    p2pChipIfaceComb.ifaceNum = p2pNum;
    ComboIface comb;
    if (staNum != 0)
        comb.limits.push_back(staChipIfaceComb);
    if (apNum != 0)
        comb.limits.push_back(apChipIfaceComb);
    if (p2pNum != 0)
        comb.limits.push_back(p2pChipIfaceComb);
    chipComb.push_back(comb);
    UsableMode chipmode = {};
    chipmode.modeId = modeId;
    chipmode.usableCombo = chipComb;
    return chipmode;
}

std::vector<UsableMode> WifiChipModes::GetChipModesForPrimary()
{
    std::vector<UsableMode> modes = {};
    UsableMode mode = MakeComModes(3, 0, 1, 0);
    modes.push_back(mode);
    UsableMode modeAp = MakeComModes(0, 1, 0, 1);
    modes.push_back(modeAp);
    return modes;
}

std::vector<UsableMode> WifiChipModes::GetChipModesForTriple()
{
    std::vector<UsableMode> modes = {};
    UsableMode mode = MakeComModes(STA_MAX_NUM, 1, 1, 0);
    modes.push_back(mode);
    return modes;
}

std::vector<UsableMode> WifiChipModes::GetChipModes(bool isPrimary)
{
    bool isCoex;
    vendorHal_.lock()->IsSupportCoex(isCoex);
    if (isCoex) {
        return GetChipModesForTriple();
    } else {
        return GetChipModesForPrimary();
    }
}
}
}
}
}
}