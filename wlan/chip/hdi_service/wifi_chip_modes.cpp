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
#include "parameter.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
#define STA IfaceType::STA
#define AP IfaceType::AP
#define P2P IfaceType::P2P

constexpr int PROP_BOOL_VALUE_LEN = 6;

WifiChipModes::WifiChipModes() {}

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
    char propValue[PROP_MAX_LEN] = {0};
    int errCode = GetParameter(SAPCOEXIST_PROP, 0, propValue, PROP_BOOL_VALUE_LEN);
    if (errCode > 0) {
        if (strncmp(propValue, "true", strlen("true")) == 0) {
            HDF_LOGI("select sap and sta coexist");
            UsableMode mode = MakeComModes(3, 1, 1, 0);
            modes.push_back(mode);
            return modes;
        }
    }
    UsableMode mode = MakeComModes(3, 0, 1, 0);
    modes.push_back(mode);
    UsableMode modeAp = MakeComModes(0, 1, 0, 1);
    modes.push_back(modeAp);
    return modes;
}

std::vector<UsableMode> WifiChipModes::GetChipModesForTriple()
{
    std::vector<UsableMode> modes = {};
    UsableMode mode = MakeComModes(1, 1, 1, 0);
    modes.push_back(mode);
    return modes;
}

std::vector<UsableMode> WifiChipModes::GetChipModes(bool isPrimary)
{
    char propValue[PROP_MAX_LEN] = {0};
    int errCode = GetParameter(SUBCHIP_PROP, 0, propValue, PROP_SUBCHIPTYPE_LEN);
    if (errCode > 0) {
        if (strncmp(propValue, SUPPORT_COEXCHIP, strlen(SUPPORT_COEXCHIP)) == 0) {
            HDF_LOGI("select tripleModes for wifi");
            return GetChipModesForTriple();
        }
    }
    return GetChipModesForPrimary();
}
}
}
}
}
}