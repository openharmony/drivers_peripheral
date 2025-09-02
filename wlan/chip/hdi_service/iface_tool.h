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

#ifndef HAL_WIFI_SYSTEM_INTERFACE_TOOL_H
#define HAL_WIFI_SYSTEM_INTERFACE_TOOL_H

#include <array>
#include <cstdint>
#include <linux/if_ether.h>

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD001566

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V2_0 {

class IfaceTool {
public:
    IfaceTool() = default;
    virtual ~IfaceTool() = default;
    virtual bool GetUpState(const char* ifName);
    virtual bool SetUpState(const char* ifName, bool requestUp);
    virtual bool SetWifiUpState(bool requestUp);
    virtual bool SetMacAddress(const char* ifName, const char* mac);
};
}
}
}
}
}
#endif