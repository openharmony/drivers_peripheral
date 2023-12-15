/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HID_DDK_SERVICE_H
#define HID_DDK_SERVICE_H

#include "v1_0/ihid_ddk.h"

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_0 {
class HidDdkService : public IHidDdk {
public:
    HidDdkService() = default;
    virtual ~HidDdkService() = default;

    int32_t CreateDevice(const Hid_Device& hidDevice, const Hid_EventProperties& hidEventProperties) override;

    int32_t EmitEvent(uint32_t deviceId, const std::vector<Hid_EmitItem>& items) override;

    int32_t DestroyDevice(uint32_t deviceId) override;
};
} // V1_0
} // Ddk
} // Input
} // HDI
} // OHOS

#endif // HID_DDK_SERVICE_H