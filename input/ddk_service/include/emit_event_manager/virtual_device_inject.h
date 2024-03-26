/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VIRTUALDEVICE_INJECT_H
#define VIRTUALDEVICE_INJECT_H

#include <map>
#include <memory>

#include "inject_thread.h"
#include "virtual_device.h"

namespace OHOS {
namespace ExternalDeviceManager {
using namespace OHOS::HDI::Input::Ddk::V1_0;
class VirtualDeviceInject {
public:
    VirtualDeviceInject(std::shared_ptr<VirtualDevice> virtualDevice, uint32_t creatorToken);
    DISALLOW_COPY_AND_MOVE(VirtualDeviceInject);
    virtual ~VirtualDeviceInject();
    void EmitEvent(const std::vector<Hid_EmitItem> &items);
    uint32_t GetCreatorToken();

private:
    std::unique_ptr<InjectThread> injectThread_;
    uint32_t creatorToken_;
};
} // namespace ExternalDeviceManager
} // namespace OHOS
#endif // VIRTUALDEVICE_INJECT_H