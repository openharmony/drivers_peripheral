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

#ifndef INPUT_EMIT_EVENT_EMIT_EVENT_MANAGER_H
#define INPUT_EMIT_EVENT_EMIT_EVENT_MANAGER_H
#include <inttypes.h>

#include "v1_0/hid_ddk_types.h"
#include "virtual_device_inject.h"

namespace OHOS {
namespace ExternalDeviceManager {
using namespace OHOS::HDI::Input::Ddk::V1_0;
class EmitEventManager final {
public:
    static EmitEventManager& GetInstance();

    int32_t CreateDevice(const Hid_Device &hidDevice, const Hid_EventProperties &hidEventProperties);
    int32_t EmitEvent(uint32_t deviceId, const std::vector<Hid_EmitItem> &items);
    int32_t DestroyDevice(uint32_t deviceId);
    bool GetCurDeviceId(int32_t &id);
    void ClearDeviceMap(void);

private:
    EmitEventManager() = default;
    ~EmitEventManager() = default;
    EmitEventManager(const EmitEventManager&) = delete;
    EmitEventManager &operator=(const EmitEventManager &) = delete;
    EmitEventManager(EmitEventManager &&) = delete;
    EmitEventManager &operator=(EmitEventManager &&) = delete;

    std::map<uint32_t, std::unique_ptr<VirtualDeviceInject>> virtualDeviceMap_;
    std::mutex mutex_;
    uint32_t lastDeviceId_ = 0;
};
} // namespace ExternalDeviceManager
} // namespace OHOS
#endif // INPUT_EMIT_EVENT_EMIT_EVENT_MANAGER_H