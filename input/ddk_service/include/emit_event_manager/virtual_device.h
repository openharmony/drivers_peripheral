/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef VIRTUAL_DEVICE_H
#define VIRTUAL_DEVICE_H

#include <cstdint>
#include <vector>

#include <linux/uinput.h>

#include "nocopyable.h"
#include "v1_0/hid_ddk_types.h"

namespace OHOS {
namespace ExternalDeviceManager {
using namespace OHOS::HDI::Input::Ddk::V1_0;
class VirtualDevice {
public:
    VirtualDevice(const char *deviceName, uint16_t productId);
    VirtualDevice(const Hid_Device &hidDevice, const Hid_EventProperties &hidEventProperties);
    DISALLOW_COPY_AND_MOVE(VirtualDevice);
    virtual ~VirtualDevice();
    bool EmitEvent(uint16_t type, uint16_t code, uint32_t value) const;
    bool SetUp();
    bool CreateKey();

protected:
    virtual const std::vector<uint32_t> &GetEventTypes() const;
    virtual const std::vector<uint32_t> &GetKeys() const;
    virtual const std::vector<uint32_t> &GetProperties() const;
    virtual const std::vector<uint32_t> &GetAbs() const;
    virtual const std::vector<uint32_t> &GetRelBits() const;
    virtual const std::vector<uint32_t> &GetLeds() const;
    virtual const std::vector<uint32_t> &GetMiscellaneous() const;
    virtual const std::vector<uint32_t> &GetRepeats() const;
    virtual const std::vector<uint32_t> &GetSwitches() const;
    bool SetAttribute();
    FILE *file_ {nullptr};
    int32_t fd_ {-1};
    const char * const deviceName_;
    const uint16_t busType_;
    const uint16_t vendorId_;
    const uint16_t productId_;
    const uint16_t version_;
    struct uinput_user_dev uinputDev_ {};
    struct uinput_abs_setup uinputAbs_ {};
    std::vector<uinput_abs_setup> absInit_;
    std::vector<uint32_t> eventTypes_;
    std::vector<uint32_t> keys_;
    std::vector<uint32_t> properties_;
    std::vector<uint32_t> abs_;
    std::vector<uint32_t> relBits_;
    std::vector<uint32_t> leds_;
    std::vector<uint32_t> miscellaneous_;
    std::vector<uint32_t> switches_;
    std::vector<uint32_t> repeats_;
};
} // namespace ExternalDeviceManager
} // namespace OHOS
#endif // VIRTUAL_DEVICE_H