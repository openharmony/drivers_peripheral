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

#include "virtual_device.h"
#include <cstring>
#include <map>
#include <fcntl.h>
#include <securec.h>
#include <unistd.h>
#include <hdf_log.h>
#include <cerrno>

#define HDF_LOG_TAG virtual_device

namespace OHOS {
namespace ExternalDeviceManager {
namespace {
using namespace OHOS::HiviewDFX;
constexpr uint32_t MAX_NAME_LENGTH = 80;

bool DoIoctl(int32_t fd, int32_t request, const uint32_t value)
{
    int32_t rc = ioctl(fd, request, value);
    if (rc < 0) {
        HDF_LOGE("%{public}s Failed to ioctl", __func__);
        return false;
    }
    return true;
}
} // namespace

VirtualDevice::VirtualDevice(const Hid_Device &hidDevice, const Hid_EventProperties &hidEventProperties)
    : deviceName_(hidDevice.deviceName.c_str()),
    busType_(hidDevice.bustype),
    vendorId_(hidDevice.vendorId),
    productId_(hidDevice.productId),
    version_(hidDevice.version),
    eventTypes_(std::vector<uint32_t>(hidEventProperties.hidEventTypes.begin(),
        hidEventProperties.hidEventTypes.end())),
    keys_(std::vector<uint32_t>(hidEventProperties.hidKeys.begin(), hidEventProperties.hidKeys.end())),
    properties_(std::vector<uint32_t>(hidDevice.properties.begin(), hidDevice.properties.end())),
    abs_(std::vector<uint32_t>(hidEventProperties.hidAbs.begin(), hidEventProperties.hidAbs.end())),
    relBits_(std::vector<uint32_t>(hidEventProperties.hidRelBits.begin(), hidEventProperties.hidRelBits.end())),
    miscellaneous_(std::vector<uint32_t>(hidEventProperties.hidMiscellaneous.begin(),
        hidEventProperties.hidMiscellaneous.end()))
{
    const int absLength = 64;
    if (hidEventProperties.hidAbsMax.size() <= absLength) {
        std::copy(hidEventProperties.hidAbsMax.begin(), hidEventProperties.hidAbsMax.end(), uinputDev_.absmax);
    }
    if (hidEventProperties.hidAbsMin.size() <= absLength) {
        std::copy(hidEventProperties.hidAbsMin.begin(), hidEventProperties.hidAbsMin.end(), uinputDev_.absmin);
    }
    if (hidEventProperties.hidAbsFuzz.size() <= absLength) {
        std::copy(hidEventProperties.hidAbsFuzz.begin(), hidEventProperties.hidAbsFuzz.end(), uinputDev_.absfuzz);
    }
    if (hidEventProperties.hidAbsFlat.size() <= absLength) {
        std::copy(hidEventProperties.hidAbsFlat.begin(), hidEventProperties.hidAbsFlat.end(), uinputDev_.absflat);
    }
}

VirtualDevice::~VirtualDevice()
{
    if (fd_ >= 0) {
        ioctl(fd_, UI_DEV_DESTROY);
        close(fd_);
        fd_ = -1;
    }
}

bool VirtualDevice::SetUp()
{
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd_ < 0) {
        HDF_LOGE("%{public}s Failed to open uinput, errno=%{public}d", __func__, errno);
        return false;
    }

    if (!SetAttribute()) {
        HDF_LOGE("%{public}s Failed to set attribute", __func__);
        return false;
    }

    if (!CreateKey()) {
        HDF_LOGE("%{public}s Failed to create uinput KeyValue", __func__);
        return false;
    }

    if (strlen(deviceName_) == 0 || strlen(deviceName_) > MAX_NAME_LENGTH - 1) {
        HDF_LOGE("%{public}s Length of deviceName_ is out of range", __func__);
        return false;
    }
    errno_t ret = strncpy_s(uinputDev_.name, MAX_NAME_LENGTH, deviceName_, MAX_NAME_LENGTH - 1);
    if (ret != EOK) {
        HDF_LOGE("%{public}s Failed to copy deviceName", __func__);
        return false;
    }
    uinputDev_.id.bustype = busType_;
    uinputDev_.id.vendor = vendorId_;
    uinputDev_.id.product = productId_;
    uinputDev_.id.version = version_;
    if (write(fd_, &uinputDev_, sizeof(uinputDev_)) < 0) {
        HDF_LOGE("%{public}s Unable to set input device info", __func__);
        return false;
    }
    if (ioctl(fd_, UI_DEV_CREATE) < 0) {
        HDF_LOGE("%{public}s Unable to create input device", __func__);
        return false;
    }
    return true;
}

bool VirtualDevice::SetAttribute()
{
    for (const auto &item : GetEventTypes()) {
        if (!DoIoctl(fd_, UI_SET_EVBIT, item)) {
            HDF_LOGE("%{public}s Error setting event type:%{public}u", __func__, item);
            return false;
        }
    }
    for (const auto &item : GetKeys()) {
        if (!DoIoctl(fd_, UI_SET_KEYBIT, item)) {
            HDF_LOGE("%{public}s Error setting key:%{public}u", __func__, item);
            return false;
        }
    }
    for (const auto &item : GetProperties()) {
        if (!DoIoctl(fd_, UI_SET_PROPBIT, item)) {
            HDF_LOGE("%{public}s Error setting property:%{public}u", __func__, item);
            return false;
        }
    }
    for (const auto &item : GetAbs()) {
        if (!DoIoctl(fd_, UI_SET_ABSBIT, item)) {
            HDF_LOGE("%{public}s Error setting abs:%{public}u", __func__, item);
            return false;
        }
    }
    for (const auto &item : GetRelBits()) {
        if (!DoIoctl(fd_, UI_SET_RELBIT, item)) {
            HDF_LOGE("%{public}s Error setting rel:%{public}u", __func__, item);
            return false;
        }
    }

    return true;
}

bool VirtualDevice::EmitEvent(uint16_t type, uint16_t code, uint32_t value) const
{
    struct input_event event {};
    event.type = type;
    event.code = code;
    event.value = (int32_t)value;

#ifndef __MUSL__
    gettimeofday(&event.time, nullptr);
#endif
    if (write(fd_, &event, sizeof(event)) < static_cast<ssize_t>(sizeof(event))) {
        HDF_LOGE("%{public}s Event write failed, fd:%{public}d, errno:%{public}d", __func__, fd_, errno);
        return false;
    }
    return true;
}

const std::vector<uint32_t> &VirtualDevice::GetEventTypes() const
{
    return eventTypes_;
}

const std::vector<uint32_t> &VirtualDevice::GetKeys() const
{
    return keys_;
}

const std::vector<uint32_t> &VirtualDevice::GetProperties() const
{
    return properties_;
}

const std::vector<uint32_t> &VirtualDevice::GetAbs() const
{
    return abs_;
}

const std::vector<uint32_t> &VirtualDevice::GetRelBits() const
{
    return relBits_;
}

const std::vector<uint32_t> &VirtualDevice::GetLeds() const
{
    return leds_;
}

const std::vector<uint32_t> &VirtualDevice::GetRepeats() const
{
    return repeats_;
}

const std::vector<uint32_t> &VirtualDevice::GetMiscellaneous() const
{
    return miscellaneous_;
}

const std::vector<uint32_t> &VirtualDevice::GetSwitches() const
{
    return switches_;
}

bool VirtualDevice::CreateKey()
{
    auto fun = [&](int32_t uiSet, const std::vector<uint32_t> &list) -> bool {
        for (const auto &item : list) {
            if (ioctl(fd_, uiSet, item) < 0) {
                HDF_LOGE("%{public}s not setting event type: %{public}d, deviceName:%{public}s",
                    __func__, item, deviceName_);
                return false;
            }
        }
        return true;
    };
    std::map<int32_t, std::vector<uint32_t>> uinputTypes;
    uinputTypes[UI_SET_EVBIT] = GetEventTypes();
    uinputTypes[UI_SET_KEYBIT] = GetKeys();
    uinputTypes[UI_SET_PROPBIT] = GetProperties();
    uinputTypes[UI_SET_ABSBIT] = GetAbs();
    uinputTypes[UI_SET_RELBIT] = GetRelBits();

    uinputTypes[UI_SET_MSCBIT] = GetMiscellaneous();
    uinputTypes[UI_SET_LEDBIT] = GetLeds();
    uinputTypes[UI_SET_SWBIT] = GetSwitches();
    uinputTypes[UI_SET_FFBIT] = GetRepeats();

    for (const auto &item : uinputTypes) {
        if (!fun(item.first, item.second)) {
            return false;
        }
    }
    return true;
}
} // namespace ExternalDeviceManager
} // namespace OHOS
