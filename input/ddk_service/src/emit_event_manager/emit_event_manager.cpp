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

#include "emit_event_manager.h"
#include "ipc_skeleton.h"
#include <hdf_log.h>
#include "ipc_skeleton.h"

#define HDF_LOG_TAG emit_event_manager

namespace OHOS {
namespace ExternalDeviceManager {
constexpr uint16_t MAX_VIRTUAL_DEVICE_NUM = 200;
EmitEventManager& EmitEventManager::GetInstance(void)
{
    static EmitEventManager instance;
    return instance;
}

int32_t EmitEventManager::CreateDevice(const Hid_Device &hidDevice, const Hid_EventProperties &hidEventProperties)
{
    std::lock_guard<std::mutex> lock(mutex_);
    // check device number
    if (virtualDeviceMap_.size() >= MAX_VIRTUAL_DEVICE_NUM) {
        HDF_LOGE("%{public}s device num exceeds maximum %{public}d", __func__, MAX_VIRTUAL_DEVICE_NUM);
        return HID_DDK_FAILURE;
    }
    // get device id
    int32_t id = 0;
    if (GetCurDeviceId(id) == false) {
        HDF_LOGE("%{public}s faild to generate device id", __func__);
        return HID_DDK_FAILURE;
    }

    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    // create device
    virtualDeviceMap_[id] = std::make_unique<VirtualDeviceInject>(
        std::make_shared<VirtualDevice>(hidDevice, hidEventProperties), callingToken);
    return id;
}

int32_t EmitEventManager::EmitEvent(uint32_t deviceId, const std::vector<Hid_EmitItem> &items)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (virtualDeviceMap_.count(deviceId) == 0) {
        HDF_LOGE("%{public}s device is not exit", __func__);
        return HID_DDK_FAILURE;
    }

    if (virtualDeviceMap_[deviceId] == nullptr) {
        HDF_LOGE("%{public}s VirtualDeviceInject is null", __func__);
        return HID_DDK_NULL_PTR;
    }
	
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (virtualDeviceMap_[deviceId]->GetCreatorToken() != callingToken) {
        HDF_LOGE("caller of %{public}s is invalid", __func__);
        return HID_DDK_INVALID_OPERATION;
    }

    virtualDeviceMap_[deviceId]->EmitEvent(items);
    return HID_DDK_SUCCESS;
}

int32_t EmitEventManager::DestroyDevice(uint32_t deviceId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (virtualDeviceMap_.count(deviceId) == 0) {
        HDF_LOGE("%{public}s device is not exit", __func__);
        return HID_DDK_FAILURE;
    }
	
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (virtualDeviceMap_[deviceId] != nullptr
        && virtualDeviceMap_[deviceId]->GetCreatorToken() != callingToken) {
        HDF_LOGE("caller of %{public}s is invalid", __func__);
        return HID_DDK_INVALID_OPERATION;
    }
    virtualDeviceMap_.erase(deviceId);
    lastDeviceId_ = deviceId;
    return HID_DDK_SUCCESS;
}

bool EmitEventManager::GetCurDeviceId(int32_t &id)
{
    if (virtualDeviceMap_.size() >= MAX_VIRTUAL_DEVICE_NUM) {
        HDF_LOGE("%{public}s: The number of devices has reached max_num", __func__);
        id = -1;
        return false;
    }
    if (virtualDeviceMap_.count(lastDeviceId_) == 0) {
        id = lastDeviceId_;
        return true;
    }
    uint32_t newId = virtualDeviceMap_.size();
    while (virtualDeviceMap_.count(newId) != 0) {
        newId++;
    }
    id = static_cast<int32_t>(newId);
    return true;
}

void EmitEventManager::ClearDeviceMap(void)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (virtualDeviceMap_.size() > 0) {
        virtualDeviceMap_.clear();
        HDF_LOGI("%{public}s: clear device map success", __func__);
    }
}
} // namespace ExternalDeviceManager
} // namespace OHOS