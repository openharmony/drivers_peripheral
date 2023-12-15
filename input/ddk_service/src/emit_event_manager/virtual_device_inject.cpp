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

#include "virtual_device_inject.h"
#include <hdf_log.h>

#define HDF_LOG_TAG virtual_device_inject

namespace OHOS {
namespace ExternalDeviceManager {
VirtualDeviceInject::VirtualDeviceInject(std::shared_ptr<VirtualDevice> virtualDevice)
{
    virtualDevice->SetUp();
    injectThread_ = std::make_unique<InjectThread>(virtualDevice);
    injectThread_->Start();
}

VirtualDeviceInject::~VirtualDeviceInject()
{
    injectThread_->Stop();
}

void VirtualDeviceInject::EmitEvent(const std::vector<Hid_EmitItem> &items)
{
    injectThread_->WaitFunc(items);
}
} // namespace ExternalDeviceManager
} // namespace OHOS
