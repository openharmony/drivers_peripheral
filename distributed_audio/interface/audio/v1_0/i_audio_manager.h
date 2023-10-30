/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HDF_I_AUDIO_MANAGER_H
#define HDF_I_AUDIO_MANAGER_H

#include <string>
#include <vector>

#include "i_audio_adapter.h"
#include "types.h"

namespace OHOS {
namespace DistributedHardware {
using AdapterHandler = uint64_t;

class IAudioManager {
public:
    virtual int32_t GetAllAdapters(std::vector<AudioAdapterDescriptorHAL> &descriptors) = 0;

    virtual int32_t LoadAdapter(const AudioAdapterDescriptorHAL &descriptor, AdapterHandler &handler,
        IAudioAdapter &adapter) = 0;

    virtual int32_t UnloadAdapter(const AdapterHandler &handler) = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // HDF_I_AUDIO_MANAGER_H