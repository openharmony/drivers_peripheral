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

#ifndef HDI_DEVICE_INTELL_VOICE_TRIGGER_MANAGER_IMPL_H
#define HDI_DEVICE_INTELL_VOICE_TRIGGER_MANAGER_IMPL_H

#include <mutex>
#include <unordered_map>

#include "v1_1/iintell_voice_trigger_manager.h"
#include "i_trigger.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Trigger {
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerAdapterDsecriptor;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IIntellVoiceTriggerAdapter;

using GetTriggerManagerHalInstFunc = ITriggerManager *(*)();

struct IntellVoiceTriggerManagerPriv {
    void *handle { nullptr };
    GetTriggerManagerHalInstFunc getTriggerManagerHalInst { nullptr };
};

class IntellVoiceTriggerManagerImpl :
    public OHOS::HDI::IntelligentVoice::Trigger::V1_1::IIntellVoiceTriggerManager {
public:
    IntellVoiceTriggerManagerImpl();
    ~IntellVoiceTriggerManagerImpl();

    int32_t LoadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor,
        sptr<OHOS::HDI::IntelligentVoice::Trigger::V1_0::IIntellVoiceTriggerAdapter> &adapter) override;
    int32_t LoadAdapter_V1_1(const IntellVoiceTriggerAdapterDsecriptor &descriptor,
        sptr<OHOS::HDI::IntelligentVoice::Trigger::V1_1::IIntellVoiceTriggerAdapter> &adapter) override;

    int32_t UnloadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor) override;

private:
    template<typename T>
    int32_t LoadIntellVoiceTriggerAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor, sptr<T> &adapter);
    int32_t LoadVendorLib();
    void UnloadVendorLib();

private:
    std::mutex mutex_ {};
    IntellVoiceTriggerManagerPriv triggerManagerPriv_;
    ITriggerManager *inst_ = nullptr;
    std::unordered_map<std::string, sptr<IIntellVoiceTriggerAdapter>> halAdapters_;
};
}
}
}
#endif // HDI_DEVICE_INTELL_VOICE_TRIGGER_MANAGER_IMPL_H