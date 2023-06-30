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

#ifndef HDI_DEVICE_INTELL_VOICE_TRIGGER_ADAPTER_IMPL_H
#define HDI_DEVICE_INTELL_VOICE_TRIGGER_ADAPTER_IMPL_H

#include <memory>

#include "v1_0/iintell_voice_trigger_adapter.h"
#include "i_trigger.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Trigger {
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerProperties;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerModel;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceRecognitionEvent;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IIntellVoiceTriggerCallback;

class IntellVoiceTriggerCallbackDevice : public ITriggerCallback {
public:
    explicit IntellVoiceTriggerCallbackDevice(OHOS::sptr<IIntellVoiceTriggerCallback> callback);
    void OnRecognitionHdiEvent(const IntellVoiceRecognitionEvent &event, int32_t cookie) override;

private:
    OHOS::sptr<IIntellVoiceTriggerCallback> callback_ = nullptr;
};

class IntellVoiceTriggerAdapterImpl :
    public OHOS::HDI::IntelligentVoice::Trigger::V1_0::IIntellVoiceTriggerAdapter {
public:
    explicit IntellVoiceTriggerAdapterImpl(std::unique_ptr<ITrigger> adapter);
    ~IntellVoiceTriggerAdapterImpl();

    int32_t GetProperties(IntellVoiceTriggerProperties &properties) override;
    int32_t LoadModel(const IntellVoiceTriggerModel &model, const sptr<IIntellVoiceTriggerCallback> &triggerCallback,
        int32_t cookie, int32_t &handle) override;
    int32_t UnloadModel(int32_t handle) override;
    int32_t Start(int32_t handle) override;
    int32_t Stop(int32_t handle) override;

private:
    bool GetModelDataFromAshmem(sptr<Ashmem> ashmem, std::vector<uint8_t> &modelData);

private:
    std::unique_ptr<ITrigger> adapter_ = nullptr;
};
}
}
}
#endif // HDI_DEVICE_INTELL_VOICE_TRIGGER_ADAPTER_IMPL_H