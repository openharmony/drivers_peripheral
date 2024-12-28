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

#ifndef I_TRIGGER_H
#define I_TRIGGER_H
#include <memory>
#include <vector>
#include "v1_2/intell_voice_trigger_types.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Trigger {
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerAdapterDsecriptor;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerProperties;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerModel;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceRecognitionEvent;

struct TriggerModel {
    TriggerModel(OHOS::HDI::IntelligentVoice::Trigger::V1_2::IntellVoiceTriggerModelType typeIn, uint32_t uidIn,
        std::vector<uint8_t> dataIn) : type(typeIn), uid(uidIn)
    {
        data.swap(dataIn);
    }
    OHOS::HDI::IntelligentVoice::Trigger::V1_2::IntellVoiceTriggerModelType type;
    uint32_t uid;
    std::vector<uint8_t> data;
};

class ITriggerCallback {
public:
    virtual ~ITriggerCallback() = default;
    virtual void OnRecognitionHdiEvent(const IntellVoiceRecognitionEvent &event, int32_t cookie) = 0;
};

class ITrigger {
public:
    virtual ~ITrigger() {};
    virtual int32_t GetProperties(IntellVoiceTriggerProperties &properties) = 0;
    virtual int32_t LoadIntellVoiceTriggerModel(const TriggerModel &model,
        const std::shared_ptr<ITriggerCallback> &callback, int32_t cookie, int32_t &handle) = 0;
    virtual int32_t UnloadIntellVoiceTriggerModel(int32_t handle) = 0;
    virtual int32_t Start(int32_t handle) = 0;
    virtual int32_t Stop(int32_t handle) = 0;
    virtual int32_t SetParams(const std::string &key, const std::string &value) = 0;
    virtual std::string GetParams(const std::string &key) = 0;
};

class ITriggerManager {
public:
    virtual ~ITriggerManager() {};
    virtual int32_t LoadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor,
        std::unique_ptr<ITrigger> &adapter) = 0;
    virtual int32_t UnloadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor) = 0;
};
}
}
}
#endif
