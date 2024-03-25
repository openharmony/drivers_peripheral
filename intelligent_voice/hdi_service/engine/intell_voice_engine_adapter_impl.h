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

#ifndef HDI_DEVICE_INTELL_VOICE_ADAPTER_SERVICE_H
#define HDI_DEVICE_INTELL_VOICE_ADAPTER_SERVICE_H

#include <memory>
#include <fstream>
#include <map>

#include "v1_2/iintell_voice_engine_adapter.h"
#include "i_engine.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IIntellVoiceEngineCallback;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IntellVoiceEngineCallBackEvent;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IntellVoiceEngineAdapterInfo;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::StartInfo;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::ContentType;
using OHOS::HDI::IntelligentVoice::Engine::V1_2::EvaluationResultInfo;

class EngineListener : public IEngineCallback {
public:
    explicit EngineListener(const sptr<IIntellVoiceEngineCallback> &cb);
    ~EngineListener();
    void OnIntellVoiceEvent(const IntellVoiceEngineCallBackEvent &event) override;
private:
    sptr<IIntellVoiceEngineCallback> cb_;
};

class IntellVoiceEngineAdapterImpl : public HDI::IntelligentVoice::Engine::V1_2::IIntellVoiceEngineAdapter {
public:
    explicit IntellVoiceEngineAdapterImpl(std::unique_ptr<IEngine> engine);
    ~IntellVoiceEngineAdapterImpl();

    int32_t SetCallback(const sptr<IIntellVoiceEngineCallback> &engineCallback) override;
    int32_t Attach(const IntellVoiceEngineAdapterInfo &info) override;
    int32_t Detach() override;
    int32_t SetParameter(const std::string &keyValueList) override;
    int32_t GetParameter(const std::string &keyList, std::string &valueList) override;
    int32_t Start(const StartInfo &info) override;
    int32_t Stop() override;
    int32_t WriteAudio(const std::vector<uint8_t> &buffer) override;
    int32_t Read(ContentType type, sptr<Ashmem> &buffer) override;
    int32_t GetWakeupPcm(std::vector<uint8_t> &data) override;
    int32_t Evaluate(const std::string &word, EvaluationResultInfo &info) override;

private:
    int32_t ReadFileDataInner(ContentType type, uint8_t *&buffer, uint32_t &size);

private:
    std::unique_ptr<IEngine> engine_ = nullptr;
};
}
}
}
#endif
