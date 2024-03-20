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
#ifndef HDI_DEVICE_ENGINE_BASE_H
#define HDI_DEVICE_ENGINE_BASE_H
#include "i_engine.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
class EngineBase : public IEngine {
public:
    EngineBase() = default;
    ~EngineBase() = default;

    IntellVoiceStatus SetListener(std::shared_ptr<IEngineCallback> listener) override;
    IntellVoiceStatus Release() override;
    IntellVoiceStatus SetParameter(const std::string &keyValueList) override;
    IntellVoiceStatus GetParameter(const std::string &keyList, getParameterCb cb) override;
    IntellVoiceStatus Write(const uint8_t *buffer, uint32_t size) override;
    IntellVoiceStatus Stop() override;
    IntellVoiceStatus Cancel() override;
    IntellVoiceStatus ReadFileData(ContentType type, getFileDataCb cb) override;
    IntellVoiceStatus GetWakeupPcm(std::vector<uint8_t> &data) override;
    IntellVoiceStatus Evaluate(const std::string &word, EvaluationResultInfo &info) override;

protected:
    std::shared_ptr<IEngineCallback> callback_ = nullptr;
};
}
}
}
#endif