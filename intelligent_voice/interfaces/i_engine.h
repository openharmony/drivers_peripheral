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
#ifndef I_ENGINE_H
#define I_ENGINE_H

#include <functional>
#include <memory>
#include "v1_0/intell_voice_engine_types.h"
#include "v1_1/intell_voice_engine_types.h"
#include "v1_2/intell_voice_engine_types.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IntellVoiceEngineCallBackEvent;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IntellVoiceEngineAdapterInfo;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::StartInfo;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IntellVoiceEngineAdapterDescriptor;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::ContentType;
using OHOS::HDI::IntelligentVoice::Engine::V1_1::IntellVoiceDataOprType;
using OHOS::HDI::IntelligentVoice::Engine::V1_2::UploadHdiFile;
using OHOS::HDI::IntelligentVoice::Engine::V1_2::EvaluationResultInfo;
using IntellVoiceStatus = int32_t;

using getParameterCb = std::function<void(const std::string &retStr)>;
using getFileDataCb = std::function<void(std::shared_ptr<uint8_t> data, uint32_t size)>;

class IEngineCallback {
public:
    IEngineCallback() = default;
    virtual ~IEngineCallback() = default;
    virtual void OnIntellVoiceEvent(const IntellVoiceEngineCallBackEvent &event) = 0;
};

struct OprDataInfo {
    std::shared_ptr<char> data = nullptr;
    uint32_t size = 0;
};

class IDataOprListener {
public:
    IDataOprListener() = default;
    virtual ~IDataOprListener() = default;
    virtual int32_t OnDataOprEvent(IntellVoiceDataOprType type, const OprDataInfo &inData, OprDataInfo &outData) = 0;
};

class IEngine {
public:
    IEngine() {};
    virtual ~IEngine() {};
    virtual IntellVoiceStatus SetListener(std::shared_ptr<IEngineCallback> listener) = 0;
    virtual IntellVoiceStatus Init(const IntellVoiceEngineAdapterInfo &adapterInfo) = 0;
    virtual IntellVoiceStatus Release() = 0;
    virtual IntellVoiceStatus SetParameter(const std::string &keyValueList) = 0;
    virtual IntellVoiceStatus GetParameter(const std::string &keyList, getParameterCb cb) = 0;
    virtual IntellVoiceStatus Write(const uint8_t *buffer, uint32_t size) = 0;
    virtual IntellVoiceStatus Start(const StartInfo &info) = 0;
    virtual IntellVoiceStatus Stop() = 0;
    virtual IntellVoiceStatus Cancel() = 0;
    virtual IntellVoiceStatus ReadFileData(ContentType type, getFileDataCb cb) = 0;
    virtual IntellVoiceStatus GetWakeupPcm(std::vector<uint8_t> &data) = 0;
    virtual IntellVoiceStatus Evaluate(const std::string &word, EvaluationResultInfo &info) = 0;
};

class IEngineManager {
public:
    virtual ~IEngineManager() {};
    virtual int32_t CreateAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor,
        std::unique_ptr<IEngine> &engine) = 0;
    virtual int32_t ReleaseAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor) = 0;
    virtual int32_t SetDataOprListener(std::shared_ptr<IDataOprListener> listener) = 0;
    virtual int32_t GetUploadFiles(int32_t maxNum, std::vector<UploadHdiFile> &files) = 0;
    virtual int32_t GetCloneFilesList(std::vector<std::string> &cloneFiles) = 0;
    virtual int32_t GetCloneFile(const std::string &filePath, std::shared_ptr<uint8_t> &buffer, uint32_t &size) = 0;
    virtual int32_t SendCloneFile(const std::string &filePath, const uint8_t *buffer, uint32_t size) = 0;
    virtual int32_t ClearUserWakeupData(const std::string &wakeupPhrase) = 0;
};
}
}
}
#endif
