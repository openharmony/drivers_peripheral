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
#include "enroll_engine.h"

#include <thread>
#include "hdf_base.h"
#include "intell_voice_log.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceEnrollEngine"

using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
IntellVoiceStatus EnrollEngine::Init(const IntellVoiceEngineAdapterInfo & /* adapterInfo */)
{
    INTELLIGENT_VOICE_LOGI("enter");
    if (callback_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    IntellVoiceEngineCallBackEvent initEvent = {
        .msgId = INTELL_VOICE_ENGINE_MSG_INIT_DONE,
        .result = INTELL_VOICE_ENGINE_OK,
        .info = "",
    };

    std::thread([&, initEvent]() { callback_->OnIntellVoiceEvent(initEvent); }).detach();
    return HDF_SUCCESS;
}

IntellVoiceStatus EnrollEngine::SetParameter(const std::string &keyValueList)
{
    INTELLIGENT_VOICE_LOGI("enter, keyValueList:%{public}s", keyValueList.c_str());
    if (callback_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    if (keyValueList.find("CommitEnrollment") != std::string::npos) {
        IntellVoiceEngineCallBackEvent commitEvent = {
            .msgId = INTELL_VOICE_ENGINE_MSG_COMMIT_ENROLL_COMPLETE,
            .result = INTELL_VOICE_ENGINE_OK,
            .info = "",
        };
        std::thread([&, commitEvent]() { callback_->OnIntellVoiceEvent(commitEvent); }).detach();
    }
    return HDF_SUCCESS;
}

IntellVoiceStatus EnrollEngine::Start(const StartInfo & /*info */)
{
    INTELLIGENT_VOICE_LOGI("enter");
    if (callback_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    IntellVoiceEngineCallBackEvent startEvent = {
        .msgId = INTELL_VOICE_ENGINE_MSG_ENROLL_COMPLETE,
        .result = INTELL_VOICE_ENGINE_OK,
        .info = "",
    };
    std::thread([&, startEvent]() { callback_->OnIntellVoiceEvent(startEvent); }).detach();
    return HDF_SUCCESS;
}
}
}
}
