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
#include "wakeup_engine.h"

#include <thread>
#include "hdf_base.h"
#include "intell_voice_log.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceWakeupEngine"

using namespace std;
using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
IntellVoiceStatus WakeupEngine::Init(const IntellVoiceEngineAdapterInfo & /* adapterInfo */)
{
    if (callback_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    IntellVoiceEngineCallBackEvent initEvent = {
        .msgId = INTELL_VOICE_ENGINE_MSG_INIT_DONE,
        .result = INTELL_VOICE_ENGINE_OK,
        .info = "",
    };
    callback_->OnIntellVoiceEvent(initEvent);
    return HDF_SUCCESS;
}

IntellVoiceStatus WakeupEngine::Start(const StartInfo & /*info */)
{
    if (callback_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    IntellVoiceEngineCallBackEvent startEvent = {
        .msgId = INTELL_VOICE_ENGINE_MSG_RECOGNIZE_COMPLETE,
        .result = INTELL_VOICE_ENGINE_OK,
        .info = "",
    };
    std::thread([&, startEvent]() { callback_->OnIntellVoiceEvent(startEvent); }).detach();
    return HDF_SUCCESS;
}
}
}
}
