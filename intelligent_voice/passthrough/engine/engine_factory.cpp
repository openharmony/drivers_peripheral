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
#include "engine_factory.h"
#include "intell_voice_log.h"
#include "enroll_engine.h"
#include "wakeup_engine.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceEngineFactory"

using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
std::unique_ptr<EngineBase> EngineFactory::CreateEngine(IntellVoiceEngineAdapterType type)
{
    std::unique_ptr<EngineBase> engine = nullptr;

    switch (type) {
        case ENROLL_ADAPTER_TYPE:
            engine = std::make_unique<EnrollEngine>();
            break;
        case WAKEUP_ADAPTER_TYPE:
            engine = std::make_unique<WakeupEngine>();
            break;
        default:
            INTELLIGENT_VOICE_LOGE("type: %{public}d is invalid", type);
            break;
    }

    return engine;
}
}
}
}