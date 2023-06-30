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
#include <cerrno>
#include "i_engine.h"
#include "hdf_base.h"
#include "intell_voice_log.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceEngineStub"

using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
class IntellVoiceEngineManager final : public IEngineManager {
public:
    int32_t CreateAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor, std::unique_ptr<IEngine> &engine)
    {
        INTELLIGENT_VOICE_LOGD("create adapter stub");
        return 0;
    }

    int32_t ReleaseAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor)
    {
        INTELLIGENT_VOICE_LOGD("release adapter stub");
        return 0;
    }

    static IntellVoiceEngineManager *GetInstance()
    {
        static IntellVoiceEngineManager manager;
        return &manager;
    }

private:
    IntellVoiceEngineManager(){};
    ~IntellVoiceEngineManager(){};
};
}
}
}

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) OHOS::IntelligentVoice::Engine::IEngineManager *GetIntellVoiceEngineManagerHalInst(void)
{
    INTELLIGENT_VOICE_LOGD("enter to engine manager stub");
    return OHOS::IntelligentVoice::Engine::IntellVoiceEngineManager::GetInstance();
}

#ifdef __cplusplus
}
#endif
