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

#include <errno.h>
#include "i_engine.h"
#include "hdf_base.h"
#include "intell_voice_log.h"

#define LOG_TAG "IntellVoiceEngineStub"
using namespace OHOS::IntellVoiceEngine;
using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

namespace OHOS {
namespace IntellVoiceEngineStub {

class IntellVoiceEngineManagerStub final : public IEngineManager {
public:
    int32_t CreateAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor, std::unique_ptr<IEngine> &engine)
    {
        INTELL_VOICE_LOG_INFO("create adapter stub");
        return 0;
    }

    int32_t ReleaseAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor)
    {
        INTELL_VOICE_LOG_INFO("release adapter stub");
        return 0;
    }

    static IntellVoiceEngineManagerStub *GetInstance()
    {
        static IntellVoiceEngineManagerStub manager;
        return &manager;
    }

private:
    IntellVoiceEngineManagerStub(){};
    ~IntellVoiceEngineManagerStub(){};
};

}  // namespace IntellVoiceEngineStub
}  // namespace OHOS

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) OHOS::IntellVoiceEngine::IEngineManager *GetIntellVoiceEngineManagerHalInst(void)
{
    INTELL_VOICE_LOG_INFO("enter to engine manager stub");
    return OHOS::IntellVoiceEngineStub::IntellVoiceEngineManagerStub::GetInstance();
}

#ifdef __cplusplus
}
#endif
