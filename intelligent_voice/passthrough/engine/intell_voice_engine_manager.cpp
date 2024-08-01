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
#include "hdf_base.h"
#include "intell_voice_log.h"
#include "engine_factory.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceEngineMgr"

using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
class IntellVoiceEngineManager final : public IEngineManager {
public:
    int32_t CreateAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor,
        std::unique_ptr<IEngine> &engine) override
    {
        INTELLIGENT_VOICE_LOGD("create adapter");
        engine = EngineFactory::CreateEngine(descriptor.adapterType);
        if (engine == nullptr) {
            INTELLIGENT_VOICE_LOGE("failed to create engine");
        }
        return HDF_SUCCESS;
    }

    int32_t ReleaseAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor) override
    {
        INTELLIGENT_VOICE_LOGD("release adapter");
        return HDF_SUCCESS;
    }

    int32_t SetDataOprListener(std::shared_ptr<IDataOprListener> listener) override
    {
        INTELLIGENT_VOICE_LOGD("enter");
        return HDF_SUCCESS;
    }

    int32_t GetUploadFiles(int32_t maxNum, std::vector<UploadHdiFile> &files) override
    {
        INTELLIGENT_VOICE_LOGD("enter");
        return HDF_SUCCESS;
    }

    int32_t GetCloneFilesList(std::vector<std::string> &cloneFiles) override
    {
        INTELLIGENT_VOICE_LOGD("enter");
        return HDF_SUCCESS;
    }

    int32_t GetCloneFile(const std::string &filePath, std::shared_ptr<uint8_t> &buffer, uint32_t &size) override
    {
        INTELLIGENT_VOICE_LOGD("enter");
        return HDF_SUCCESS;
    }

    int32_t SendCloneFile(const std::string &filePath, const uint8_t *buffer, uint32_t size) override
    {
        INTELLIGENT_VOICE_LOGD("enter");
        return HDF_SUCCESS;
    }

    int32_t ClearUserWakeupData(const std::string &wakeupPhrase) override
    {
        INTELLIGENT_VOICE_LOGD("enter");
        return HDF_SUCCESS;
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
