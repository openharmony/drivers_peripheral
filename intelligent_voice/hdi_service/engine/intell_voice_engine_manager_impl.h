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

#ifndef HDI_DEVICE_INTELL_VOICE_MANAGER_IMPL_H
#define HDI_DEVICE_INTELL_VOICE_MANAGER_IMPL_H

#include <map>
#include <mutex>
#include <string>

#include "v1_2/intell_voice_engine_types.h"
#include "v1_1/intell_voice_engine_types.h"
#include "v1_2/iintell_voice_engine_manager.h"
#include "v1_1/iintell_voice_data_opr_callback.h"
#include "i_engine.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
using OHOS::HDI::IntelligentVoice::Engine::V1_2::IIntellVoiceEngineManager;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IIntellVoiceEngineAdapter;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IntellVoiceEngineAdapterType;
using OHOS::HDI::IntelligentVoice::Engine::V1_0::IntellVoiceEngineAdapterDescriptor;
using OHOS::HDI::IntelligentVoice::Engine::V1_1::IIntellVoiceDataOprCallback;
using OHOS::HDI::IntelligentVoice::Engine::V1_1::IntellVoiceDataOprType;
using OHOS::HDI::IntelligentVoice::Engine::V1_2::UploadHdiFile;

using GetEngineManagerHalInstFunc = IEngineManager *(*)();

struct IntellVoiceEngineManagerPriv {
    void *handle { nullptr };
    GetEngineManagerHalInstFunc getEngineManagerHalInst { nullptr };
};

class DataOprListener : public IDataOprListener {
public:
    DataOprListener(sptr<IIntellVoiceDataOprCallback> cb);
    ~DataOprListener();
    int32_t OnDataOprEvent(IntellVoiceDataOprType type, const OprDataInfo &inData, OprDataInfo &outData) override;
private:
    sptr<Ashmem> CreateAshmemFromOprData(const OprDataInfo &data, const std::string &name);
    int32_t FillOprDataFromAshmem(const sptr<Ashmem> &ashmem, OprDataInfo &data);
    sptr<IIntellVoiceDataOprCallback> cb_;
};

class IntellVoiceEngineManagerImpl : public IIntellVoiceEngineManager {
public:
    IntellVoiceEngineManagerImpl();
    ~IntellVoiceEngineManagerImpl();

    int32_t GetAdapterDescriptors(std::vector<IntellVoiceEngineAdapterDescriptor> &descs) override;
    int32_t CreateAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor,
        sptr<HDI::IntelligentVoice::Engine::V1_0::IIntellVoiceEngineAdapter> &adapter) override;
    int32_t ReleaseAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor) override;
    int32_t SetDataOprCallback(const sptr<IIntellVoiceDataOprCallback> &dataOprCallback) override;
    int32_t GetUploadFiles(int32_t numMax, std::vector<UploadHdiFile> &files) override;
    int32_t CreateAdapter_V_2(const IntellVoiceEngineAdapterDescriptor &descriptor,
        sptr<HDI::IntelligentVoice::Engine::V1_2::IIntellVoiceEngineAdapter> &adapter) override;
    int32_t GetCloneFilesList(std::vector<std::string> &cloneFiles) override;
    int32_t GetCloneFile(const std::string &filePath, std::vector<uint8_t> &buffer) override;
    int32_t SendCloneFile(const std::string &filePath, const std::vector<uint8_t> &buffer) override;
    int32_t ClearUserWakeupData(const std::string &wakeupPhrase) override;

private:
    int32_t LoadVendorLib();
    void UnloadVendorLib();
    template<typename T>
    int32_t CreateAdapterInner(const IntellVoiceEngineAdapterDescriptor &descriptor, sptr<T> &adapter);

private:
    std::map<IntellVoiceEngineAdapterType, sptr<IIntellVoiceEngineAdapter>> adapters_;
    std::mutex mutex_ {};
    IntellVoiceEngineManagerPriv engineManagerPriv_;
    IEngineManager *inst_ = nullptr;
};
}
}
}
#endif
