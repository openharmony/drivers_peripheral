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
#include "intell_voice_engine_adapter_impl.h"

#include <cinttypes>
#include <memory>
#include <vector>

#include "hdf_base.h"
#include "securec.h"
#include "intell_voice_log.h"
#include "scope_guard.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceEngineAdapterImpl"

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
IntellVoiceEngineAdapterImpl::IntellVoiceEngineAdapterImpl(std::unique_ptr<IEngine> engine)
    : engine_(std::move(engine))
{}

IntellVoiceEngineAdapterImpl::~IntellVoiceEngineAdapterImpl()
{
    engine_ = nullptr;
}

int32_t IntellVoiceEngineAdapterImpl::SetCallback(const sptr<IIntellVoiceEngineCallback> &engineCallback)
{
    if (engineCallback == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback is nullptr");
        return HDF_ERR_MALLOC_FAIL;
    }

    std::shared_ptr<EngineListener> listener = std::make_shared<EngineListener>(engineCallback);
    if (listener == nullptr) {
        INTELLIGENT_VOICE_LOGE("listener is nullptr");
        return HDF_ERR_MALLOC_FAIL;
    }

    if (engine_->SetListener(listener) != 0) {
        INTELLIGENT_VOICE_LOGE("failed to set listener");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t IntellVoiceEngineAdapterImpl::Attach(const IntellVoiceEngineAdapterInfo &info)
{
    INTELLIGENT_VOICE_LOGD("Attach enter");
    return engine_->Init(info);
}

int32_t IntellVoiceEngineAdapterImpl::Detach()
{
    INTELLIGENT_VOICE_LOGD("Detach enter");
    return engine_->Release();
}

int32_t IntellVoiceEngineAdapterImpl::SetParameter(const std::string &keyValueList)
{
    INTELLIGENT_VOICE_LOGD("SetParameter enter");
    return engine_->SetParameter(keyValueList);
}

int32_t IntellVoiceEngineAdapterImpl::GetParameter(const std::string &keyList, std::string &valueList)
{
    INTELLIGENT_VOICE_LOGD("GetParameter enter");
    return engine_->GetParameter(keyList, [&](const std::string &retStr) { valueList = retStr; });
}

int32_t IntellVoiceEngineAdapterImpl::Start(const StartInfo &info)
{
    INTELLIGENT_VOICE_LOGD("Start enter");
    return engine_->Start(info);
}

int32_t IntellVoiceEngineAdapterImpl::Stop()
{
    INTELLIGENT_VOICE_LOGD("Stop enter");
    return engine_->Stop();
}

int32_t IntellVoiceEngineAdapterImpl::WriteAudio(const std::vector<uint8_t> &buffer)
{
    return engine_->Write(buffer.data(), buffer.size());
}

int32_t IntellVoiceEngineAdapterImpl::Evaluate(const std::string &word, EvaluationResultInfo &info)
{
    return engine_->Evaluate(word, info);
}

int32_t IntellVoiceEngineAdapterImpl::Read(ContentType type, sptr<Ashmem> &buffer)
{
    INTELLIGENT_VOICE_LOGD("enter");
    uint8_t *tmp = nullptr;
    uint32_t size = 0;

    ReadFileDataInner(type, tmp, size);
    if (tmp == nullptr) {
        INTELLIGENT_VOICE_LOGE("tmp buffer is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    ON_SCOPE_EXIT_WITH_NAME(bufferExit)
    {
        INTELLIGENT_VOICE_LOGI("now delete buffer");
        delete[] tmp;
        tmp = nullptr;
    };

    if (size == 0) {
        INTELLIGENT_VOICE_LOGE("size(%{public}u) is invalid", size);
        return HDF_ERR_INVALID_OBJECT;
    }

    buffer = OHOS::Ashmem::CreateAshmem("ReadContent", size);
    if (buffer == nullptr) {
        INTELLIGENT_VOICE_LOGE("ashmem buffer is nullptr, size:%{public}u", size);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (!buffer->MapReadAndWriteAshmem()) {
        INTELLIGENT_VOICE_LOGE("failed to map and write ashmem");
        goto ERROR_EXIT;
    }

    if (!buffer->WriteToAshmem(tmp, size, 0)) {
        INTELLIGENT_VOICE_LOGE("failed to write to ashmem");
        goto ERROR_EXIT;
    }
    return HDF_SUCCESS;

ERROR_EXIT:
    buffer->UnmapAshmem();
    buffer->CloseAshmem();
    buffer = nullptr;
    return HDF_FAILURE;
}

int32_t IntellVoiceEngineAdapterImpl::ReadFileDataInner(ContentType type, uint8_t *&buffer, uint32_t &size)
{
    INTELLIGENT_VOICE_LOGD("enter");
    return engine_->ReadFileData(type, [&](std::shared_ptr<uint8_t> fileData, uint32_t fileSize) {
        buffer = new (std::nothrow) uint8_t[fileSize];
        if (buffer == nullptr) {
            INTELLIGENT_VOICE_LOGE("buffer is nullptr");
            return;
        }
        size = fileSize;
        (void)memcpy_s(buffer, size, fileData.get(), fileSize);
    });
}


int32_t IntellVoiceEngineAdapterImpl::GetWakeupPcm(std::vector<uint8_t> &data)
{
    return engine_->GetWakeupPcm(data);
}

EngineListener::EngineListener(const sptr<IIntellVoiceEngineCallback> &cb) : cb_(cb)
{
}

EngineListener::~EngineListener()
{
    cb_ = nullptr;
}

void EngineListener::OnIntellVoiceEvent(const IntellVoiceEngineCallBackEvent &event)
{
    if (cb_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("cb_ is nullptr");
        return;
    }

    cb_->OnIntellVoiceHdiEvent(event);
}
}
}
}
