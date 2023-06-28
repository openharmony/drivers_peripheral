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
#include <cinttypes>
#include <memory>
#include <vector>

#include "hdf_base.h"
#include "intell_voice_log.h"
#include "securec.h"
#include "scope_guard.h"

#include "intell_voice_engine_adapter_impl.h"

#define LOG_TAG "IntellVoiceEngineAdapterImpl"

using namespace OHOS::IntellVoiceUtils;

namespace OHOS {
namespace IntellVoiceEngine {
IntellVoiceEngineAdapterImpl::IntellVoiceEngineAdapterImpl(std::unique_ptr<IEngine> engine) : engine_(std::move(engine))
{}

IntellVoiceEngineAdapterImpl::~IntellVoiceEngineAdapterImpl()
{
    engine_ = nullptr;
}

int32_t IntellVoiceEngineAdapterImpl::SetCallback(const sptr<IIntellVoiceEngineCallback> &adapterCallback)
{
    if (adapterCallback == nullptr) {
        INTELL_VOICE_LOG_ERROR("callback is nullptr");
        return HDF_ERR_MALLOC_FAIL;
    }

    std::shared_ptr<EngineListener> listener = std::make_shared<EngineListener>(adapterCallback);
    if (listener == nullptr) {
        INTELL_VOICE_LOG_ERROR("listener is nullptr");
        return HDF_ERR_MALLOC_FAIL;
    }

    if (engine_->SetListener(listener) != 0) {
        INTELL_VOICE_LOG_ERROR("failed to set listener");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t IntellVoiceEngineAdapterImpl::Attach(const IntellVoiceEngineAdapterInfo& info)
{
    INTELL_VOICE_LOG_INFO("Attach enter");
    return engine_->Init(info);
}

int32_t IntellVoiceEngineAdapterImpl::Detach()
{
    INTELL_VOICE_LOG_INFO("Detach enter");
    return engine_->Release();
}

int32_t IntellVoiceEngineAdapterImpl::SetParameter(const std::string &keyValueList)
{
    INTELL_VOICE_LOG_INFO("SetParameter enter");
    return engine_->SetParameter(keyValueList);
}

int32_t IntellVoiceEngineAdapterImpl::GetParameter(const std::string &keyList, std::string &valueList)
{
    INTELL_VOICE_LOG_INFO("GetParameter enter");
    return engine_->GetParameter(keyList, [&](const std::string &retStr) { valueList = retStr; });
}

int32_t IntellVoiceEngineAdapterImpl::Start(const StartInfo& info)
{
    INTELL_VOICE_LOG_INFO("Start enter");
    return engine_->Start(info);
}

int32_t IntellVoiceEngineAdapterImpl::Stop()
{
    INTELL_VOICE_LOG_INFO("Stop enter");
    return engine_->Stop();
}

int32_t IntellVoiceEngineAdapterImpl::WriteAudio(const std::vector<uint8_t> &buffer)
{
    return engine_->Write(buffer.data(), buffer.size());
}

int32_t IntellVoiceEngineAdapterImpl::Read(ContentType type, sptr<Ashmem> &buffer)
{
    INTELL_VOICE_LOG_INFO("enter");
    uint8_t *tmp = nullptr;
    uint32_t size = 0;

    ReadFileDataInner(type, tmp, size);
    if (tmp == nullptr) {
        INTELL_VOICE_LOG_ERROR("tmp buffer is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    ON_SCOPE_EXIT_WITH_NAME(bufferExit)
    {
        INTELL_VOICE_LOG_INFO("now delete buffer");
        delete[] tmp;
        tmp = nullptr;
    };

    if (size == 0) {
        INTELL_VOICE_LOG_ERROR("size(%{public}u) is invalid", size);
        return HDF_ERR_INVALID_OBJECT;
    }

    buffer = OHOS::Ashmem::CreateAshmem("ReadContent", size);
    if (buffer == nullptr) {
        INTELL_VOICE_LOG_ERROR("ashmem buffer is nullptr, size:%{public}u", size);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (!buffer->MapReadAndWriteAshmem()) {
        INTELL_VOICE_LOG_ERROR("failed to map and write ashmem");
        return HDF_FAILURE;
    }

    if (!buffer->WriteToAshmem(tmp, size, 0)) {
        INTELL_VOICE_LOG_ERROR("failed to write to ashmem");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t IntellVoiceEngineAdapterImpl::ReadFileDataInner(ContentType type, uint8_t *&buffer, uint32_t &size)
{
    INTELL_VOICE_LOG_INFO("enter");
    return engine_->ReadFileData(type, [&](std::shared_ptr<uint8_t> fileData, uint32_t fileSize) {
        buffer = new (std::nothrow) uint8_t[fileSize];
        if (buffer == nullptr) {
            INTELL_VOICE_LOG_ERROR("buffer is nullptr");
            return;
        }
        size = fileSize;
        (void)memcpy_s(buffer, size, fileData.get(), fileSize);
    });
}

EngineListener::EngineListener(const sptr<IIntellVoiceEngineCallback> &cb) : cb_(cb)
{}

void EngineListener::OnIntellVoiceEvent(const IntellVoiceEngineCallBackEvent &event)
{
    if (cb_ == nullptr) {
        INTELL_VOICE_LOG_ERROR("cb_ is nullptr");
        return;
    }

    cb_->OnIntellVoiceHdiEvent(event);
}
}  // namespace IntellVoiceEngine
}  // namespace OHOS
