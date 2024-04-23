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
#include "engine_base.h"
#include "hdf_base.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
IntellVoiceStatus EngineBase::SetListener(std::shared_ptr<IEngineCallback> listener)
{
    callback_ = listener;
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::Release()
{
    callback_ = nullptr;
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::SetParameter(const std::string & /* keyValueList */)
{
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::GetParameter(const std::string & /* keyList */, getParameterCb /* cb */)
{
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::Write(const uint8_t * /* buffer */, uint32_t /* size */)
{
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::Stop()
{
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::Cancel()
{
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::ReadFileData(ContentType /* type */, getFileDataCb /* cb */)
{
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::GetWakeupPcm(std::vector<uint8_t> & /* data */)
{
    return HDF_SUCCESS;
}

IntellVoiceStatus EngineBase::Evaluate(const std::string & /* word */, EvaluationResultInfo & /* info */)
{
    return HDF_SUCCESS;
}
}
}
}
