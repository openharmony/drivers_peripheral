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
#include "intell_voice_trigger_adapter_impl.h"
#include "hdf_base.h"
#include "iproxy_broker.h"
#include "intell_voice_log.h"
#include "securec.h"
#include "scope_guard.h"
#include "memory_guard.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "TriggerAdapterImpl"

using namespace OHOS::HDI::IntelligentVoice::Trigger::V1_0;
using namespace OHOS::IntelligentVoice::Utils;

namespace OHOS {
namespace IntelligentVoice {
namespace Trigger {
IntellVoiceTriggerCallbackDevice::IntellVoiceTriggerCallbackDevice(OHOS::sptr<IIntellVoiceTriggerCallback> callback)
    : callback_(callback)
{}

IntellVoiceTriggerCallbackDevice::~IntellVoiceTriggerCallbackDevice()
{
    callback_ = nullptr;
}

void IntellVoiceTriggerCallbackDevice::OnRecognitionHdiEvent(const IntellVoiceRecognitionEvent &event, int32_t cookie)
{
    if (callback_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback_ is nullptr");
        return;
    }
    callback_->OnRecognitionHdiEvent(event, cookie);
}

IntellVoiceTriggerAdapterImpl::IntellVoiceTriggerAdapterImpl(std::unique_ptr<ITrigger> adapter)
    : adapter_(std::move(adapter))
{}

IntellVoiceTriggerAdapterImpl::~IntellVoiceTriggerAdapterImpl()
{
    adapter_ = nullptr;
}

int32_t IntellVoiceTriggerAdapterImpl::GetProperties(IntellVoiceTriggerProperties& properties)
{
    return adapter_->GetProperties(properties);
}

int32_t IntellVoiceTriggerAdapterImpl::LoadModel(const IntellVoiceTriggerModel &model,
    const sptr<IIntellVoiceTriggerCallback> &triggerCallback, int32_t cookie, int32_t &handle)
{
    MemoryGuard memoryGuard;
    std::shared_ptr<ITriggerCallback> cb = std::make_shared<IntellVoiceTriggerCallbackDevice>(triggerCallback);
    if (cb == nullptr) {
        INTELLIGENT_VOICE_LOGE("callback is nullptr");
        return HDF_ERR_MALLOC_FAIL;
    }

    if (model.data == nullptr) {
        INTELLIGENT_VOICE_LOGE("model data is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }

    ON_SCOPE_EXIT {
        INTELLIGENT_VOICE_LOGI("close ashmem");
        model.data->UnmapAshmem();
        model.data->CloseAshmem();
    };

    std::vector<uint8_t> modelData;
    if (GetModelDataFromAshmem(model.data, modelData) != static_cast<int32_t>(HDF_SUCCESS)) {
        return HDF_ERR_INVALID_PARAM;
    }

    TriggerModel triggerModel(static_cast<OHOS::HDI::IntelligentVoice::Trigger::V1_2::IntellVoiceTriggerModelType>(
        model.type), model.uid, modelData);
    int32_t ret = adapter_->LoadIntellVoiceTriggerModel(triggerModel, cb, cookie, handle);
    if (ret != 0) {
        INTELLIGENT_VOICE_LOGE("failed to load model, ret:%{public}d", ret);
        return ret;
    }

    RegisterDeathRecipient(handle, triggerCallback);
    return ret;
}

int32_t IntellVoiceTriggerAdapterImpl::UnloadModel(int32_t handle)
{
    MemoryGuard memoryGuard;
    int32_t ret = adapter_->UnloadIntellVoiceTriggerModel(handle);
    if (ret != 0) {
        INTELLIGENT_VOICE_LOGE("failed to unload model");
        return ret;
    }

    DeregisterDeathRecipient(handle);
    return ret;
}

int32_t IntellVoiceTriggerAdapterImpl::Start(int32_t handle)
{
    INTELLIGENT_VOICE_LOGE("Start");
    MemoryGuard memoryGuard;
    return adapter_->Start(handle);
}

int32_t IntellVoiceTriggerAdapterImpl::Stop(int32_t handle)
{
    MemoryGuard memoryGuard;
    return adapter_->Stop(handle);
}

int32_t IntellVoiceTriggerAdapterImpl::SetParams(const std::string &key, const std::string &value)
{
    INTELLIGENT_VOICE_LOGI("enter");
    MemoryGuard memoryGuard;
    return adapter_->SetParams(key, value);
}

int32_t IntellVoiceTriggerAdapterImpl::GetParams(const std::string &key, std::string &value)
{
    INTELLIGENT_VOICE_LOGI("enter");
    MemoryGuard memoryGuard;
    value = adapter_->GetParams(key);
    return 0;
}

int32_t IntellVoiceTriggerAdapterImpl::GetModelDataFromAshmem(sptr<Ashmem> ashmem, std::vector<uint8_t> &modelData)
{
    if (ashmem == nullptr) {
        INTELLIGENT_VOICE_LOGE("ashmem is nullptr");
        return HDF_ERR_INVALID_OBJECT;
    }

    uint32_t size = static_cast<uint32_t>(ashmem->GetAshmemSize());
    if (size == 0) {
        INTELLIGENT_VOICE_LOGE("size is zero");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!ashmem->MapReadOnlyAshmem()) {
        INTELLIGENT_VOICE_LOGE("map ashmem failed");
        return HDF_FAILURE;
    }

    const uint8_t *buffer = static_cast<const uint8_t *>(ashmem->ReadFromAshmem(size, 0));
    if (buffer == nullptr) {
        INTELLIGENT_VOICE_LOGE("read from ashmem failed");
        return HDF_ERR_MALLOC_FAIL;
    }

    modelData.insert(modelData.begin(), buffer, buffer + size);
    return HDF_SUCCESS;
}

bool IntellVoiceTriggerAdapterImpl::RegisterDeathRecipient(int32_t handle,
    const sptr<IIntellVoiceTriggerCallback> &triggerCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    INTELLIGENT_VOICE_LOGI("enter");
    handleToCallbackMap_[handle] = triggerCallback;
    sptr<IRemoteObject> object = OHOS::HDI::hdi_objcast<IIntellVoiceTriggerCallback>(triggerCallback);
    if (object == nullptr) {
        INTELLIGENT_VOICE_LOGE("object is nullptr");
        return false;
    }

    auto it = callbackToHandleMap_.find(object.GetRefPtr());
    if (it != callbackToHandleMap_.end()) {
        it->second.insert(handle);
        INTELLIGENT_VOICE_LOGI("callback already register, handle:%{public}d", handle);
        return true;
    }

    sptr<IntellVoiceDeathRecipient> recipient = new (std::nothrow) IntellVoiceDeathRecipient(
        std::bind(&IntellVoiceTriggerAdapterImpl::Clean, this, std::placeholders::_1), object.GetRefPtr());
    if (recipient == nullptr) {
        INTELLIGENT_VOICE_LOGE("create death recipient failed");
        return false;
    }

    if (!object->AddDeathRecipient(recipient)) {
        INTELLIGENT_VOICE_LOGE("add death recipient failed");
        return false;
    }

    callbackToHandleMap_[object.GetRefPtr()].insert(handle);
    deathRecipientMap_[object.GetRefPtr()] = recipient;
    INTELLIGENT_VOICE_LOGI("register death recipient success");
    return true;
}

void IntellVoiceTriggerAdapterImpl::DeregisterDeathRecipient(int32_t handle)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto callbackIter = handleToCallbackMap_.find(handle);
    if (callbackIter == handleToCallbackMap_.end()) {
        INTELLIGENT_VOICE_LOGE("failed to find callback");
        return ;
    }
    sptr<IIntellVoiceTriggerCallback> callback = callbackIter->second;
    handleToCallbackMap_.erase(callbackIter);

    sptr<IRemoteObject> object = OHOS::HDI::hdi_objcast<IIntellVoiceTriggerCallback>(callback);
    if (object == nullptr) {
        INTELLIGENT_VOICE_LOGE("object is nullptr");
        return;
    }

    auto handleSetIter = callbackToHandleMap_.find(object.GetRefPtr());
    if (handleSetIter == callbackToHandleMap_.end()) {
        INTELLIGENT_VOICE_LOGE("no handle set in callback, handle is: %{public}d", handle);
        return;
    }

    auto handleIter = handleSetIter->second.find(handle);
    if (handleIter == handleSetIter->second.end()) {
        INTELLIGENT_VOICE_LOGE("no handle in handle set, handle is: %{public}d", handle);
        return;
    }

    handleSetIter->second.erase(handleIter);
    if (!handleSetIter->second.empty()) {
        INTELLIGENT_VOICE_LOGI("handle set is not empty");
        return;
    }

    if (deathRecipientMap_.count(object.GetRefPtr()) != 0) {
        object->RemoveDeathRecipient(deathRecipientMap_[object.GetRefPtr()]);
        deathRecipientMap_.erase(object.GetRefPtr());
    }

    callbackToHandleMap_.erase(object.GetRefPtr());
    INTELLIGENT_VOICE_LOGI("handle set is empty, remove death recipient");
}

void IntellVoiceTriggerAdapterImpl::Clean(IRemoteObject *remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    INTELLIGENT_VOICE_LOGI("enter");
    if (remote == nullptr) {
        INTELLIGENT_VOICE_LOGE("remote is nullptr");
        return;
    }

    if (callbackToHandleMap_.count(remote) == 0) {
        INTELLIGENT_VOICE_LOGE("no remote");
        return;
    }

    MemoryGuard memoryGuard;
    for (auto it = callbackToHandleMap_[remote].begin(); it != callbackToHandleMap_[remote].end(); ++it) {
        INTELLIGENT_VOICE_LOGI("unload model, id is %{public}d", *it);
        (void)adapter_->UnloadIntellVoiceTriggerModel(*it);
        handleToCallbackMap_.erase(*it);
    }

    callbackToHandleMap_.erase(remote);
    deathRecipientMap_.erase(remote);
}
}  // namespace Trigger
}  // namespace IntelligentVoice
}  // namespace OHOS