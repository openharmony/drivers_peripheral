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

#ifndef HDI_DEVICE_INTELL_VOICE_TRIGGER_ADAPTER_IMPL_H
#define HDI_DEVICE_INTELL_VOICE_TRIGGER_ADAPTER_IMPL_H

#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>
#include "iremote_object.h"
#include "v1_1/iintell_voice_trigger_adapter.h"
#include "i_trigger.h"

namespace OHOS {
namespace IntelligentVoice {
namespace Trigger {
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IIntellVoiceTriggerCallback;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceRecognitionEvent;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerModel;
using OHOS::HDI::IntelligentVoice::Trigger::V1_0::IntellVoiceTriggerProperties;

class IntellVoiceTriggerCallbackDevice : public ITriggerCallback {
public:
    explicit IntellVoiceTriggerCallbackDevice(OHOS::sptr<IIntellVoiceTriggerCallback> callback);
    ~IntellVoiceTriggerCallbackDevice();
    void OnRecognitionHdiEvent(const IntellVoiceRecognitionEvent &event, int32_t cookie) override;

private:
    OHOS::sptr<IIntellVoiceTriggerCallback> callback_ = nullptr;
};

class IntellVoiceDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    using ServiceDiedCallback = std::function<void(IRemoteObject *)>;
    IntellVoiceDeathRecipient(ServiceDiedCallback callback, IRemoteObject *remote)
        : callback_(callback), remote_(remote) {};
    ~IntellVoiceDeathRecipient() override = default;

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        (void)remote;
        if (callback_ != nullptr) {
            callback_(remote_);
        }
    }

private:
    ServiceDiedCallback callback_ = nullptr;
    IRemoteObject *remote_ = nullptr;
};

class IntellVoiceTriggerAdapterImpl : public OHOS::HDI::IntelligentVoice::Trigger::V1_1::IIntellVoiceTriggerAdapter {
public:
    explicit IntellVoiceTriggerAdapterImpl(std::unique_ptr<ITrigger> adapter);
    ~IntellVoiceTriggerAdapterImpl();

    int32_t GetProperties(IntellVoiceTriggerProperties &properties) override;
    int32_t LoadModel(const IntellVoiceTriggerModel &model, const sptr<IIntellVoiceTriggerCallback> &triggerCallback,
        int32_t cookie, int32_t &handle) override;
    int32_t UnloadModel(int32_t handle) override;
    int32_t Start(int32_t handle) override;
    int32_t Stop(int32_t handle) override;
    int32_t SetParams(const std::string &key, const std::string &value) override;
    int32_t GetParams(const std::string &key, std::string &value) override;

private:
    int32_t GetModelDataFromAshmem(sptr<Ashmem> ashmem, std::vector<uint8_t> &modelData);
    bool RegisterDeathRecipient(int32_t handle, const sptr<IIntellVoiceTriggerCallback> &triggerCallback);
    void DeregisterDeathRecipient(int32_t handle);
    void Clean(IRemoteObject *remote);

private:
    std::unique_ptr<ITrigger> adapter_ = nullptr;
    std::mutex mutex_;
    std::unordered_map<int32_t, sptr<IIntellVoiceTriggerCallback>> handleToCallbackMap_;
    std::unordered_map<IRemoteObject *, std::set<int32_t>> callbackToHandleMap_;
    std::unordered_map<IRemoteObject *, sptr<IRemoteObject::DeathRecipient>> deathRecipientMap_;
};
}  // namespace Trigger
}  // namespace IntelligentVoice
}  // namespace OHOS
#endif  // HDI_DEVICE_INTELL_VOICE_TRIGGER_ADAPTER_IMPL_H