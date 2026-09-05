/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "daudio_manager_interface_impl.h"

#include <hdf_base.h>

#include "cJSON.h"
#include "daudio_errcode.h"
#include "daudio_log.h"
#include "daudio_utils.h"


#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioManagerInterfaceImpl"

using namespace OHOS::DistributedHardware;
using namespace OHOS::HDI::DistributedAudio::Audio::V2_0;

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audioext {
namespace V3_0 {
DAudioManagerInterfaceImpl *DAudioManagerInterfaceImpl::dAudioMgr_ = nullptr;
std::mutex DAudioManagerInterfaceImpl::mgrMtx_;
extern "C" IDAudioManager *DAudioManagerImplGetInstance(void)
{
    return DAudioManagerInterfaceImpl::GetDAudioManager();
}

DAudioManagerInterfaceImpl::DAudioManagerInterfaceImpl()
{
    DHLOGI("Distributed audio ext manager constructed.");
    audioMgr_ = AudioManagerInterfaceImpl::GetAudioManager();
}

DAudioManagerInterfaceImpl::~DAudioManagerInterfaceImpl()
{
    DHLOGI("Distributed audio ext manager destructed.");
}

int32_t DAudioManagerInterfaceImpl::RegisterAudioDevice(const std::string &adpName, int32_t devId,
    const std::string &capability, const sptr<IDAudioCallback> &callbackObj)
{
    DHLOGI("Register audio device, name: %{public}s, device: %{public}s.", GetAnonyString(adpName).c_str(),
        GetChangeDevIdMap(devId).c_str());
    if (audioMgr_ == nullptr) {
        DHLOGE("Audio manager is null.");
        return HDF_FAILURE;
    }

    std::string param = capability;

    int32_t ret = audioMgr_->AddAudioDevice(adpName, devId, param, callbackObj);
    if (ret != DH_SUCCESS) {
        DHLOGE("Register audio device failed, ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    DHLOGI("Register audio device success.");
    return HDF_SUCCESS;
}

int32_t DAudioManagerInterfaceImpl::UnRegisterAudioDevice(const std::string &adpName, int32_t devId)
{
    DHLOGI("UnRegister audio device, name: %{public}s, device: %{public}s.", GetAnonyString(adpName).c_str(),
        GetChangeDevIdMap(devId).c_str());
    if (audioMgr_ == nullptr || audioMgr_->GetAudioMgrState()) {
        DHLOGE("Audio manager is null or destructing...");
        return HDF_FAILURE;
    }

    int32_t ret = audioMgr_->RemoveAudioDevice(adpName, devId);
    if (ret != DH_SUCCESS) {
        DHLOGE("UnRegister audio devcie failed. ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    DHLOGI("UnRegister audio device success.");
    return HDF_SUCCESS;
}

int32_t DAudioManagerInterfaceImpl::NotifyEvent(const std::string &adpName, int32_t devId,
    int32_t streamId, const DAudioEvent &event)
{
    if (audioMgr_ == nullptr || audioMgr_->GetAudioMgrState()) {
        DHLOGE("Audio manager is null or destructing...");
        return HDF_FAILURE;
    }

    DAudioEvent newEvent = event;
    uint32_t triggerFirstTokenId = audioMgr_->GetTriggerFirstTokenId();
    if (triggerFirstTokenId != 0) {
        cJSON *json = cJSON_Parse(newEvent.content.c_str());
        if (json != nullptr) {
            cJSON_AddNumberToObject(json, KEY_TRIGGER_FIRST_TOKENID, static_cast<double>(triggerFirstTokenId));
            char *jsonStr = cJSON_PrintUnformatted(json);
            std::string newContent(jsonStr);
            cJSON_Delete(json);
            cJSON_free(jsonStr);
            newEvent.content = newContent;
        }
        DHLOGI("[MultiUserTrigger] NotifyEvent triggerFirstTokenId=%{public}s, pass to daudio SA",
            GetAnonyString(std::to_string(triggerFirstTokenId)).c_str());
    }

    DHLOGI("Notify event. event type = %{public}d", event.type);
    int32_t ret = audioMgr_->Notify(adpName, devId, streamId, newEvent);
    if (ret != DH_SUCCESS) {
        DHLOGE("Notify audio event failed. ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t DAudioManagerInterfaceImpl::RegisterAudioHdfListener(const std::string &serviceName,
    const sptr<IDAudioHdfCallback> &callbackObj)
{
    DHLOGI("Register audio HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    if (callbackObj == nullptr) {
        DHLOGE("Audio hdf callback is null.");
        return HDF_FAILURE;
    }

    if (audioMgr_ == nullptr) {
        DHLOGE("Audio manager is null.");
        return HDF_FAILURE;
    }

    int32_t ret = audioMgr_->RegisterAudioHdfListener(serviceName, callbackObj);
    if (ret != DH_SUCCESS) {
        DHLOGE("Register audio HDF listener failed, ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    DHLOGI("Register audio HDF listener success.");
    return HDF_SUCCESS;
}

int32_t DAudioManagerInterfaceImpl::UnRegisterAudioHdfListener(const std::string &serviceName)
{
    DHLOGI("Unregister audio HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    if (audioMgr_ == nullptr) {
        DHLOGE("Audio manager is null.");
        return HDF_FAILURE;
    }

    int32_t ret = audioMgr_->UnRegisterAudioHdfListener(serviceName);
    if (ret != DH_SUCCESS) {
        DHLOGE("Unregister audio HDF listener failed. ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    DHLOGI("Unregister audio HDF listener success.");
    return HDF_SUCCESS;
}
} // v3_0
} // AudioExt
} // Daudio
} // HDI
} // OHOS
