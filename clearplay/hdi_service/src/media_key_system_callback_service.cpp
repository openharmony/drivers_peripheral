/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "v1_0/media_key_system_callback_service.h"
#include <hdf_base.h>
#include <hdf_log.h>

#define HDF_LOG_TAG media_key_system_callback_service

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
MediaKeySystemCallbackService::MediaKeySystemCallbackService(OHOS::sptr<IMediaKeySystemCallback> callback)
    : keySystemCallback_(callback)
{
    HDF_LOGI("%{public}s: start", __func__);
    deathRecipient_ = new (std::nothrow) KeySystemCallbackDeathRecipient(this);
    if (deathRecipient_ == nullptr) {
        HDF_LOGE("%{public}s: new KeySystemCallbackDeathRecipient failed", __func__);
        return;
    }
    const OHOS::sptr<OHOS::IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IMediaKeySystemCallback>(callback);
    if (remote == nullptr || !remote->AddDeathRecipient(deathRecipient_)) {
        HDF_LOGE("%{public}s: AddDeathRecipient failed", __func__);
        deathRecipient_ = nullptr;
    }
}

MediaKeySystemCallbackService::~MediaKeySystemCallbackService()
{
    HDF_LOGI("%{public}s: start", __func__);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (keySystemCallback_ != nullptr && deathRecipient_ != nullptr) {
        const OHOS::sptr<OHOS::IRemoteObject> &remote =
            OHOS::HDI::hdi_objcast<IMediaKeySystemCallback>(keySystemCallback_);
        if (remote != nullptr) {
            remote->RemoveDeathRecipient(deathRecipient_);
        }
    }
    deathRecipient_ = nullptr;
    keySystemCallback_ = nullptr;
}

void MediaKeySystemCallbackService::OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object)
{
    (void)object;
    HDF_LOGW("%{public}s: remote media key system callback died", __func__);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    keySystemCallback_ = nullptr;
}

int32_t MediaKeySystemCallbackService::SendEvent(EventType eventType, int32_t extra, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: start", __func__);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (keySystemCallback_ == nullptr) {
        HDF_LOGE("%{public}s: remote callback is null or already dead", __func__);
        return HDF_FAILURE;
    }
    keySystemCallback_->SendEvent(eventType, extra, data);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}
} // V1_0
} // Drm
} // HDI
} // OHOS
