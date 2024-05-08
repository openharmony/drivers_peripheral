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

#include <hdf_base.h>
#include <hdf_log.h>
#include "v1_0/media_key_system_factory_service.h"
#include "v1_0/media_key_system_service.h"
#include "clearplay_uuid.h"
#include "mime_type.h"

#define HDF_LOG_TAG media_key_system_factory_service

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
extern "C" IMediaKeySystemFactory *MediaKeySystemFactoryImplGetInstance(void)
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return new (std::nothrow) MediaKeySystemFactoryService();
}

MediaKeySystemFactoryService::~MediaKeySystemFactoryService()
{
    HDF_LOGI("%{public}s: start", __func__);
    mediaKeySystemMutex_.lock();
    while (mediaKeySystemMap_.size() > 0) {
        sptr<OHOS::HDI::Drm::V1_0::MediaKeySystemService> mediaKeySystem = mediaKeySystemMap_.begin()->first;
        mediaKeySystemMutex_.unlock();
        CloseMediaKeySystemService(mediaKeySystem);
        mediaKeySystemMutex_.lock();
    }
    mediaKeySystemMutex_.unlock();
    HDF_LOGI("%{public}s: end", __func__);
}

int32_t MediaKeySystemFactoryService::IsMediaKeySystemSupported(const std::string &uuid, const std::string &mimeType,
    ContentProtectionLevel level, bool &isSupported)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (IsClearPlayUuid(uuid) != true) {
        isSupported = false;
        HDF_LOGE("%{public}s: uuid is wrown", __func__);
        return HDF_SUCCESS;
    }
    if (mimeType != "" && mimeType != ISO_VIDEO_MIME_TYPE && mimeType != ISO_AUDIO_MIME_TYPE &&
        mimeType != CENC_INIT_DATA_FORMAT && mimeType != WEBM_INIT_DATA_FORMAT && mimeType != WEBM_AUDIO_DATA_FORMAT &&
        mimeType != WEBM_VIDEO_DATA_FORMAT) {
        isSupported = false;
        return HDF_SUCCESS;
    }
    if (level < SECURE_UNKNOWN || level > HW_SECURE_MAX) {
        isSupported = false;
        return HDF_SUCCESS;
    }
    isSupported = true;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemFactoryService::CreateMediaKeySystem(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> &mediaKeySystem)
{
    HDF_LOGI("%{public}s: start", __func__);
    sptr<MediaKeySystemService> newMediaKeySystem = new (std::nothrow) MediaKeySystemService();
    if (newMediaKeySystem == nullptr) {
        HDF_LOGE("new MediaKeySystemService() failed");
        return HDF_ERR_MALLOC_FAIL;
    }
    newMediaKeySystem->SetKeySystemServiceCallback(this);
    mediaKeySystemMap_[newMediaKeySystem] = true;
    mediaKeySystem = newMediaKeySystem;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemFactoryService::GetMediaKeySystemDescription(std::string &name, std::string &uuid)
{
    HDF_LOGI("%{public}s: start", __func__);
    name = CLEARPLAY_NAME;
    uuid = CLEARPLAY_UUID;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}
int32_t MediaKeySystemFactoryService::CloseMediaKeySystemService(sptr<MediaKeySystemService> mediaKeySystem)
{
    HDF_LOGI("%{public}s: start", __func__);
    mediaKeySystemMutex_.lock();
    auto it = mediaKeySystemMap_.find(mediaKeySystem);
    if (it == mediaKeySystemMap_.end()) {
        mediaKeySystemMutex_.unlock();
        return HDF_FAILURE;
    }
    mediaKeySystemMap_.erase(it);
    mediaKeySystemMutex_.unlock();
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}
} // V1_0
} // Drm
} // HDI
} // OHOS
