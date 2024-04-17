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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMFACTORYSERVICE_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMFACTORYSERVICE_H

#include "v1_0/imedia_key_system_factory.h"
#include "v1_0/media_key_system_service.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class MediaKeySystemFactoryService : public OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory, public MediaKeySystemServiceCallback {
public:
    MediaKeySystemFactoryService() = default;
    virtual ~MediaKeySystemFactoryService();

    int32_t IsMediaKeySystemSupported(const std::string& name, const std::string& mimeType,
         OHOS::HDI::Drm::V1_0::ContentProtectionLevel level, bool& isSupported) override;
    int32_t GetMediaKeySystemDescription(std::string &name, std::string &uuid) override;
    int32_t CreateMediaKeySystem(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem>& mediaKeySystem) override;
    int32_t CloseMediaKeySystemService(sptr<OHOS::HDI::Drm::V1_0::MediaKeySystemService> mediaKeySystem) override;

private:
    std::map<sptr<OHOS::HDI::Drm::V1_0::MediaKeySystemService>, bool> mediaKeySystemMap_;
    std::mutex mediaKeySystemMutex_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMFACTORYSERVICE_H