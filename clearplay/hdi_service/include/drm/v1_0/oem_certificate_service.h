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

#ifndef OHOS_HDI_DRM_V1_0_OEMCERTIFICATESERVICE_H
#define OHOS_HDI_DRM_V1_0_OEMCERTIFICATESERVICE_H

#include "v1_0/ioem_certificate.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class OemCertificateService : public OHOS::HDI::Drm::V1_0::IOemCertificate {
public:
    OemCertificateService() = default;
    virtual ~OemCertificateService() = default;

    int32_t GenerateOemKeySystemRequest(std::string& defaultUrl, std::vector<uint8_t>& request) override;

    int32_t ProcessOemKeySystemResponse(const std::vector<uint8_t>& response) override;

};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_OEMCERTIFICATESERVICE_H