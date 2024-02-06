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

#include "v1_0/oem_certificate_service.h"
#include <hdf_base.h>
#include <hdf_log.h>

#define HDF_LOG_TAG oem_certificate_service

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
int32_t OemCertificateService::GenerateOemKeySystemRequest(std::string &defaultUrl, std::vector<uint8_t> &request)
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t OemCertificateService::ProcessOemKeySystemResponse(const std::vector<uint8_t> &response)
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}
} // V1_0
} // Drm
} // HDI
} // OHOS