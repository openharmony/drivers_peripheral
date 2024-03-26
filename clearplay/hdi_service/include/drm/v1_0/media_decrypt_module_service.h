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

#ifndef OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULESERVICE_H
#define OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULESERVICE_H

#include "v1_0/imedia_decrypt_module.h"
#include "session.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class MediaDecryptModuleService : public OHOS::HDI::Drm::V1_0::IMediaDecryptModule {
public:
    MediaDecryptModuleService(sptr<Session>& session);
    virtual ~MediaDecryptModuleService() = default;

    int32_t DecryptMediaData(bool secure, const CryptoInfo& cryptoInfo, const DrmBuffer& srcBuffer,
         const DrmBuffer& destBuffer) override;

    int32_t Release() override;
    int32_t GetDecryptNumber();
    int32_t GetErrorDecryptNumber();
    int32_t GetDecryptTimes(std::vector<double> &times);
private:
    int32_t DecryptByAesCbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, 
        uint8_t* src_data, uint8_t* dest_data, const std::vector<SubSample>& subSamples);
    int32_t DecryptBySM4Cbc(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
    uint8_t *srcData, uint8_t *destData, const std::vector<SubSample> &subSamples);

    int32_t CopyBuffer(uint8_t* srcBuffer, uint8_t* dstBuffer, const std::vector<SubSample>& subSamples);
    int32_t decryptNumber = 0;
    int32_t errorDecryptNumber = 0;
    std::vector<double> decryptTimes;
    sptr<Session> session_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULESERVICE_H
