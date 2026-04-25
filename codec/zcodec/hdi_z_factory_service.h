/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_HDI_VIDEO_ZCODEC_V1_0_HDIZFACTORYSERVICE_H
#define OHOS_HDI_VIDEO_ZCODEC_V1_0_HDIZFACTORYSERVICE_H

#include "v1_0/hdi_z_factory.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Zcodec {
namespace V1_0 {
class HdiZFactoryService : public OHOS::HDI::Codec::Zcodec::V1_0::HdiZFactory {
public:
    HdiZFactoryService() = default;
    virtual ~HdiZFactoryService();

    int32_t GetCapabilities(std::vector<OHOS::HDI::Codec::Zcodec::V1_0::HdiCapability>& caps) override;

    int32_t CreateByStandard(int32_t standard, bool isEncoder,
        const sptr<OHOS::HDI::Codec::Zcodec::V1_0::HdiZCallback>& cb, const sptr<OHOS::HDI::Codec::ParcelableParam>& param,
        sptr<OHOS::HDI::Codec::Zcodec::V1_0::HdiZComponent>& instance) override;

    int32_t CreateByName(const std::string& name, const sptr<OHOS::HDI::Codec::Zcodec::V1_0::HdiZCallback>& cb,
        const sptr<OHOS::HDI::Codec::ParcelableParam>& param, sptr<OHOS::HDI::Codec::Zcodec::V1_0::HdiZComponent>& instance) override;
private:
    std::mutex mtx_;
    void* vdiHandle_ = nullptr;
};
} // V1_0
} // Zcodec
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_VIDEO_ZCODEC_V1_0_HDIZFACTORYSERVICE_H

