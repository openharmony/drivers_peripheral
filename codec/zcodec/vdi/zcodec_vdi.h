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

#ifndef OHOS_HDI_VIDEO_ZCODEC_V1_0_HDIZCODECVDI_H
#define OHOS_HDI_VIDEO_ZCODEC_V1_0_HDIZCODECVDI_H
#include "v1_0/hdi_z_factory.h"

namespace OHOS::HDI::Codec::Zcodec::V1_0 {
constexpr char SONAME[] = "libzcodec_vdi_impl.z.so";

constexpr char GET_CAPABILITY_FUNC_NAME[] = "GetZCapability";
using GetZCapabilityFunc = int32_t (*)(std::vector<HdiCapability>& caps);

constexpr char CREATE_ZCODEC_BY_STD_FUNC[] = "CreateZComponentByStandardVdi";
using CreateZCodecByStdFunc = int32_t (*)(Standard standard, bool isEncoder,
        const sptr<HdiZCallback>&, const sptr<ParcelableParam>&, sptr<HdiZComponent>&);

constexpr char CREATE_ZCODEC_BY_NAME_FUNC[] = "CreateZComponentByNameVdi";
using CreateZCodecByNameFunc = int32_t (*)(const std::string& name,
        const sptr<HdiZCallback>&, const sptr<ParcelableParam>&, sptr<HdiZComponent>&);

}
#endif
