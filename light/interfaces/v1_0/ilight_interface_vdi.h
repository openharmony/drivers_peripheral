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

#ifndef OHOS_HDI_LIGHT_V1_0_LIGHTIFSERVICE_VDI_H
#define OHOS_HDI_LIGHT_V1_0_LIGHTIFSERVICE_VDI_H

#include <stdint.h>
#include <vector>
#include <hdf_base.h>
#include "hdf_load_vdi.h"
#include "ilight_type_vdi.h"

namespace OHOS {
namespace HDI {
namespace Light {
namespace V1_0 {

#define HDI_LIGHT_VDI_LIBNAME "libhdi_light_impl.z.so"

class ILightInterfaceVdi {
public:
    virtual ~ILightInterfaceVdi() = default;
    virtual int32_t Init() = 0;
    virtual int32_t GetLightInfo(std::vector<HdfLightInfoVdi>& info) = 0;
    virtual int32_t TurnOnLight(int32_t lightId, const HdfLightEffectVdi& effect) = 0;
    virtual int32_t TurnOnMultiLights(int32_t lightId, const std::vector<HdfLightColorVdi>& colors) = 0;
    virtual int32_t TurnOffLight(int32_t lightId) = 0;
};

struct VdiWrapperLight {
    struct HdfVdiBase base;
    ILightInterfaceVdi *lightModule;
};
} // namespace V1_0
} // namespace Light
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_LIGHT_V1_0_LIGHTIFSERVICE_VDI_H