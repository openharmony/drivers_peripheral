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

#ifndef OHOS_HDI_MOTION_V1_1_IMOTIONINTERFACE_VDI_H
#define OHOS_HDI_MOTION_V1_1_IMOTIONINTERFACE_VDI_H

#include "hdf_load_vdi.h"
#include "imotion_callback_vdi.h"

namespace OHOS {
namespace HDI {
namespace Motion {
namespace V1_1 {

#define HDI_MOTION_VDI_LIBNAME "libhdi_motion_impl.z.so"

class IMotionInterfaceVdi {
public:
    virtual ~IMotionInterfaceVdi() = default;
    virtual int32_t InitMotion();
    virtual int32_t EnableMotion(int32_t motionType) = 0;
    virtual int32_t DisableMotion(int32_t motionType) = 0;
    virtual int32_t RegisterMotionCallback(const sptr<IMotionCallbackVdi> cb) = 0;
    virtual int32_t UnregisterMotionCallback(const sptr<IMotionCallbackVdi> cb) = 0;
    virtual int32_t SetMotionConfig(int32_t motionType, const std::vector<uint8_t>& data) = 0;
};

struct WrapperMotionVdi {
    struct HdfVdiBase base;
    IMotionInterfaceVdi *motionModule;
};
} // V1_1
} // Motion
} // HDI
} // OHOS

#endif // OHOS_HDI_MOTION_V1_1_IMOTIONINTERFACE_VDI_H
