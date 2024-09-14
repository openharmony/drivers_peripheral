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

#ifndef OHOS_HDI_MOTION_V1_1_MOTIONIFSERVICE_H
#define OHOS_HDI_MOTION_V1_1_MOTIONIFSERVICE_H

#include "imotion_interface_vdi.h"
#include "motion_uhdf_log.h"
#include "motion_callback_vdi.h"
#include "v1_1/imotion_interface.h"

namespace OHOS {
namespace HDI {
namespace Motion {
namespace V1_1 {
class MotionIfService : public IMotionInterface {
public:
    MotionIfService();
    ~MotionIfService();
    int32_t Init();
    int32_t EnableMotion(int32_t motionType) override;
    int32_t DisableMotion(int32_t motionType) override;
    int32_t Register(const sptr<IMotionCallback> &callbackObj) override;
    int32_t Unregister(const sptr<IMotionCallback> &callbackObj) override;
    int32_t SetMotionConfig(int32_t motionType, const std::vector<uint8_t>& data) override;

    int32_t GetMotionVdiImpl();
private:
    int32_t CheckMotionType(int32_t motionType);
    IMotionInterfaceVdi *motionVdiImpl_ = nullptr;
    struct HdfVdiObject *vdi_ = nullptr;
};
} // namespace V1_1
} // namespace Motion
} // namespace HDI
} // namespcae OHOS

#endif // OHOS_HDI_MOTION_V1_1_MOTIONIFSERVICE_H
