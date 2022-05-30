/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_MOTION_V1_0_MOTIONIMPL_H
#define OHOS_HDI_MOTION_V1_0_MOTIONIMPL_H

#include "v1_0/imotion_interface.h"

namespace OHOS {
namespace HDI {
namespace Motion {
namespace V1_0 {
class MotionImpl : public IMotionInterface {
public:
    MotionImpl() = default;
    virtual ~MotionImpl() = default;
    int32_t EnableMotion(int32_t motionType) override;
    int32_t DisableMotion(int32_t motionType) override;
    int32_t Register(const sptr<IMotionCallback> &callbackObj) override;
    int32_t Unregister(const sptr<IMotionCallback> &callbackObj) override;
};
} // namespace V1_0
} // namespace Motion
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_MOTION_V1_0_MOTIONIMPL_H