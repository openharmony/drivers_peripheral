/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_hal_hicollie.h"

namespace OHOS::Camera {

CameraHalHicollie::CameraHalHicollie(
    const std::string &name, uint32_t timeout, std::function<void (void *)> func, void *arg, uint32_t flag)
{
    id_ = HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, func, arg, flag);
    if (id_ < NUMBER_ZERO) {
        CAMERA_LOGE("CameraHalHicollie SetTimer name:%{public}s id:%{public}d failed", name.c_str(), id_);
    }
    CAMERA_LOGD("CameraHalHicollie SetTimer name:%{public}s id:%{public}d", name.c_str(), id_);
}

CameraHalHicollie::~CameraHalHicollie()
{
    if (id_ >= NUMBER_ZERO) {
        HiviewDFX::XCollie::GetInstance().CancelTimer(id_);
        CAMERA_LOGD("CameraHalHicollie CancelTimer id:%{public}d", id_);
    }
}

}