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

#ifndef CAMERA_HAL_HICOLLIE_H
#define CAMERA_HAL_HICOLLIE_H

#include <string>
#include "camera.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

namespace OHOS::Camera {

constexpr uint32_t TIMEOUT_SECOND = 10;
constexpr uint32_t NUMBER_ZERO = 0;

class CameraHalHicollie {
public:
    explicit CameraHalHicollie(const std::string &name, uint32_t timeout = TIMEOUT_SECOND,
        std::function<void (void *)> func = nullptr, void *arg = nullptr,
        uint32_t flag = (HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY));
    ~CameraHalHicollie();

private:
    int id_ = -1;
};

}  // namespace OHOS::Camera
#endif