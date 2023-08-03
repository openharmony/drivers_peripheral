/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "camera.h"
#include "camera_host_fuzzer.h"
#include "v1_1/icamera_host.h"

namespace OHOS {

const size_t THRESHOLD = 10;
bool CameraHostFuzzTest(const uint8_t *rawData, size_t size)
{
    (void)size;
    bool result = false;
    if (rawData == nullptr) {
        return false;
    }

    sptr<HDI::Camera::V1_1::ICameraHost> g_cameraHost = nullptr;
    if (g_cameraHost->Prelaunch(reinterpret_cast<const HDI::Camera::V1_1::PrelaunchConfig&>(rawData))) {
        result = true;
    }

    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::CameraHostFuzzTest(data, size);
    return 0;
}
}
