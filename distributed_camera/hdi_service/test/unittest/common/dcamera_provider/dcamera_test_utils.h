/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DCAMERA_TEST_UTILS_H
#define OHOS_DCAMERA_TEST_UTILS_H

#include <v1_1/id_camera_provider.h>

namespace OHOS {
namespace HDI {
namespace DistributedCamera {
namespace V1_1 {
class MockIDCameraHdfCallback : public IDCameraHdfCallback {
public:
    virtual ~MockIDCameraHdfCallback() = default;

    int32_t NotifyEvent(int32_t devId, const DCameraHDFEvent& event) override
    {
        return 0;
    }
};
} // V1_1
} // DistributedCamera
} // HDI
} // OHOS
#endif // OHOS_DCAMERA_TEST_UTILS_H