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

#ifndef OHOS_VDI_CAMERA_V1_0_ISTREAMOPERATORVDICALLBACK_H
#define OHOS_VDI_CAMERA_V1_0_ISTREAMOPERATORVDICALLBACK_H

#include <stdint.h>
#include <vector>
#include <hdf_base.h>
#include <hdi_base.h>
#include "v1_0/vdi_types.h"

namespace OHOS {
namespace VDI {
namespace Camera {
namespace V1_0 {
using namespace OHOS;
using namespace OHOS::HDI;

class IStreamOperatorVdiCallback : public HdiBase {
public:

    virtual ~IStreamOperatorVdiCallback() = default;

    virtual int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamIds) = 0;

    virtual int32_t OnCaptureEnded(int32_t captureId, const std::vector<VdiCaptureEndedInfo> &infos) = 0;

    virtual int32_t OnCaptureError(int32_t captureId, const std::vector<VdiCaptureErrorInfo> &infos) = 0;

    virtual int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t> &streamIds, uint64_t timestamp) = 0;
};
} // V1_0
} // Camera
} // VDI
} // OHOS

#endif // OHOS_VDI_CAMERA_V1_0_ISTREAMOPERATORVDICALLBACK_H