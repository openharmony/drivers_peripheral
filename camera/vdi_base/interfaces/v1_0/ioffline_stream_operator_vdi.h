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

#ifndef OHOS_HDI_CAMERA_V1_0_IOFFLINESTREAMOPERATORVDI_H
#define OHOS_HDI_CAMERA_V1_0_IOFFLINESTREAMOPERATORVDI_H

#include <stdint.h>
#include <vector>
#include <hdf_base.h>
#include <hdi_base.h>
#include "v1_0/types.h"

#define IOFFLINE_STREAM_OPERATOR_VDI_MAJOR_VERSION 1
#define IOFFLINE_STREAM_OPERATOR_VDI_MINOR_VERSION 0

namespace OHOS {
namespace VDI {
namespace Camera {
namespace V1_0 {
using namespace OHOS;
using namespace OHOS::HDI;
using namespace OHOS::HDI::Camera::V1_0;

class IOfflineStreamOperatorVdi : public HdiBase {
public:
    virtual ~IOfflineStreamOperatorVdi() = default;

    virtual int32_t CancelCapture(int32_t captureId) = 0;

    virtual int32_t ReleaseStreams(const std::vector<int32_t> &streamIds) = 0;

    virtual int32_t Release() = 0;

    virtual int32_t GetVersion(uint32_t &majorVer, uint32_t &minorVer)
    {
        majorVer = IOFFLINE_STREAM_OPERATOR_VDI_MAJOR_VERSION;
        minorVer = IOFFLINE_STREAM_OPERATOR_VDI_MINOR_VERSION;
        return HDF_SUCCESS;
    }
};
} // V1_0
} // Camera
} // VDI
} // OHOS

#endif // OHOS_HDI_CAMERA_V1_0_IOFFLINESTREAMOPERATORVDI_H
