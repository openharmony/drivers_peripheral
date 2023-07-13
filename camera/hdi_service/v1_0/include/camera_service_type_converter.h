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

#ifndef CAMERA_SERVICE_TYPE_CONVERTER_H
#define CAMERA_SERVICE_TYPE_CONVERTER_H

#include "v1_0/types.h"
#include "v1_0/vdi_types.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

void ConvertStreamInfoHdiToVdi(const StreamInfo &src, VdiStreamInfo &dst);

void ConvertStreamAttributeHdiToVdi(const StreamAttribute &src, VdiStreamAttribute &dst);

void ConvertCaptureInfoHdiToVdi(const CaptureInfo &src, VdiCaptureInfo &dst);

void ConvertCaptureEndedInfoHdiToVdi(const CaptureEndedInfo &src, VdiCaptureEndedInfo &dst);

void ConvertCaptureErrorInfoHdiToVdi(const CaptureErrorInfo &src, VdiCaptureErrorInfo &dst);

void ConvertStreamInfoVdiToHdi(const VdiStreamInfo &src, StreamInfo &dst);

void ConvertStreamAttributeVdiToHdi(const VdiStreamAttribute &src, StreamAttribute &dst);

void ConvertCaptureInfoVdiToHdi(const VdiCaptureInfo &src, CaptureInfo &dst);

void ConvertCaptureEndedInfoVdiToHdi(const VdiCaptureEndedInfo &src, CaptureEndedInfo &dst);

void ConvertCaptureErrorInfoVdiToHdi(const VdiCaptureErrorInfo &src, CaptureErrorInfo &dst);

} // end namespace OHOS::Camera
#endif // CAMERA_SERVICE_TYPE_CONVERTER_H
