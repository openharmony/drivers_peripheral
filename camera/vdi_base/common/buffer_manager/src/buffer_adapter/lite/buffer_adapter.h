/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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

#ifndef HOS_CAMERA_BUFFER_ADAPTER_H
#define HOS_CAMERA_BUFFER_ADAPTER_H

#include <surface_buffer.h>
#include <memory>
#include "display_format.h"
#include "ibuffer.h"
#include "surface.h"

namespace OHOS::Camera {
class BufferAdapter {
public:
    // convert surfae buffer to camera ibuffer, only for external buffer.
    static RetCode SurfaceBufferToCameraBuffer(const OHOS::SurfaceBuffer* surfaceBuffer,
                                               const std::shared_ptr<OHOS::Surface>& surface,
                                               const std::shared_ptr<IBuffer>& buffer);

    static RetCode SetExtInfoToSurfaceBuffer(const std::shared_ptr<IBuffer>& buffer,
                                               const std::shared_ptr<OHOS::SurfaceBuffer>& surfaceBuffer);

    // convert camera format to pixel format.
    static uint32_t CameraFormatToPixelFormat(const uint32_t cameraFormat);
    // convert pixel format to camera format.
    static uint32_t PixelFormatToCameraFormat(const uint32_t format);

    // convert camera usage to gralloc usage.
    static uint64_t CameraUsageToGrallocUsage(const uint64_t cameraUsage);

    // convert gralloc usage to camera usage.
    static uint64_t GrallocUsageToCameraUsage(const uint64_t usage);
};
} // namespace OHOS::Camera
#endif
