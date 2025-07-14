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
#include <map>
#include "display_format.h"
#include "ibuffer.h"
#include "camera_hal_hisysevent.h"

namespace OHOS::Camera {
const std::unordered_map<PixelFormat, uint32_t> pixelFormatToCameraFormat_ = {
    {PIXEL_FMT_YUV_422_I,    CAMERA_FORMAT_YUV_422_I},
    {PIXEL_FMT_YCBCR_422_SP, CAMERA_FORMAT_YCBCR_422_SP},
    {PIXEL_FMT_YCRCB_422_SP, CAMERA_FORMAT_YCRCB_422_SP},
    {PIXEL_FMT_YCBCR_420_SP, CAMERA_FORMAT_YCBCR_420_SP},
    {PIXEL_FMT_YCRCB_420_SP, CAMERA_FORMAT_YCRCB_420_SP},
    {PIXEL_FMT_YCBCR_422_P,  CAMERA_FORMAT_YCBCR_422_P},
    {PIXEL_FMT_YCRCB_422_P,  CAMERA_FORMAT_YCRCB_422_P},
    {PIXEL_FMT_YCBCR_420_P,  CAMERA_FORMAT_YCBCR_420_P},
    {PIXEL_FMT_YCRCB_420_P,  CAMERA_FORMAT_YCRCB_420_P},
    {PIXEL_FMT_YUYV_422_PKG, CAMERA_FORMAT_YUYV_422_PKG},
    {PIXEL_FMT_UYVY_422_PKG, CAMERA_FORMAT_UYVY_422_PKG},
    {PIXEL_FMT_YVYU_422_PKG, CAMERA_FORMAT_YVYU_422_PKG},
    {PIXEL_FMT_VYUY_422_PKG, CAMERA_FORMAT_VYUY_422_PKG},
    {PIXEL_FMT_RGBA_8888,    CAMERA_FORMAT_RGBA_8888}
};

const std::unordered_map<uint32_t, PixelFormat> cameraFormatToPixelFormat_ = {
    {CAMERA_FORMAT_YUV_422_I,    PIXEL_FMT_YUV_422_I},
    {CAMERA_FORMAT_YCBCR_422_SP, PIXEL_FMT_YCBCR_422_SP},
    {CAMERA_FORMAT_YCRCB_422_SP, PIXEL_FMT_YCRCB_422_SP},
    {CAMERA_FORMAT_YCBCR_420_SP, PIXEL_FMT_YCBCR_420_SP},
    {CAMERA_FORMAT_YCRCB_420_SP, PIXEL_FMT_YCRCB_420_SP},
    {CAMERA_FORMAT_YCBCR_422_P,  PIXEL_FMT_YCBCR_422_P},
    {CAMERA_FORMAT_YCRCB_422_P,  PIXEL_FMT_YCRCB_422_P},
    {CAMERA_FORMAT_YCBCR_420_P,  PIXEL_FMT_YCBCR_420_P},
    {CAMERA_FORMAT_YCRCB_420_P,  PIXEL_FMT_YCRCB_420_P},
    {CAMERA_FORMAT_YUYV_422_PKG, PIXEL_FMT_YUYV_422_PKG},
    {CAMERA_FORMAT_UYVY_422_PKG, PIXEL_FMT_UYVY_422_PKG},
    {CAMERA_FORMAT_YVYU_422_PKG, PIXEL_FMT_YVYU_422_PKG},
    {CAMERA_FORMAT_VYUY_422_PKG, PIXEL_FMT_VYUY_422_PKG},
    {CAMERA_FORMAT_RGBA_8888,    PIXEL_FMT_RGBA_8888}
};

class BufferAdapter {
public:
    // convert surfae buffer to camera ibuffer, only for external buffer.
    static RetCode SurfaceBufferToCameraBuffer(const OHOS::sptr<OHOS::SurfaceBuffer>& surfaceBuffer,
                                               const std::shared_ptr<IBuffer>& buffer);

    // convert camera ibuffer to surface buffer, only for external buffer.
    // It may lose information of surface buffer, call this function with caution.
    static RetCode CameraBufferToSurfaceBuffer(const std::shared_ptr<IBuffer>& buffer,
                                               const OHOS::sptr<OHOS::SurfaceBuffer>& surfaceBuffer);
    static RetCode SetExtInfoToSurfaceBuffer(const std::shared_ptr<IBuffer>& buffer,
                                               const OHOS::sptr<OHOS::SurfaceBuffer>& surfaceBuffer);

    // convert camera format to pixel format. inline implementation to avoid duplicate code
    static PixelFormat CameraFormatToPixelFormat(const uint32_t cameraFormat)
    {
        PixelFormat format = PIXEL_FMT_YCRCB_420_P;
        auto itr = cameraFormatToPixelFormat_.find(cameraFormat);
        if (itr != cameraFormatToPixelFormat_.end()) {
            format = itr->second;
        } else {
            CameraHalHisysevent::WriteFaultHisysEvent(CameraHalHisysevent::GetEventName(TYPE_CAST_ERROR),
                CameraHalHisysevent::CreateMsg("CameraFormatToPixelFormat failed cameraFormat:%d", cameraFormat));
            CAMERA_LOGI("not find cameraFormat = %{public}u, use default format", cameraFormat);
        }
        CAMERA_LOGD("CameraFormatToPixelFormat: %{public}u -> %{public}u", cameraFormat, format);
        return format;
    }
    // convert pixel format to camera format. inline implementation to avoid duplicate code
    static uint32_t PixelFormatToCameraFormat(const PixelFormat format)
    {
        uint32_t cameraFormat = CAMERA_FORMAT_YCRCB_420_P;
        auto itr = pixelFormatToCameraFormat_.find(format);
        if (itr != pixelFormatToCameraFormat_.end()) {
            cameraFormat = itr->second;
        } else {
            CameraHalHisysevent::WriteFaultHisysEvent(CameraHalHisysevent::GetEventName(TYPE_CAST_ERROR),
                CameraHalHisysevent::CreateMsg("PixelFormatToCameraFormat failed format:%d", format));
            CAMERA_LOGI("not find format = %{public}u, use default format", static_cast<uint32_t>(format));
        }
        CAMERA_LOGD("PixelFormatToCameraFormat: %{public}u -> %{public}u", format, cameraFormat);
        return cameraFormat;
    }

    // convert camera usage to gralloc usage.
    static uint64_t CameraUsageToGrallocUsage(const uint64_t cameraUsage);

    // convert gralloc usage to camera usage.
    static uint64_t GrallocUsageToCameraUsage(const uint64_t usage);
};
} // namespace OHOS::Camera
#endif
