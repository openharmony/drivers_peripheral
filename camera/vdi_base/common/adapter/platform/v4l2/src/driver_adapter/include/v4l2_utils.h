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

#ifndef HOS_CAMERA_V4L2_UTILS_H
#define HOS_CAMERA_V4L2_UTILS_H

#include <map>
#include <camera.h>
#include <linux/videodev2.h>

namespace OHOS::Camera {

static const std::map<CameraBufferFormat, uint32_t> ohos_mapPixFmtHal2V4l2 = {
    { CAMERA_FORMAT_RGBX_4444, V4L2_PIX_FMT_RGBX444 },
    { CAMERA_FORMAT_RGB_888, V4L2_PIX_FMT_RGB24 },
#ifdef V4L2_EMULATOR
    { CAMERA_FORMAT_RGBA_8888, V4L2_PIX_FMT_RGBA32 },
#endif
    { CAMERA_FORMAT_YCRCB_422_SP, V4L2_PIX_FMT_NV61M },
    { CAMERA_FORMAT_YCBCR_422_P, V4L2_PIX_FMT_NV16 },
    { CAMERA_FORMAT_YCRCB_422_P, V4L2_PIX_FMT_NV61 },
    { CAMERA_FORMAT_YCBCR_420_P, V4L2_PIX_FMT_NV12 },
    { CAMERA_FORMAT_YCRCB_420_P, V4L2_PIX_FMT_NV21 },
    { CAMERA_FORMAT_YUYV_422_PKG, V4L2_PIX_FMT_YUYV },
    { CAMERA_FORMAT_UYVY_422_PKG, V4L2_PIX_FMT_UYVY },
    { CAMERA_FORMAT_VYUY_422_PKG, V4L2_PIX_FMT_VYUY },
};

class V4L2Utils {
public:
    static uint32_t ConvertPixfmtHal2V4l2(CameraBufferFormat halPixfmt)
    {
        auto it = ohos_mapPixFmtHal2V4l2.find(halPixfmt);
        if (it == ohos_mapPixFmtHal2V4l2.end()) {
            CAMERA_LOGI("The halPixfmt is not find in ohos_mapPixFmtHal2V4l2");
            return V4L2_PIX_FMT_YUV420; // default value
        }
        return it->second;
    }

    V4L2Utils() {}
    ~V4L2Utils() {}
};
} // namespace OHOS::Camera
#endif // HOS_CAMERA_V4L2_UTILS_H
