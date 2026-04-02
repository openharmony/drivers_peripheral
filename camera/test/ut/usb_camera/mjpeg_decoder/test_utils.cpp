/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "test_utils.h"
#include <cmath>
#include <iostream>

extern "C" {
#include <turbojpeg.h>
}

namespace OHOS::Camera {

std::vector<uint8_t> GenerateJPEGWithTurboJpeg(int width, int height, int quality)
{
    std::vector<uint8_t> jpegData;
    std::vector<uint8_t> yuvData(width * height * NV21_SCALE_FACTOR / NV21_DIVISOR);

    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            uint8_t value = static_cast<uint8_t>((x + y) * PIXEL_MAX_VALUE / (width + height));
            yuvData[y * width + x] = value;
        }
    }

    size_t uvOffset = width * height;
    for (size_t i = uvOffset; i < yuvData.size(); i++) {
        yuvData[i] = YUV_DEFAULT_VALUE;
    }

    tjhandle tjInstance = tjInitCompress();
    if (!tjInstance) {
        std::cerr << "Failed to initialize TurboJPEG" << std::endl;
        return {};
    }

    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    int result = tjCompressFromYUV(tjInstance, yuvData.data(), width, 1, height,
        TJSAMP_420, &jpegBuf, &jpegSize, quality, TJFLAG_FASTDCT);
    if (result == 0 && jpegBuf != nullptr && jpegSize > 0) {
        jpegData.assign(jpegBuf, jpegBuf + jpegSize);
        tjFree(jpegBuf);
    }

    tjDestroy(tjInstance);
    return jpegData;
}

} // namespace OHOS::Camera
