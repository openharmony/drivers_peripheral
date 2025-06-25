/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cmath>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include "display_test.h"
#include "buffer_handle.h"

#include "v1_3/display_composer_type.h"
#include "v1_0/include/idisplay_buffer.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;

const uint8_t BITS_PER_BYTE = 8;

static uint32_t BGRAToRGBA(uint32_t bgra)
{
    uint32_t rgba = 0;
    const uint32_t COLOR_RED = 0x0000ff00;
    const uint32_t COLOR_GREEN = 0x00ff0000;
    const uint32_t COLOR_BLUE = 0xff000000;
    const uint32_t ALPHA = 0x000000ff;
    const int32_t TWO_BYTE_OFFSET = 16;

    rgba |= (bgra & COLOR_RED) << TWO_BYTE_OFFSET; // get red then move to rgba
    rgba |= (bgra & COLOR_GREEN);                  // get green
    rgba |= (bgra & COLOR_BLUE) >> TWO_BYTE_OFFSET; // get blue then move to rgba
    rgba |= (bgra & ALPHA);                  // get alpha

    return rgba;
}

static int32_t GetPixelFormatBpp(Composer::V1_0::PixelFormat format)
{
    const int32_t BPP_RGBA_8888 = 32;
    switch (format) {
        case Composer::V1_0::PIXEL_FMT_RGBA_8888:
            return BPP_RGBA_8888;
        case Composer::V1_0::PIXEL_FMT_BGRA_8888:
            return BPP_RGBA_8888;
        default:
            return -1;
    }
}

void SaveFile(const char *fileName, uint8_t *data, int size)
{
    if (fileName != nullptr && data != nullptr) {
        int fileFd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        if (fileFd <= 0) {
            DISPLAY_TEST_LOGE("Open file failed %{public}d", fileFd);
            return;
        }

        int hasWriten = write(fileFd, data, size);
        DISPLAY_TEST_LOGD("SaveFile hasWriten %{public}d", hasWriten);
        close(fileFd);
    } else {
        DISPLAY_TEST_LOGE("SaveFile failed");
    }
}

static uint32_t ConverToRGBA(Composer::V1_0::PixelFormat fmt, uint32_t color)
{
    switch (fmt) {
        case Composer::V1_0::PIXEL_FMT_BGRA_8888:
            return BGRAToRGBA(color);
        case Composer::V1_0::PIXEL_FMT_RGBA_8888:
            return color;
        default:
            DISPLAY_TEST_LOGE("the fmt can not convert %{public}d", fmt);
    }
    return color;
}

uint32_t GetPixelValue(const BufferHandle &handle, int x, int y)
{
    const int32_t PIXEL_BYTES = 4;
    int32_t bpp = GetPixelFormatBpp((Composer::V1_0::PixelFormat)handle.format);
    DISPLAY_TEST_CHK_RETURN((bpp <= 0), 0, DISPLAY_TEST_LOGE("CheckPixel do not support format %{public}d",
        handle.format));
    DISPLAY_TEST_CHK_RETURN((handle.virAddr == nullptr), 0,
        DISPLAY_TEST_LOGE("CheckPixel viraddr is null must map it"));
    DISPLAY_TEST_CHK_RETURN((x < 0 || x >= handle.width), 0,
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter x:%{public}d width:%{public}d", x, handle.width));
    DISPLAY_TEST_CHK_RETURN((y < 0 || y >= handle.height), 0,
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter y:%{public}d height:%{public}d", y, handle.height));

    int32_t position = y * handle.width + x;
    if ((position * PIXEL_BYTES) > handle.size) {
        DISPLAY_TEST_LOGE("the pixel position outside\n");
    }
    uint32_t *pixel = reinterpret_cast<uint32_t *>(handle.virAddr) + position;
    DISPLAY_TEST_CHK_RETURN((pixel == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("get pixel failed"));

    return *pixel;
}

uint32_t GetUint32(uint32_t value)
{
    uint32_t dst;
    uint8_t *data = reinterpret_cast<uint8_t *>(&dst);
    for (uint8_t i = 0; i < sizeof(uint32_t); i++) {
        *(data + i) = (value >> ((sizeof(uint32_t) - i - 1) * BITS_PER_BYTE)) & 0xff;
    }
    return dst;
}

uint32_t CheckPixel(const BufferHandle &handle, int x, int y, uint32_t color)
{
    const int32_t PIXEL_BYTES = 4;
    int32_t bpp = GetPixelFormatBpp(static_cast<Composer::V1_0::PixelFormat>(handle.format));
    DISPLAY_TEST_CHK_RETURN((bpp <= 0), 0, DISPLAY_TEST_LOGE("CheckPixel do not support format %{public}d",
        handle.format));
    DISPLAY_TEST_CHK_RETURN((handle.virAddr == nullptr), 0,
        DISPLAY_TEST_LOGE("CheckPixel viraddr is null must map it"));
    DISPLAY_TEST_CHK_RETURN((x < 0 || x >= handle.width), 0,
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter x:%{public}d width:%{public}d", x, handle.width));
    DISPLAY_TEST_CHK_RETURN((y < 0 || y >= handle.height), 0,
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter y:%{public}d height:%{public}d", y, handle.height));

    int32_t position = y * handle.width + x;
    if ((position * PIXEL_BYTES) > handle.size) {
        DISPLAY_TEST_LOGE("the pixel position outside\n");
    }
    uint32_t *pixel = reinterpret_cast<uint32_t *>(handle.virAddr) + position;
    DISPLAY_TEST_CHK_RETURN((pixel == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("get pixel failed"));

    uint32_t checkColor = ConverToRGBA(static_cast<Composer::V1_0::PixelFormat>(handle.format), GetUint32(*pixel));
    if (checkColor != color) {
        DISPLAY_TEST_LOGD("x:%{public}d y:%{public}d width:%{public}d", x, y, handle.width);
        SaveFile("/data/display_test_bitmap_", static_cast<uint8_t *>(handle.virAddr), handle.size);
        return DISPLAY_FAILURE;
    }
    return DISPLAY_SUCCESS;
}

void SetUint32(uint32_t &dst, uint32_t value)
{
    uint8_t *data = reinterpret_cast<uint8_t *>(&dst);
    if (data != nullptr) {
        for (uint8_t i = 0; i < sizeof(uint32_t); i++) {
            *(data + i) = (value >> ((sizeof(uint32_t) - i - 1) * BITS_PER_BYTE)) & 0xff;
        }
    } else {
        DISPLAY_TEST_LOGE("SetUint32 failed");
    }
}

void SetPixel(const BufferHandle &handle, int x, int y, uint32_t color)
{
    const int32_t PIXEL_BYTES = 4;
    const int32_t BPP = 32;
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((BPP <= 0),
        DISPLAY_TEST_LOGE("CheckPixel do not support format %{public}d", handle.format));
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((handle.virAddr == nullptr),
        DISPLAY_TEST_LOGE("CheckPixel viraddr is null must map it"));
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((x < 0 || x >= handle.width),
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter x:%{public}d width:%{public}d", x, handle.width));
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((y < 0 || y >= handle.height),
        DISPLAY_TEST_LOGE("CheckPixel invalid parameter y:%{public}d height:%{public}d", y, handle.height));

    int32_t position = y * handle.stride / PIXEL_BYTES + x;
    if ((position * PIXEL_BYTES) > handle.size) {
        DISPLAY_TEST_LOGE("the pixel position outside\n");
    }
    uint32_t *pixel = reinterpret_cast<uint32_t *>(handle.virAddr) + position;
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((pixel == nullptr), DISPLAY_TEST_LOGE("get pixel failed"));

    SetUint32(*pixel, color);
}

void ClearColor(const BufferHandle &handle, uint32_t color)
{
    for (int32_t x = 0; x < handle.width; x++) {
        for (int32_t y = 0; y < handle.height; y++) {
            SetPixel(handle, x, y, color);
        }
    }
}

void ClearColorRect(const BufferHandle &handle, uint32_t color, const IRect &rect)
{
    DISPLAY_TEST_LOGD("x %{public}d, y %{public}d w %{public}d h %{public}d color %x ", rect.x, rect.y, rect.w, rect.h,
        color);
    for (int32_t x = 0; x < rect.w; x++) {
        for (int32_t y = 0; y < rect.h; y++) {
            SetPixel(handle, x + rect.x, y + rect.y, color);
        }
    }
}

std::vector<IRect> SplitBuffer(const BufferHandle &handle, std::vector<uint32_t> &colors)
{
    std::vector<IRect> splitRects;
    if (colors.empty()) {
        DISPLAY_TEST_LOGD("the colors empty");
    }
    const uint32_t ROW_NUM = sqrt(colors.size());
    const uint32_t COL_NUM = ROW_NUM;
    if (ROW_NUM == 0) {
        DISPLAY_TEST_LOGD("ROW_NUM is zero");
        return splitRects;
    }

    const uint32_t CELL_WIDTH = handle.width / ROW_NUM;
    const uint32_t CELL_HEIGHT = handle.height / COL_NUM;
    IRect rect = { 0, 0, CELL_WIDTH, CELL_HEIGHT };
    DISPLAY_TEST_LOGD("ROW_NUM %{public}u, COL_NUM %{public}u CELL_WIDTH %{public}u CELL_HEIGHT %{public}u",
        ROW_NUM, COL_NUM, CELL_WIDTH, CELL_HEIGHT);
    uint32_t count = 0;
    for (uint32_t x = 0; x < ROW_NUM; x++) {
        for (uint32_t y = 0; y < COL_NUM; y++) {
            rect.x = x * CELL_WIDTH;
            rect.y = y * CELL_HEIGHT;
            ClearColorRect(handle, colors[count++], rect);
            splitRects.push_back(rect);
        }
    }
    SaveFile("/data/splitbuffer_data_", static_cast<uint8_t *>(handle.virAddr), handle.size);
    return splitRects;
}
} // OHOS
} // HDI
} // Display
} // TEST
