/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DISPLAY_TEST_UTILS_H
#define DISPLAY_TEST_UTILS_H
#include <vector>
#include "display_test.h"
namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_0;

constexpr uint8_t BITS_PER_BYTE = 16;
constexpr uint32_t DISPLAY_DEAULT_W = 480;
constexpr uint32_t DISPLAY_DEAULT_H = 960;
constexpr uint32_t RED = 0xff0000ff;
constexpr uint32_t GREEN = 0x00ff00ff;
constexpr uint32_t BLUE = 0x0000ffff;
constexpr uint32_t TRANSPARENT = 0;
constexpr uint32_t YELLOW = 0xffff29ff;
constexpr uint32_t PINK = 0xffc0cbff;
constexpr uint32_t PURPLE = 0x800080ff;
constexpr uint32_t CYAN = 0x00ffffff;

struct FRect {
    float x = 0;
    float y = 0;
    float w = 0; // ratio
    float h = 0; // ratio
};

struct BufferRatio {
    float w;
    float h;
};

struct Size {
    uint32_t w;
    uint32_t h;
};

struct LayerSettings {
    IRect displayRect;
    IRect displayCrop;
    FRect rectRatio = { 0.0f };
    uint32_t color;
    uint32_t zorder = 0;
    Size bufferSize = { 0 };
    BufferRatio bufferRatio { 0 };
    int32_t alpha = -1;
    CompositionType compositionType = COMPOSITION_DEVICE;
    BlendType blendType = BLEND_SRC;
    TransformType rotate = ROTATE_NONE;
};

struct TestParemeter {
    static TestParemeter &GetInstance()
    {
        static TestParemeter instance;
        return instance;
    }
    int32_t mTestSleep = 0;
};

using LayersSetting = std::vector<LayerSettings>;

void SaveFile(const char *fileName, uint8_t *data, int size);
void SetUint32(uint32_t &dst, uint32_t value);
void SetPixel(const BufferHandle &handle, int x, int y, uint32_t color);
void ClearColor(const BufferHandle &handle, uint32_t color);
uint32_t GetPixelValue(const BufferHandle &handle, int x, int y);
uint32_t CheckPixel(const BufferHandle &handle, int x, int y, uint32_t color);
std::vector<IRect> SplitBuffer(const BufferHandle &handle, std::vector<uint32_t> &colors);
} // OHOS
} // HDI
} // Display
} // TEST

#endif // HDI_TEST_RENDER_UTILS_H
