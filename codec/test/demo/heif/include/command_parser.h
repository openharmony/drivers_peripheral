/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_HDI_CODEC_IMAGE_V2_1_COMMAND_PARSER
#define OHOS_HDI_CODEC_IMAGE_V2_1_COMMAND_PARSER

#include <string>
#include <vector>

namespace OHOS::VDI::HEIF {
enum ImageMirror {
    HORIZONTAL,
    VERTICAL,
    NONE
};

enum class ImageRotation {
    ANTI_CLOCKWISE_90,
    ANTI_CLOCKWISE_180,
    ANTI_CLOCKWISE_270,
    NONE
};

enum class SampleSize {
    SAMPLE_SIZE_1 = 1,
    SAMPLE_SIZE_2 = 2,
    SAMPLE_SIZE_4 = 4,
    SAMPLE_SIZE_8 = 8,
    SAMPLE_SIZE_16 = 16,
};

enum class UserPixelFormat {
    NV12 = 0,
    NV21,
    NV12_10BIT,
    NV21_10BIT,
    RGBA8888,
    BGRA8888,
    RGB565,
    RGBA1010102,
    NONE
};

enum class ColorSpace {
    BT_601_P,
    BT_601_N,
    P3,
    BT_709,
    BT_2020
};

struct CommandOpt {
    // common
    bool isGetHelpInfoOnly = false;
    bool isEncoder = true;
    // for encoder
    std::string primaryImgPath = "";
    std::string auxiliaryImgPath = "";
    std::string thumbnailImgPath = "";
    std::string gainMapPath = "";
    std::string exifDataPath = "";
    std::string userDataPath = "";
    std::string iccProfilePath = "";
    std::string it35Path = "";
    std::string outputPath = "/storage/media/100/local/files/heif_edit_dump";
    ImageMirror mirrorInfo = ImageMirror::NONE;
    ImageRotation rotateInfo = ImageRotation::NONE;
    // for decoder
    std::string inputPath = "";
    SampleSize sampleSize = SampleSize::SAMPLE_SIZE_1;
    UserPixelFormat pixelFmt = UserPixelFormat::NV12;
    bool isLimitedRange = true;
    ColorSpace colorSpace = ColorSpace::BT_601_P;

    void Print() const;
    void PrintEncoderParam() const;
    void PrintDecoderParam() const;
};

CommandOpt Parse(int argc, char *argv[]);
void ShowUsage();
} // OHOS::VDI::HEIF
#endif // OHOS_HDI_CODEC_IMAGE_V2_1_COMMAND_PARSER