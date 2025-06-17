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

struct CommandOpt {
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

    void Print() const;
};

CommandOpt Parse(int argc, char *argv[]);
void ShowUsage();
} // OHOS::VDI::HEIF
#endif // OHOS_HDI_CODEC_IMAGE_V2_1_COMMAND_PARSER