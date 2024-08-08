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

#include <getopt.h>
#include <iostream>
#include "command_parser.h"

namespace OHOS::VDI::HEIF {
using namespace std;

enum ShortOption {
    OPT_UNKONWN = 0,
    OPT_HELP,
    OPT_PRIMARY_IMG,
    OPT_AUXILIARY_IMG,
    OPT_THUMBNAIL_IMG,
    OPT_GAIN_MAP,
    OPT_EXIF_DATA,
    OPT_USER_DATA,
    OPT_ICC_PROFILE,
    OPT_IT35,
    OPT_MIRROR,
    OPT_ROTATE,
    OPT_OUTPUT = 'o'
};

static struct option g_longOptions[] = {
    {"help",            no_argument,        nullptr, static_cast<int>(ShortOption::OPT_HELP)},
    {"primaryImg",      required_argument,  nullptr, static_cast<int>(ShortOption::OPT_PRIMARY_IMG)},
    {"auxiliaryImg",    required_argument,  nullptr, static_cast<int>(ShortOption::OPT_AUXILIARY_IMG)},
    {"thumbnailImg",    required_argument,  nullptr, static_cast<int>(ShortOption::OPT_THUMBNAIL_IMG)},
    {"gainMap",         required_argument,  nullptr, static_cast<int>(ShortOption::OPT_GAIN_MAP)},
    {"exifData",        required_argument,  nullptr, static_cast<int>(ShortOption::OPT_EXIF_DATA)},
    {"userData",        required_argument,  nullptr, static_cast<int>(ShortOption::OPT_USER_DATA)},
    {"iccProfile",      required_argument,  nullptr, static_cast<int>(ShortOption::OPT_ICC_PROFILE)},
    {"it35",            required_argument,  nullptr, static_cast<int>(ShortOption::OPT_IT35)},
    {"mirror",          required_argument,  nullptr, static_cast<int>(ShortOption::OPT_MIRROR)},
    {"rotate",          required_argument,  nullptr, static_cast<int>(ShortOption::OPT_ROTATE)},
    {"out",             required_argument,  nullptr, static_cast<int>(ShortOption::OPT_OUTPUT)},
    {nullptr,           no_argument,        nullptr, static_cast<int>(ShortOption::OPT_UNKONWN)},
};

void ShowUsage()
{
    std::string rotateValueOpt = "0: ANTI_CLOCKWISE_90, 1: ANTI_CLOCKWISE_180, 2: ANTI_CLOCKWISE_270";
    std::cout << "Heif Hardware encode Demo Options:" << std::endl;
    std::cout << " --help               help info." << std::endl;
    std::cout << " --primaryImg         full path for primary image file." << std::endl;
    std::cout << " --auxiliaryImg       (optional) full path for auxiliary image file." << std::endl;
    std::cout << " --thumbnailImg       (optional) full path for thumbnail image file." << std::endl;
    std::cout << " --gainMap            (optional) full path for gainMap file." << std::endl;
    std::cout << " --exifData           (optional) full path for exifData file." << std::endl;
    std::cout << " --userData           (optional) full path for userData file." << std::endl;
    std::cout << " --iccProfile         (optional) full path for iccProfile file." << std::endl;
    std::cout << " --it35               (optional) full path for it35 file." << std::endl;
    std::cout << " --mirror             (optional) image mirror info. 0: HORIZONTAL, 1: VERTICAL" << std::endl;
    std::cout << " --rotate             (optional) image rotate info. " << rotateValueOpt << std::endl;
    std::cout << " -o, --out            (optional) full path for output file." << std::endl;
}

CommandOpt Parse(int argc, char *argv[])
{
    CommandOpt opt;
    int c;
    while ((c = getopt_long(argc, argv, "o:", g_longOptions, nullptr)) != -1) {
        switch (static_cast<ShortOption>(c)) {
            case ShortOption::OPT_HELP:
                ShowUsage();
                break;
            case ShortOption::OPT_PRIMARY_IMG:
                opt.primaryImgPath = string(optarg);
                break;
            case ShortOption::OPT_AUXILIARY_IMG:
                opt.auxiliaryImgPath = string(optarg);
                break;
            case ShortOption::OPT_THUMBNAIL_IMG:
                opt.thumbnailImgPath = string(optarg);
                break;
            case ShortOption::OPT_GAIN_MAP:
                opt.gainMapPath = string(optarg);
                break;
            case ShortOption::OPT_EXIF_DATA:
                opt.exifDataPath = string(optarg);
                break;
            case ShortOption::OPT_USER_DATA:
                opt.userDataPath = string(optarg);
                break;
            case ShortOption::OPT_ICC_PROFILE:
                opt.iccProfilePath = string(optarg);
                break;
            case ShortOption::OPT_IT35:
                opt.it35Path = string(optarg);
                break;
            case ShortOption::OPT_MIRROR:
                opt.mirrorInfo = static_cast<ImageMirror>(stol(optarg));
                break;
            case ShortOption::OPT_ROTATE:
                opt.rotateInfo = static_cast<ImageRotation>(stol(optarg));
                break;
            case ShortOption::OPT_OUTPUT:
                opt.outputPath = string(optarg);
                break;
            default:
                break;
        }
    }
    return opt;
}

static string GetMirrorPrintInfo(ImageMirror info)
{
    if (info == ImageMirror::NONE) {
        return "ImageMirror::NONE";
    }
    if (info == ImageMirror::HORIZONTAL) {
        return "ImageMirror::HORIZONTAL";
    }
    if (info == ImageMirror::VERTICAL) {
        return "ImageMirror::VERTICAL";
    }
    return "unknown mirror info";
}

static string GetRotatePrintInfo(ImageRotation info)
{
    if (info == ImageRotation::NONE) {
        return "ImageRotation::NONE";
    }
    if (info == ImageRotation::ANTI_CLOCKWISE_90) {
        return "ImageRotation::ANTI_CLOCKWISE_90";
    }
    if (info == ImageRotation::ANTI_CLOCKWISE_180) {
        return "ImageRotation::ANTI_CLOCKWISE_180";
    }
    if (info == ImageRotation::ANTI_CLOCKWISE_270) {
        return "ImageRotation::ANTI_CLOCKWISE_270";
    }
    return "unknown rotate info";
}

void CommandOpt::Print() const
{
    std::cout << "=========================== OPT INFO ===========================" << endl;
    std::cout << "   primaryImgPath : " << primaryImgPath << endl;
    std::cout << " auxiliaryImgPath : " << auxiliaryImgPath << endl;
    std::cout << " thumbnailImgPath : " << thumbnailImgPath << endl;
    std::cout << "      gainMapPath : " << gainMapPath << endl;
    std::cout << "     exifDataPath : " << exifDataPath << endl;
    std::cout << "     userDataPath : " << userDataPath << endl;
    std::cout << "   iccProfilePath : " << iccProfilePath << endl;
    std::cout << "         it35Path : " << it35Path << endl;
    std::cout << "       mirrorInfo : " << GetMirrorPrintInfo(mirrorInfo) << endl;
    std::cout << "       rotateInfo : " << GetRotatePrintInfo(rotateInfo) << endl;
    std::cout << "       outputPath : " << outputPath << endl;
    std::cout << "=================================================================" << endl;
}
}
