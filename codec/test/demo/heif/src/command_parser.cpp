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
#include <map>
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
    OPT_OUTPUT = 'o',
    OPT_INPUT_PATH = 'i',
    OPT_SAMPLE_SIZE,
    OPT_PIXEL_FMT,
    OPT_IS_ENCODER,
    OPT_IS_LIMITED_RANGE,
    OPT_COLORSPACE
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
    {"inputPath",       required_argument,  nullptr, static_cast<int>(ShortOption::OPT_INPUT_PATH)},
    {"sampleSize",      required_argument,  nullptr, static_cast<int>(ShortOption::OPT_SAMPLE_SIZE)},
    {"pixelFmt",        required_argument,  nullptr, static_cast<int>(ShortOption::OPT_PIXEL_FMT)},
    {"isEncoder",       required_argument,  nullptr, static_cast<int>(ShortOption::OPT_IS_ENCODER)},
    {"isLimitedRange",  required_argument,  nullptr, static_cast<int>(ShortOption::OPT_IS_LIMITED_RANGE)},
    {"colorSpace",      required_argument,  nullptr, static_cast<int>(ShortOption::OPT_COLORSPACE)},
    {nullptr,           no_argument,        nullptr, static_cast<int>(ShortOption::OPT_UNKONWN)},
};

void ShowUsage()
{
    std::string rotateValueOpt = "0: ANTI_CLOCKWISE_90, 1: ANTI_CLOCKWISE_180, 2: ANTI_CLOCKWISE_270";
    std::string pixelFmtValueOpt = "0:NV12(default), 1:NV21, 2:NV12_10BIT, 3:NV21_10BIT, " \
                                   "4:RGBA8888, 5:BGRA8888, 6:RGB565, 7:RGBA1010102";
    std::string colorSpaceOpt = "0: BT_601_P(default), 1: BT_601_N, 2: P3, 3: BT_709, 4: BT_2020";
    std::cout << " --help               help info." << std::endl;
    std::cout << " --isEncoder          codec type. 0: decoder, 1: encoder" << std::endl;
    std::cout << "Heif Hardware encode Demo Options:" << std::endl;
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
    std::cout << " -o, --out            full path for output file." << std::endl;
    std::cout << "Heif Hardware decode Demo Options:" << std::endl;
    std::cout << " -i, --inputPath      full path for input." << std::endl;
    std::cout << " --sampleSize         (optional) output sample size. options: 2/4/8/16" << std::endl;
    std::cout << " --pixelFmt           (optional) output pixel format. " << pixelFmtValueOpt << std::endl;
    std::cout << " --isLimitedRange     (optional) range flag. 0: full range, 1: limited range" << std::endl;
    std::cout << " --colorSpace         (optional) color space type. " << colorSpaceOpt << std::endl;
}

static void AnalyzeParamForEncoder(ShortOption c, CommandOpt& opt)
{
    switch (c) {
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

static void AnalyzeParamForDecoder(ShortOption c, CommandOpt& opt)
{
    switch (c) {
        case ShortOption::OPT_INPUT_PATH:
            opt.inputPath = string(optarg);
            break;
        case ShortOption::OPT_SAMPLE_SIZE:
            opt.sampleSize = static_cast<SampleSize>(stol(optarg));
            break;
        case ShortOption::OPT_PIXEL_FMT:
            opt.pixelFmt = static_cast<UserPixelFormat>(stol(optarg));
            break;
        case ShortOption::OPT_IS_LIMITED_RANGE:
            opt.isLimitedRange = (stol(optarg) != 0);
            break;
        case ShortOption::OPT_COLORSPACE:
            opt.colorSpace = static_cast<ColorSpace>(stol(optarg));
            break;
        default:
            break;
    }
}

CommandOpt Parse(int argc, char *argv[])
{
    CommandOpt opt;
    int c;
    while ((c = getopt_long(argc, argv, "o:i:", g_longOptions, nullptr)) != -1) {
        switch (static_cast<ShortOption>(c)) {
            case ShortOption::OPT_HELP:
                ShowUsage();
                opt.isGetHelpInfoOnly = true;
                break;
            case ShortOption::OPT_IS_ENCODER:
                opt.isEncoder = (stol(optarg) != 0);
                break;
            default:
                break;
        }
        if (!opt.isGetHelpInfoOnly) {
            AnalyzeParamForEncoder(static_cast<ShortOption>(c), opt);
            AnalyzeParamForDecoder(static_cast<ShortOption>(c), opt);
        }
    }
    return opt;
}

static string GetMirrorPrintInfo(const ImageMirror& info)
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

static string GetRotatePrintInfo(const ImageRotation& info)
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

void CommandOpt::PrintEncoderParam() const
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

static string GetSampleSizePrintInfo(const SampleSize& info)
{
    static const map<SampleSize, string> sampleSizeMap = {
        { SampleSize::SAMPLE_SIZE_1,  "1"  },
        { SampleSize::SAMPLE_SIZE_2,  "2"  },
        { SampleSize::SAMPLE_SIZE_4,  "4"  },
        { SampleSize::SAMPLE_SIZE_8,  "8"  },
        { SampleSize::SAMPLE_SIZE_16, "16" },
    };
    auto iter = sampleSizeMap.find(info);
    if (iter != sampleSizeMap.end()) {
        return iter->second;
    }
    return "unknown sample size";
}

static string GetPixelFmtPrintInfo(const UserPixelFormat& info)
{
    static const map<UserPixelFormat, string> pixelFmtMap = {
        { UserPixelFormat::NONE,        "UserPixelFormat::NONE" },
        { UserPixelFormat::NV12,        "UserPixelFormat::NV12" },
        { UserPixelFormat::NV21,        "UserPixelFormat::NV21" },
        { UserPixelFormat::NV12_10BIT,  "UserPixelFormat::NV12_10BIT" },
        { UserPixelFormat::NV21_10BIT,  "UserPixelFormat::NV21_10BIT" },
        { UserPixelFormat::RGBA8888,    "UserPixelFormat::RGBA8888" },
        { UserPixelFormat::BGRA8888,    "UserPixelFormat::BRGA8888" },
        { UserPixelFormat::RGB565,      "UserPixelFormat::RGB565" },
        { UserPixelFormat::RGBA1010102, "UserPixelFormat::RGBA1010102" },
    };
    auto iter = pixelFmtMap.find(info);
    if (iter != pixelFmtMap.end()) {
        return iter->second;
    }
    return "unknown pixel format";
}

static string GetColorSpacePrintInfo(const ColorSpace& info)
{
    static const map<ColorSpace, string> colorSpaceMap = {
        { ColorSpace::BT_601_P,   "ColorSpace::BT_601_P" },
        { ColorSpace::BT_601_N,   "ColorSpace::BT_601_N" },
        { ColorSpace::P3,         "ColorSpace::P3"       },
        { ColorSpace::BT_709,     "ColorSpace::BT_709"   },
        { ColorSpace::BT_2020,    "ColorSpace::BT_2020"  },
    };
    auto iter = colorSpaceMap.find(info);
    if (iter != colorSpaceMap.end()) {
        return iter->second;
    }
    return "unknown color space, use ColorSpace::BT_601_P as default";
}

void CommandOpt::PrintDecoderParam() const
{
    std::cout << "=========================== OPT INFO ===========================" << endl;
    std::cout << "        inputPath : " << inputPath << endl;
    std::cout << "       sampleSize : " << GetSampleSizePrintInfo(sampleSize) << endl;
    std::cout << "         pixelFmt : " << GetPixelFmtPrintInfo(pixelFmt) << endl;
    std::cout << "       colorSpace : " << GetColorSpacePrintInfo(colorSpace) << endl;
    std::cout << "            range : " << (isLimitedRange ? "limited range" : "full range") << endl;
    std::cout << "=================================================================" << endl;
}

void CommandOpt::Print() const
{
    if (isEncoder) {
        PrintEncoderParam();
    } else {
        PrintDecoderParam();
    }
}
}
