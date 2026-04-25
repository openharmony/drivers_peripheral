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
#include "command_parse.h"
#include <map>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include "surface_type.h"

namespace OHOS::HDI::Codec::Zcodec {
using namespace std;

enum ShortOption {
    OPT_UNKONWN = 0,
    OPT_HELP,
    OPT_DUMP,
    OPT_CODEC,
    OPT_INPUT = 'i',
    OPT_WIDTH = 'w',
    OPT_HEIGHT = 'h',
    OPT_API_TYPE = UINT8_MAX + 1,
    OPT_MAX_READ_CNT,
    OPT_PROTOCOL,
    OPT_PIXEL_FMT,
    OPT_FRAME_RATE,
    OPT_INSTANCE_NUM,
    OPT_RUN_TIMES,
    OPT_PASSTHROUGH,
    OPT_PROFILE,
    OPT_FLUSH_CNT,
    OPT_LEVEL,
    OPT_IFRAME_INTERVAL,
    OPT_INTRA_REFRESH,
    OPT_BITRATE_MODE,
    OPT_TARGET_BITRATE,
    OPT_TARGET_QUALITY,
    OPT_TARGET_QP,
    OPT_COLOR_ASPECTS,
    OPT_RESTART_AFTER_EOS,
};

static struct option g_longOptions[] = {
    {"help",            no_argument,        nullptr, OPT_HELP},
    {"isEncoder",       required_argument,  nullptr, OPT_CODEC},
    {"in",              required_argument,  nullptr, OPT_INPUT},
    {"dump",            required_argument,  nullptr, OPT_DUMP},
    {"width",           required_argument,  nullptr, OPT_WIDTH},
    {"height",          required_argument,  nullptr, OPT_HEIGHT},
    {"maxReadFrameCnt", required_argument,  nullptr, OPT_MAX_READ_CNT},
    {"protocol",        required_argument,  nullptr, OPT_PROTOCOL},
    {"pixfmt",          required_argument,  nullptr, OPT_PIXEL_FMT},
    {"frameRate",       required_argument,  nullptr, OPT_FRAME_RATE},
    {"instanceNum",     required_argument,  nullptr, OPT_INSTANCE_NUM},
    {"runTimes",        required_argument,  nullptr, OPT_RUN_TIMES},
    {"passthrough",     required_argument,  nullptr, OPT_PASSTHROUGH},
    {"profile",         required_argument,  nullptr, OPT_PROFILE},
    {"flushCnt",        required_argument,  nullptr, OPT_FLUSH_CNT},
    {"iFrameInterval",  required_argument,  nullptr, OPT_IFRAME_INTERVAL},
    {"intraRefresh",    required_argument,  nullptr, OPT_INTRA_REFRESH},
    {"bitrateMode",     required_argument,  nullptr, OPT_BITRATE_MODE},
    {"targetBitrate",   required_argument,  nullptr, OPT_TARGET_BITRATE},
    {"targetQuality",   required_argument,  nullptr, OPT_TARGET_QUALITY},
    {"targetQp",        required_argument,  nullptr, OPT_TARGET_QP},
    {"colorAspects",    required_argument,  nullptr, OPT_COLOR_ASPECTS},
    {"restartAfterEos", required_argument,  nullptr, OPT_RESTART_AFTER_EOS},
    {nullptr,           no_argument,        nullptr, OPT_UNKONWN},
};

void ShowUsage()
{
    cout << "--isEncoder      :  " << "(must) 0: decoder, 1: encoder" << endl;
    cout << "-i               :  " << "(must) input file path" << endl;
    cout << "-w               :  " << "(must) width" << endl;
    cout << "-h               :  " << "(must) height" << endl;
    cout << "--pixfmt         :  " << "(must for encoder) pixel format of input image" << endl;
    cout << "                 :      " << "8bit:  i420, nv12, nv21, rgba" << endl;
    cout << "                 :      " << "10bit: nv12_10bit, nv21_10bit, rgba1010102" << endl;
    cout << "                 :  " << "(optional for decoder) pixel format of output image" << endl;
    cout << "                 :      " << "8bit:  nv12, nv21" << endl;
    cout << "                 :      " << "10bit: nv12_10bit, nv21_10bit" << endl;
    cout << "--protocol       :  " << "(must) 0: H264(default), 1: H265" << endl;
    cout << "--frameRate      :  " << "(optional) frame rate, default is 30" << endl;
    cout << "--profile        :  " << "(optional) encoder profile, only for encoder" << endl;
    cout << "                 :      " << "H264: 0-Baseline, 1-Main, 2-High(default)" << endl;
    cout << "                 :      " << "H265: 0-Main, 1-Main10" << endl;
    cout << "--flushCnt       :  " << "(optional) total flush count during decoding, default is 0" << endl;
    cout << "--restartAfterEos:  " << "(optional) enable flush-start after receive eos, only for decoder" << endl;
    cout << "--iFrameInterval :  " << "(optional) I-frame interval in frames, default is 30" << endl;
    cout << "--intraRefresh   :  " << "(optional) intra-refresh VOP flag, 0:false(default), 1:true" << endl;
    cout << "--bitrateMode    :  " << "(optional) bitrate control mode, only for encoder" << endl;
    cout << "                 :      " << "0:VBR, 1:CBR, 2:CQ" << endl;
    cout << "--targetBitrate  :  " << "(optional) target bitrate in bps, default is 25000000(25Mbps)" << endl;
    cout << "--targetQuality  :  " << "(optional) target quality, only for encoder" << endl;
    cout << "--targetQp       :  " << "(optional) target QP, only for encoder" << endl;
    cout << "--colorAspects   :  " << "(optional) color aspects, format: range:primaries:transfer:matrix" << endl;
    cout << "                 :      " << "range: 0-1, primaries/transfer/matrix: see key_value.h" << endl;
    cout << "--instanceNum    :  " << "(optional) concurrency number, default is 1" << endl;
    cout << "--runTimes       :  " << "(optional) repeat times for single instance, default is 1" << endl;
    cout << "--maxReadFrameCnt:  " << "(optional) number of frames need to be read, 0(default) means read all" << endl;
    cout << "--passthrough    :  " << "(optional) 0: ipc(default), 1: passthrough" << endl;
}

CommandOpt Parse(int argc, char *argv[])
{
    CommandOpt opt;
    int c;
    while ((c = getopt_long(argc, argv, "i:w:h:", g_longOptions, nullptr)) != -1) {
        switch (c) {
            case OPT_HELP:
                ShowUsage();
                opt.showHelpInfoOnly = true;
                break;
            case OPT_CODEC:
                opt.isEncoder = (stol(optarg) != 0);
                break;
            case OPT_INPUT:
                opt.inputFile = string(optarg);
                break;
            case OPT_DUMP:
                opt.enableDump = stol(optarg);
                break;
            case OPT_WIDTH:
                opt.w = stol(optarg);
                break;
            case OPT_HEIGHT:
                opt.h = stol(optarg);
                break;
            case OPT_MAX_READ_CNT:
                opt.maxReadFrameCnt = stol(optarg);
                break;
            case OPT_PROTOCOL:
                opt.protocol = static_cast<CodeType>(stol(optarg));
                break;
            case OPT_PIXEL_FMT:
                opt.pixfmt = opt.ParseGraphicPixfmt(optarg);
                break;
            case OPT_FRAME_RATE:
                opt.frameRate = stol(optarg);
                break;
            case OPT_FLUSH_CNT:
                opt.flushCnt = stol(optarg);
                break;
            case OPT_INSTANCE_NUM:
                opt.instanceNum = stol(optarg);
                break;
            case OPT_RUN_TIMES:
                opt.runTimes = stol(optarg);
                break;
            case OPT_PASSTHROUGH:
                opt.isPassthrough = (stol(optarg) != 0);
                break;
            case OPT_PROFILE:
                opt.profile = (stol(optarg));
                break;
            case OPT_IFRAME_INTERVAL:
                opt.iFrameInterval = stol(optarg);
                break;
            case OPT_INTRA_REFRESH:
                opt.requestIDR = (stol(optarg) != 0);
                break;
            case OPT_BITRATE_MODE:
                opt.bitrateControlMode = opt.ParseBitrateControlMode(optarg);
                break;
            case OPT_TARGET_BITRATE:
                opt.targetBitrate = stol(optarg);
                break;
            case OPT_TARGET_QUALITY:
                opt.targetQuality = stol(optarg);
                break;
            case OPT_TARGET_QP:
                opt.targetQp = stol(optarg);
                break;
            case OPT_COLOR_ASPECTS: {
                std::string aspectsStr(optarg);
                std::vector<std::string> parts;
                size_t pos = 0;
                while ((pos = aspectsStr.find(':')) != std::string::npos) {
                    parts.push_back(aspectsStr.substr(0, pos));
                    aspectsStr.erase(0, pos + 1);
                }
                parts.push_back(aspectsStr);
                if (parts.size() == 4) {
                    opt.colorAspects = opt.ParseColorAspects(parts[0].c_str(), parts[1].c_str(), parts[2].c_str(), parts[3].c_str());
                }
                break;
            }
            case OPT_RESTART_AFTER_EOS: {
                opt.enableRestartAfterEos = (stol(optarg) != 0);
                break;
            }
            default:
                break;
        }
    }
    return opt;
}

OHOS::GraphicPixelFormat CommandOpt::ParseGraphicPixfmt(const char *cmd)
{
    std::string str(cmd);
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    if (str == "i420") {
        return OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_P;
    } else if (str == "nv12") {
        return OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
    } else if (str == "nv21") {
        return OHOS::GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
    } else if (str == "nv12_10bit") {
        return OHOS::GRAPHIC_PIXEL_FMT_YCBCR_P010;
    } else if (str == "nv21_10bit") {
        return OHOS::GRAPHIC_PIXEL_FMT_YCRCB_P010;
    } else if (str == "rgba") {
        return OHOS::GRAPHIC_PIXEL_FMT_RGBA_8888;
    }
    return OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
}

std::string CommandOpt::GetPixFmtPrintInfo() const
{
    static std::map<OHOS::GraphicPixelFormat, std::string> pixFmtDesc = {
        { OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_P,     "I420" },
        { OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP,    "NV12" },
        { OHOS::GRAPHIC_PIXEL_FMT_YCRCB_420_SP,    "NV21" },
        { OHOS::GRAPHIC_PIXEL_FMT_YCBCR_P010,      "NV12_10BIT" },
        { OHOS::GRAPHIC_PIXEL_FMT_YCRCB_P010,      "NV21_10BIT" },
        { OHOS::GRAPHIC_PIXEL_FMT_RGBA_8888,       "RGBA8888" },
        { OHOS::GRAPHIC_PIXEL_FMT_RGBA_1010102,    "RGBA1010102" },
    };
    auto iter = pixFmtDesc.find(pixfmt);
    if (iter != pixFmtDesc.end()) {
        return iter->second;
    }
    return "UNKNOWN";
}

std::string CommandOpt::GetProfilePrintInfo() const
{
    if (!profile.has_value()) {
        return "default";
    }
    static std::map<int32_t, std::string> profileDesc = {
        { AVC_PROFILE_BASELINE, "Baseline" },
        { AVC_PROFILE_MAIN,     "Main" },
        { AVC_PROFILE_HIGH,     "High" },
        { HEVC_PROFILE_MAIN,    "Main" },
        { HEVC_PROFILE_MAIN_10, "Main10" },
    };
    auto iter = profileDesc.find(profile.value());
    if (iter != profileDesc.end()) {
        return iter->second;
    }
    return "UNKNOWN";
}

std::string CommandOpt::GetDumpOutputFile(int32_t instanceId, int32_t runTimesId) const
{
    if (!enableDump || instanceId > instanceNum || runTimesId > runTimes) {
        return "";
    }
    string protocolStr = (protocol == CodeType::H264) ? "h264" : "h265";
    return inputFile + ".instance" + to_string(instanceId) + ".run" + to_string(runTimesId) + "." + protocolStr;
}

void CommandOpt::Print() const
{
    cout << "==================== [RUN PARAMS] ===================" << endl;
    cout << "codec:           " << (isEncoder ? "Encoder" : "Decoder") << endl;
    cout << "resolution:      " << w << "x" << h << endl;
    cout << "frameRate:       " << frameRate << endl;
    cout << "protocol:        " << ((protocol == CodeType::H264) ? "H264" : "H265") << endl;
    cout << "pixfmt:          " << GetPixFmtPrintInfo() << endl;
    if (isEncoder) {
        cout << "profile:         " << GetProfilePrintInfo() << endl;
        if (iFrameInterval.has_value())
            cout << "iFrameInterval:  " << iFrameInterval.value() << endl;
        if (bitrateControlMode.has_value())
            cout << "bitrateMode:     " << GetBitrateControlModePrintInfo() << endl;
        if (targetBitrate.has_value())
            cout << "targetBitrate:   " << targetBitrate.value() << " bps" << endl;
        if (targetQuality.has_value()) {
            cout << "targetQuality:   " << targetQuality.value() << endl;
        }
        if (targetQp.has_value()) {
            cout << "targetQp:        " << targetQp.value() << endl;
        }
        if (colorAspects.has_value()) {
            cout << "colorAspects:    range=" << colorAspects.value().range
                 << " prim=" << static_cast<int>(colorAspects.value().primaries)
                 << " trans=" << static_cast<int>(colorAspects.value().transfer)
                 << " matrix=" << static_cast<int>(colorAspects.value().matrixCoeffs) << endl;
        }
    } else {
        cout << "flushCnt:        " << flushCnt << endl;
        cout << "restartAfterEos: " << enableRestartAfterEos << endl;
    }
    cout << "isPassthrough:   " << isPassthrough << endl;
    cout << "inputFile:       " << inputFile << endl;
    cout << "maxReadFrameCnt: " << maxReadFrameCnt << endl;
    cout << "enableDump:      " << enableDump << endl;
    cout << "instanceNum:     " << instanceNum << endl;
    cout << "runTimes:        " << runTimes << endl;
    if (enableDump) {
        for (int32_t i = 1; i <= instanceNum; i++) {
            for (int32_t j = 1; j <= runTimes; j++) {
                cout << "outputFile:      " << GetDumpOutputFile(i, j) << endl;
            }
        }
    }
    cout << "=====================================================" << endl;
}

OHOS::HDI::Codec::BitrateControlMode CommandOpt::ParseBitrateControlMode(const char *cmd)
{
    std::string str(cmd);
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    if (str == "vbr" || str == "0") {
        return OHOS::HDI::Codec::VBR;
    } else if (str == "cbr" || str == "1") {
        return OHOS::HDI::Codec::CBR;
    } else if (str == "cq" || str == "2") {
        return OHOS::HDI::Codec::CQ;
    }
    return OHOS::HDI::Codec::VBR; // default
}

OHOS::HDI::Codec::ColorAspects CommandOpt::ParseColorAspects(const char* range, const char* primaries, const char* transfer, const char* matrix)
{
    OHOS::HDI::Codec::ColorAspects aspects{};
    aspects.range = (std::string(range) == "1");
    aspects.primaries = static_cast<uint8_t>(std::stoi(primaries));
    aspects.transfer = static_cast<uint8_t>(std::stoi(transfer));
    aspects.matrixCoeffs = static_cast<uint8_t>(std::stoi(matrix));
    return aspects;
}

std::string CommandOpt::GetBitrateControlModePrintInfo() const
{
    static std::map<BitrateControlMode, std::string> modeDesc = {
        { CBR, "CBR" },
        { VBR, "VBR" },
        { CQ,  "CQ" },
    };
    auto iter = modeDesc.find(bitrateControlMode.value());
    if (iter != modeDesc.end()) {
        return iter->second;
    }
    return "UNKNOWN";
}

} // namespace OHOS::HDI::Codec::Zcodec