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
#ifndef COMMAND_PARSE_H
#define COMMAND_PARSE_H
#include <string>
#include <optional>
#include <chrono>
#include <thread>
#include <map>
#include <cinttypes>
#include "surface_type.h"
#include "surface_buffer.h"
#include "key_value.h"
#include "codec_log_wrapper.h"

namespace OHOS::HDI::Codec::Zcodec {
using namespace OHOS;
using namespace OHOS::HDI::Codec;
enum class CodeType {
    H264,
    H265,
};

struct CommandOpt {
    // encoder & decoder
    bool isEncoder = true;
    bool isPassthrough = false; // 是否直通调用HDF
    uint32_t w = 0;
    uint32_t h = 0;
    uint32_t frameRate = 30;
    CodeType protocol = CodeType::H264;
    std::string inputFile;
    OHOS::GraphicPixelFormat pixfmt = OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
    // encoder only
    std::optional<int32_t> profile; // 编码 profile 配置，可选
    std::optional<int32_t> iFrameInterval; // I帧间隔，单位：帧数，默认30帧
    std::optional<bool> requestIDR = false; // 帧内刷新VOP标志，默认false
    std::optional<BitrateControlMode> bitrateControlMode = OHOS::HDI::Codec::CBR; // 码率控制模式，默认CBR
    std::optional<uint32_t> targetBitrate = 25000000; // 目标码率，单位：bps，默认25Mbps
    std::optional<uint32_t> targetQuality; // 目标质量，可选
    std::optional<int32_t> targetQp; // 目标量化参数，可选
    std::optional<ColorAspects> colorAspects; // 色彩属性，可选

    // decoder only
    uint32_t flushCnt = 0;
    uint32_t enableRestartAfterEos = false;

    // test control
    bool showHelpInfoOnly = false;
    bool enableDump = false;
    uint32_t maxReadFrameCnt = 0; // 0 means read whole file
    uint32_t instanceNum = 1;  // 并发实例数
    uint32_t runTimes = 1;     // 循环编码次数，默认1次

    void Print() const;
    OHOS::GraphicPixelFormat ParseGraphicPixfmt(const char *cmd);
    std::string GetPixFmtPrintInfo() const;
    std::string GetProfilePrintInfo() const;
    std::string GetDumpOutputFile(int32_t instanceId, int32_t runTimesId) const;
    OHOS::HDI::Codec::BitrateControlMode ParseBitrateControlMode(const char *cmd);
    OHOS::HDI::Codec::ColorAspects ParseColorAspects(const char* range, const char* primaries,
                                                     const char* transfer, const char* matrix);
    std::string GetLevelPrintInfo() const;
    std::string GetBitrateControlModePrintInfo() const;
};

CommandOpt Parse(int argc, char *argv[]);

} // namespace OHOS::HDI::Codec::Zcodec

#endif // COMMAND_PARSE_H