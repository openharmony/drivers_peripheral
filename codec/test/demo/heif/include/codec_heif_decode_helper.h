/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_CODEC_IMAGE_V2_1_CODEC_HEIF_DECODE_HELPER
#define OHOS_HDI_CODEC_IMAGE_V2_1_CODEC_HEIF_DECODE_HELPER

#include <vector>
#include "command_parser.h"
#include "v2_1/icodec_image.h"
#include "v1_2/display_composer_type.h"
#include "v1_2/display_buffer_type.h"
#include "v1_2/include/idisplay_buffer.h"
#include "v2_0/cm_color_space.h"

template <typename T>
std::vector<uint8_t> Pod2Vec(const T& t)
{
    const uint8_t* begin = reinterpret_cast<const uint8_t*>(&t);
    const uint8_t* end = begin + sizeof(T);
    return std::vector<uint8_t>(begin, end);
}

namespace OHOS::VDI::HEIF {
class HeifDecoderHelper {
public:
    explicit HeifDecoderHelper(const CommandOpt& opt) : decodeOpt_(opt) {}
    ~HeifDecoderHelper() = default;
    void DoDecode();
private:
    bool IsHeifHardwareDecodeSupported(OHOS::sptr<OHOS::HDI::Codec::Image::V2_1::ICodecImage>& hdiHeifDecoder);
    bool GetOutputFormat();
    bool ReadInput(std::vector<OHOS::sptr<OHOS::Ashmem>>& inputs);
    bool AllocateOutputBuffer(OHOS::sptr<OHOS::HDI::Base::NativeBuffer>& output);
    void DumpOutput(OHOS::sptr<OHOS::HDI::Base::NativeBuffer>& output);
    void GetSampleSize();
    void GetMetaDataInfo(OHOS::HDI::Display::Graphic::Common::V2_0::CM_ColorSpaceInfo& colorSpaceInfo);
    
private:
    class InputParser {
    public:
        explicit InputParser(const std::string& inputPath) : source_(inputPath) {}
        ~InputParser() = default;
        bool ParseGridInfo(OHOS::HDI::Codec::Image::V2_1::GridInfo& gridInfo);
        bool ReadInput(std::vector<OHOS::sptr<OHOS::Ashmem>>& inputs);
    private:
        void FindXpsAndIFrameFile();
        static void SplitString(const std::string& src, char sep, std::vector<std::string>& vec);
        static std::string JoinPath(const std::string& base, const std::string& append);
        static bool ReadFileToAshmem(const std::string& filePath, std::vector<OHOS::sptr<OHOS::Ashmem>>& inputs);
        static int ExtractIFrameNum(const std::string& filePath);

        static constexpr char MAIN_SEP = '_';
        static constexpr size_t MIN_MAIN_SEG_CNT = 2;
        static constexpr size_t MAX_MAIN_SEG_CNT = 4;
        static constexpr char SUB_SEP = 'x';
        static constexpr size_t SUB_SEG_CNT = 2;
        static constexpr char NO_GRID_INDICATOR[] = "nogrid";
        static constexpr char XPS_INDICATOR[] = "_hevc_xps";
        static constexpr char I_FRAME_INDICATOR[] = "_hevc_I";
        enum MainSeg {
            DISPLAY_SIZE = 0,
            GRID_FLAG,
            TILE_SIZE,
            GRID_SIZE
        };
        enum SubSeg {
            HORIZONTAL = 0,
            VERTICAL
        };

        std::string source_;
        std::string xpsFile_;
        std::vector<std::string> iFrameFile_;
    };
    struct BufferFormatInfo {
        OHOS::HDI::Display::Composer::V1_2::PixelFormat format = OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_BUTT;
        std::string desc = "unknow";
    };
private:
    static constexpr int MAX_PATH_LEN = 256;
    static constexpr char DUMP_PATH[] = "/data/log/imagecodecdump";
    CommandOpt decodeOpt_;
    BufferFormatInfo outputFormat_;
    OHOS::HDI::Codec::Image::V2_1::CodecHeifDecInfo decInfo_;
};
} // OHOS::VDI::HEIF
#endif // OHOS_HDI_CODEC_IMAGE_V2_1_CODEC_HEIF_DECODE_HELPER