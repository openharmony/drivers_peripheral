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

#include <dirent.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <chrono>
#include <map>
#include <cstdio>
#include <cinttypes>
#include <securec.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "surface_buffer.h"
#include "v2_0/cm_color_space.h"
#include "v2_0/buffer_handle_meta_key_type.h"
#include "log.h"
#include "codec_heif_decode_helper.h"

namespace OHOS::VDI::HEIF {
using namespace std;
using namespace OHOS::HDI::Codec::Image::V2_1;
using namespace OHOS::HDI::Display::Graphic::Common::V2_0;

void HeifDecoderHelper::InputParser::SplitString(const std::string& src, char sep, std::vector<std::string>& vec)
{
    vec.clear();
    string::size_type startPos = 0;
    while (true) {
        string::size_type endPos = src.find_first_of(sep, startPos);
        if (endPos == string::npos) {
            break;
        }
        vec.emplace_back(src.substr(startPos, endPos - startPos));
        startPos = endPos + 1;
    }
    if (startPos != string::npos) {
        vec.emplace_back(src.substr(startPos));
    }
}

std::string HeifDecoderHelper::InputParser::JoinPath(const std::string& base, const std::string& append)
{
    return (filesystem::path(base) / append).string();
}

bool HeifDecoderHelper::InputParser::ParseGridInfo(GridInfo& gridInfo)
{
    // source_ demo:
    // 1. has grid: 3072x4096_grid_512x512_6x8
    // 2. no grid: 3072x4096_nogrid
    string baseDir = filesystem::path(source_).filename().string();
    vector<string> vec;
    SplitString(baseDir, MAIN_SEP, vec);
    IF_TRUE_RETURN_VAL_WITH_MSG(vec.size() < MIN_MAIN_SEG_CNT, false,
                                "invalid source: %{public}s", source_.c_str());

    vector<string> vecTmp;
    SplitString(vec[DISPLAY_SIZE], SUB_SEP, vecTmp);
    IF_TRUE_RETURN_VAL_WITH_MSG(vecTmp.size() != SUB_SEG_CNT, false, "invalid source: %{public}s", source_.c_str());
    gridInfo.displayWidth = static_cast<uint32_t>(stol(vecTmp[HORIZONTAL].c_str()));
    gridInfo.displayHeight = static_cast<uint32_t>(stol(vecTmp[VERTICAL].c_str()));

    if (vec[GRID_FLAG].find(NO_GRID_INDICATOR) != string::npos) {
        gridInfo.enableGrid = false;
        gridInfo.cols = 1;
        gridInfo.rows = 1;
        gridInfo.tileWidth = gridInfo.displayWidth;
        gridInfo.tileHeight = gridInfo.displayHeight;
    } else {
        IF_TRUE_RETURN_VAL_WITH_MSG(vec.size() < MAX_MAIN_SEG_CNT, false,
                                    "invalid source: %{public}s", source_.c_str());

        gridInfo.enableGrid = true;
    
        SplitString(vec[TILE_SIZE], SUB_SEP, vecTmp);
        IF_TRUE_RETURN_VAL_WITH_MSG(vecTmp.size() != SUB_SEG_CNT, false,
                                    "invalid source: %{public}s", source_.c_str());
        gridInfo.tileWidth = static_cast<uint32_t>(stol(vecTmp[HORIZONTAL].c_str()));
        gridInfo.tileHeight = static_cast<uint32_t>(stol(vecTmp[VERTICAL].c_str()));

        SplitString(vec[GRID_SIZE], SUB_SEP, vecTmp);
        IF_TRUE_RETURN_VAL_WITH_MSG(vecTmp.size() != SUB_SEG_CNT, false,
                                    "invalid source: %{public}s", source_.c_str());
        gridInfo.cols = static_cast<uint32_t>(stol(vecTmp[HORIZONTAL].c_str()));
        gridInfo.rows = static_cast<uint32_t>(stol(vecTmp[VERTICAL].c_str()));
    }
    return true;
}

void HeifDecoderHelper::InputParser::FindXpsAndIFrameFile()
{
    DIR *dirp = opendir(source_.c_str());
    IF_TRUE_RETURN_WITH_MSG(dirp == nullptr, "failed to open: %{public}s, errno=%{public}d",
                            source_.c_str(), errno);
    struct dirent *dp;
    while ((dp = readdir(dirp)) != nullptr) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }
        string path = JoinPath(source_, dp->d_name);
        struct stat st{};
        if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        string fileName(dp->d_name);
        if (fileName.find(XPS_INDICATOR) != string::npos) {
            xpsFile_ = path;
        } else if (fileName.find(I_FRAME_INDICATOR) != string::npos) {
            iFrameFile_.emplace_back(path);
        }
    }
    closedir(dirp);
}

bool HeifDecoderHelper::InputParser::ReadFileToAshmem(const string& filePath, vector<sptr<Ashmem>>& inputs)
{
    ifstream ifs(filePath, ios::binary);
    IF_TRUE_RETURN_VAL_WITH_MSG(!ifs.is_open(), false, "failed to open file: %{public}s", filePath.c_str());

    ifs.seekg(0, ifstream::end);
    size_t fileSize = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0, ifstream::beg);

    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(filePath.c_str(), static_cast<int32_t>(fileSize));
    IF_TRUE_RETURN_VAL_WITH_MSG(ashmem == nullptr, false, "failed to create ashmem for %{public}s, size(%{public}zu)",
                                filePath.c_str(), fileSize);
    int fd = ashmem->GetAshmemFd();
    void* addr = ::mmap(nullptr, static_cast<int32_t>(fileSize), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    IF_TRUE_RETURN_VAL_WITH_MSG(addr == nullptr, false, "failed to map ashmem for %{public}s, size(%{public}zu)",
                                filePath.c_str(), fileSize);
    ifs.read(reinterpret_cast<char*>(addr), static_cast<streamsize>(fileSize));
    ifs.close();
    ::munmap(addr, static_cast<int32_t>(fileSize));
    inputs.emplace_back(ashmem);
    return true;
}

int HeifDecoderHelper::InputParser::ExtractIFrameNum(const string& filePath)
{
    string fileName = filesystem::path(filePath).filename().string();
    string::size_type pos = fileName.find(I_FRAME_INDICATOR);
    if (pos == string::npos) {
        return -1;
    }
    return stoi(fileName.substr(pos + string(I_FRAME_INDICATOR).size()));
}

bool HeifDecoderHelper::InputParser::ReadInput(vector<sptr<Ashmem>>& inputs)
{
    FindXpsAndIFrameFile();
    IF_TRUE_RETURN_VAL_WITH_MSG(xpsFile_.empty(), false, "no xps file in %{public}s", source_.c_str());
    IF_TRUE_RETURN_VAL_WITH_MSG(iFrameFile_.empty(), false, "no iframe file in %{public}s", source_.c_str());

    IF_TRUE_RETURN_VAL_WITH_MSG(!ReadFileToAshmem(xpsFile_, inputs), false,
                                "failed to read xps file: %{public}s", xpsFile_.c_str());
    std::sort(iFrameFile_.begin(), iFrameFile_.end(), [](const string& a, const string& b) {
        return ExtractIFrameNum(a) < ExtractIFrameNum(b);
    });
    for (const string& one : iFrameFile_) {
        IF_TRUE_RETURN_VAL_WITH_MSG(!ReadFileToAshmem(one, inputs), false,
                                    "failed to read iframe file: %{public}s", one.c_str());
    }
    return true;
}

static bool IsValueInRange(uint32_t value, uint32_t maxValue, uint32_t minValue)
{
    return (value >= minValue) && (value <= maxValue);
}

bool HeifDecoderHelper::IsHeifHardwareDecodeSupported(sptr<ICodecImage>& hdiHeifDecoder)
{
    std::vector<CodecImageCapability> capList;
    auto ret = hdiHeifDecoder->GetImageCapability(capList);
    IF_TRUE_RETURN_VAL(ret != HDF_SUCCESS, false);
    for (const CodecImageCapability& one : capList) {
        if (one.role != CODEC_IMAGE_HEIF || one.type != CODEC_IMAGE_TYPE_DECODER) {
            continue;
        }
        uint32_t widthToCheck = decInfo_.gridInfo.enableGrid ?
                                decInfo_.gridInfo.tileWidth :
                                decInfo_.gridInfo.displayWidth;
        uint32_t heightToCheck = decInfo_.gridInfo.enableGrid ?
                                 decInfo_.gridInfo.tileHeight :
                                 decInfo_.gridInfo.displayHeight;
        if (IsValueInRange(widthToCheck, one.maxWidth, one.minWidth) &&
            IsValueInRange(heightToCheck, one.maxHeight, one.minHeight)) {
            return true;
        }
        if (IsValueInRange(widthToCheck, one.maxHeight, one.minHeight) &&
            IsValueInRange(heightToCheck, one.maxWidth, one.minWidth)) {
            return true;
        }
    }
    return false;
}

void HeifDecoderHelper::DoDecode()
{
    cout << "start heif decode" << endl;
    IF_TRUE_RETURN_WITH_MSG(!GetOutputFormat(), "failed to get output format");
    std::vector<sptr<Ashmem>> inputs;
    IF_TRUE_RETURN_WITH_MSG(!ReadInput(inputs), "failed to read input");
    GetSampleSize();
    sptr<NativeBuffer> output;
    IF_TRUE_RETURN_WITH_MSG(!AllocateOutputBuffer(output), "failed to allocate output buffer");
    sptr<ICodecImage> hdiHeifDecoder = ICodecImage::Get();
    IF_TRUE_RETURN_WITH_MSG(hdiHeifDecoder == nullptr, "failed to get ICodecImage");
    IF_TRUE_RETURN_WITH_MSG(!IsHeifHardwareDecodeSupported(hdiHeifDecoder), "heif hw decode not supported");
    int32_t ret = hdiHeifDecoder->DoHeifDecode(inputs, output, decInfo_);
    if (ret == HDF_SUCCESS) {
        cout << "heif decode succeed" << endl;
        DumpOutput(output);
    } else {
        cout << "heif decode failed" << endl;
    }
}

bool HeifDecoderHelper::GetOutputFormat()
{
    static const map<UserPixelFormat,   OHOS::HDI::Display::Composer::V1_2::PixelFormat> pixelFmtMap = {
        { UserPixelFormat::NV12,        OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP },
        { UserPixelFormat::NV21,        OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCRCB_420_SP },
        { UserPixelFormat::NV12_10BIT,  OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_P010 },
        { UserPixelFormat::NV21_10BIT,  OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCRCB_P010 },
        { UserPixelFormat::RGBA8888,    OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGBA_8888 },
        { UserPixelFormat::BGRA8888,    OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_BGRA_8888 },
        { UserPixelFormat::RGB565,      OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGB_565 },
        { UserPixelFormat::RGBA1010102, OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGBA_1010102 },
    };
    auto iterFmt = pixelFmtMap.find(decodeOpt_.pixelFmt);
    IF_TRUE_RETURN_VAL_WITH_MSG(iterFmt == pixelFmtMap.end(), false,
                                "unsupported pixel format: %{public}d", static_cast<int>(decodeOpt_.pixelFmt));
    outputFormat_.format = iterFmt->second;

    static const map<OHOS::HDI::Display::Composer::V1_2::PixelFormat, string> pixelFmtDescMap = {
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP, "NV12"       },
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCRCB_420_SP, "NV21"       },
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_P010,   "NV12_10BIT" },
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCRCB_P010,   "NV21_10BIT" },
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGBA_8888,    "RGBA8888"   },
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_BGRA_8888,    "BGRA8888"   },
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGB_565,      "RGB565"     },
        { OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_RGBA_1010102, "RGBA1010102"},
    };
    auto iterDesc = pixelFmtDescMap.find(outputFormat_.format);
    IF_TRUE_RETURN_VAL_WITH_MSG(iterDesc == pixelFmtDescMap.end(), false,
                                "unsupported pixel format: %{public}d", static_cast<int>(decodeOpt_.pixelFmt));
    outputFormat_.desc = iterDesc->second;
    return true;
}

bool HeifDecoderHelper::ReadInput(vector<sptr<Ashmem>>& inputs)
{
    InputParser parser(decodeOpt_.inputPath);
    bool ret = parser.ParseGridInfo(decInfo_.gridInfo);
    ret = ret && parser.ReadInput(inputs);
    return ret;
}

void HeifDecoderHelper::GetMetaDataInfo(CM_ColorSpaceInfo& colorSpaceInfo)
{
    colorSpaceInfo.range = (decodeOpt_.isLimitedRange)? RANGE_LIMITED : RANGE_FULL;
    static const map<ColorSpace, CM_Matrix> colorSpaceDescMap = {
        { ColorSpace::BT_601_P, MATRIX_BT601_P },
        { ColorSpace::BT_601_N, MATRIX_BT601_N },
        { ColorSpace::P3,       MATRIX_P3      },
        { ColorSpace::BT_709,   MATRIX_BT709   },
        { ColorSpace::BT_2020,  MATRIX_BT2020  },
    };

    auto iterDesc = colorSpaceDescMap.find(decodeOpt_.colorSpace);
    if (iterDesc == colorSpaceDescMap.end()) {
        HDF_LOGE("unsupported colorSpace: %{public}d",  static_cast<uint32_t>(decodeOpt_.colorSpace));
        colorSpaceInfo.matrix = MATRIX_BT601_P;
        return;
    }

    colorSpaceInfo.matrix = iterDesc->second;
    return;
}

bool HeifDecoderHelper::AllocateOutputBuffer(sptr<NativeBuffer>& output)
{
    uint64_t usage = BUFFER_USAGE_CPU_READ |
                     BUFFER_USAGE_CPU_WRITE |
                     BUFFER_USAGE_MEM_DMA |
                     BUFFER_USAGE_MEM_MMZ_CACHE;

    sptr<OHOS::SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    IF_TRUE_RETURN_VAL_WITH_MSG(surfaceBuffer == nullptr, false, "failed to create buffer\n");

    BufferRequestConfig config = {
        .width = decInfo_.gridInfo.displayWidth / decInfo_.sampleSize,
        .height = decInfo_.gridInfo.displayHeight / decInfo_.sampleSize,
        .strideAlignment = 32,
        .format = outputFormat_.format,
        .usage = usage,
        .timeout = 0
    };
 
    GSError ret = surfaceBuffer->Alloc(config);
    IF_TRUE_RETURN_VAL_WITH_MSG(ret != GSERROR_OK, false, "failed to alloc surfaceBuffer, ret=%{public}d\n", ret);
    
    CM_ColorSpaceInfo colorSpaceInfo = {};
    GetMetaDataInfo(colorSpaceInfo);
    surfaceBuffer->SetMetadata(ATTRKEY_COLORSPACE_INFO, Pod2Vec(colorSpaceInfo));

    output = new NativeBuffer(surfaceBuffer->GetBufferHandle());

    return true;
}

static int64_t GetTimestampInMs()
{
    auto now = chrono::steady_clock::now();
    return chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
}

void HeifDecoderHelper::DumpOutput(sptr<NativeBuffer>& output)
{
    cout << "dump heif decode result" << endl;
    sptr<SurfaceBuffer> outputSurface = SurfaceBuffer::Create();
    IF_TRUE_RETURN_WITH_MSG(outputSurface == nullptr, "output is null");
    outputSurface->SetBufferHandle(output->Move());
    int64_t timestamp = GetTimestampInMs();
    char outputFilePath[MAX_PATH_LEN] = {0};
    int ret = 0;
    if (decInfo_.gridInfo.enableGrid) {
        ret = sprintf_s(outputFilePath, sizeof(outputFilePath),
                        "%s/%ld_hdiout_%s_%u(%d)x%u(%d)_grid_%ux%u_%ux%u_s%u_m%d_r%d.bin",
                        DUMP_PATH, timestamp, outputFormat_.desc.c_str(),
                        decInfo_.gridInfo.displayWidth, outputSurface->GetStride(),
                        decInfo_.gridInfo.displayHeight, outputSurface->GetHeight(),
                        decInfo_.gridInfo.tileWidth, decInfo_.gridInfo.tileHeight,
                        decInfo_.gridInfo.cols, decInfo_.gridInfo.rows, decInfo_.sampleSize,
                        static_cast<int32_t>(decodeOpt_.colorSpace), decodeOpt_.isLimitedRange);
    } else {
        ret = sprintf_s(outputFilePath, sizeof(outputFilePath),
                        "%s/%ld_hdiout_%s_%u(%d)x%u(%d)_nogrid_s%u_m%d_r%d.bin",
                        DUMP_PATH, timestamp, outputFormat_.desc.c_str(),
                        decInfo_.gridInfo.displayWidth, outputSurface->GetStride(),
                        decInfo_.gridInfo.displayHeight, outputSurface->GetHeight(),
                        decInfo_.sampleSize, static_cast<int32_t>(decodeOpt_.colorSpace),
                        decodeOpt_.isLimitedRange);
    }
    if (ret == -1) {
        HDF_LOGE("failed to create dump file");
        return;
    }
    cout << "dump result to: " << outputFilePath << endl;

    std::ofstream dumpOutFile;
    dumpOutFile.open(std::string(outputFilePath), std::ios_base::binary | std::ios_base::trunc);
    if (!dumpOutFile.is_open()) {
        cout << "failed to dump decode result" << endl;
        return;
    }

    GSError err = outputSurface->InvalidateCache();
    if (err != GSERROR_OK) {
        cout << "InvalidateCache failed, GSError=" << err << endl;
    }
    dumpOutFile.write(reinterpret_cast<char*>(outputSurface->GetVirAddr()), outputSurface->GetSize());
    dumpOutFile.close();
}

void HeifDecoderHelper::GetSampleSize()
{
    static const map<SampleSize, uint32_t> sampleSizeMap = {
        { SampleSize::SAMPLE_SIZE_1,  1  },
        { SampleSize::SAMPLE_SIZE_2,  2  },
        { SampleSize::SAMPLE_SIZE_4,  4  },
        { SampleSize::SAMPLE_SIZE_8,  8  },
        { SampleSize::SAMPLE_SIZE_16, 16 },
    };
    auto iter = sampleSizeMap.find(decodeOpt_.sampleSize);
    if (iter != sampleSizeMap.end()) {
        decInfo_.sampleSize = iter->second;
    } else {
        decInfo_.sampleSize = 1;
    }
}
}