/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "codec_packet_reader.h"
#include <arpa/inet.h>
#include <hdf_log.h>
namespace {
constexpr int32_t START_CODE_OFFSET_ONE = -1;
constexpr int32_t START_CODE_OFFSET_SEC = -2;
constexpr int32_t START_CODE_OFFSET_THIRD = -3;
constexpr int32_t START_CODE_SIZE_FRAME = 4;
constexpr int32_t START_CODE_SIZE_SLICE = 3;
constexpr char START_CODE = 0x1;
constexpr char VOP_START = 0xB6;
}  // namespace

CodecPacketReader::Ptr CodecPacketReader::GetPacketReader(const CodecMime &mime)
{
    CodecPacketReader::Ptr reader = nullptr;
    switch (mime) {
        case CodecMime::AVC:
        case CodecMime::HEVC:
            reader = std::make_shared<CodecH264Reader>();
            break;
        case CodecMime::MPEG4:
            reader = std::make_shared<CodecMpeg4Reader>();
            break;
        case CodecMime::VP9:
            reader = std::make_shared<CodecVp9Reader>();
            break;
        default:
            break;
    }
    return reader;
}

CodecH264Reader::CodecH264Reader() : CodecPacketReader()
{}

bool CodecH264Reader::ReadOnePacket(std::ifstream &ioIn, char *buf, uint32_t &filledCount)
{
    // read start code first
    ioIn.read(buf, START_CODE_SIZE_FRAME);
    if (ioIn.eof()) {
        return true;
    }

    char *temp = buf;
    temp += START_CODE_SIZE_FRAME;
    bool ret = true;
    while (!ioIn.eof()) {
        ioIn.read(temp, 1);
        if (*temp == START_CODE) {
            // check start code
            if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0) &&
                (temp[START_CODE_OFFSET_THIRD] == 0)) {
                ioIn.seekg(-START_CODE_SIZE_FRAME, std::ios_base::cur);
                temp -= (START_CODE_SIZE_FRAME - 1);
                ret = false;
                break;
            } else if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0)) {
                ioIn.seekg(-START_CODE_SIZE_SLICE, std::ios_base::cur);
                temp -= (START_CODE_SIZE_SLICE - 1);
                ret = false;
                break;
            }
        }
        temp++;
    }
    filledCount = (temp - buf);
    return ret;
}

CodecMpeg4Reader::CodecMpeg4Reader() : CodecPacketReader()
{}

bool CodecMpeg4Reader::ReadOnePacket(std::ifstream &ioIn, char *buf, uint32_t &filledCount)
{
    ioIn.read(buf, START_CODE_SIZE_SLICE);
    if (ioIn.eof()) {
        return true;
    }

    char *temp = buf;
    temp += START_CODE_SIZE_SLICE;
    bool ret = true;
    bool findVop = false;
    while (!ioIn.eof()) {
        ioIn.read(temp, 1);
        // check start code
        if ((*temp == VOP_START) && (temp[START_CODE_OFFSET_ONE] == START_CODE) && (temp[START_CODE_OFFSET_SEC] == 0) &&
            (temp[START_CODE_OFFSET_THIRD] == 0)) {
            findVop = true;
        }
        if (findVop && (*temp == START_CODE) && (temp[START_CODE_OFFSET_ONE] == 0) &&
            (temp[START_CODE_OFFSET_SEC] == 0)) {
            temp -= START_CODE_SIZE_SLICE - 1;
            ioIn.seekg(START_CODE_OFFSET_THIRD, std::ios_base::cur);
            ret = false;
            break;
        }
        temp++;
    }
    filledCount = (temp - buf);
    return ret;
}

CodecVp9Reader::CodecVp9Reader() : CodecPacketReader()
{}

bool CodecVp9Reader::ReadOnePacket(std::ifstream &ioIn, char *buf, uint32_t &filledCount)
{
    // vp9 saved in trunk, use ffmpeg to save vp9 to .vp9 file, the format like this:
    // len(4 bytes, little-end, length of vp9 data) + vp9 data
    filledCount = 0;
    ioIn.read(reinterpret_cast<char *>(&filledCount), sizeof(filledCount));
    if (ioIn.eof()) {
        return true;
    }
    filledCount = ntohl(filledCount);
    ioIn.read(buf, filledCount);
    if (ioIn.eof()) {
        return true;
    }
    return false;
}