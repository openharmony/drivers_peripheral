/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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
#ifndef CODEC_PACKET_READER_H
#define CODEC_PACKET_READER_H
#include <cinttypes>
#include <fstream>
#include <iostream>
#include <memory>
#include "command_parse.h"
class CodecPacketReader {
public:
    using Ptr = std::shared_ptr<CodecPacketReader>;
    CodecPacketReader() = default;
    virtual ~CodecPacketReader() = default;

    virtual bool ReadOnePacket(std::ifstream &ioIn, char *buf, uint32_t &filledCount) = 0;

    static Ptr GetPacketReader(const CodecMime &mime);
};

class CodecH264Reader : public CodecPacketReader {
public:
    using Ptr = std::shared_ptr<CodecPacketReader>;
    CodecH264Reader();
    ~CodecH264Reader() = default;

    bool ReadOnePacket(std::ifstream &ioIn, char *buf, uint32_t &filledCount) override;
};

class CodecMpeg4Reader : public CodecPacketReader {
public:
    using Ptr = std::shared_ptr<CodecPacketReader>;
    CodecMpeg4Reader();
    ~CodecMpeg4Reader() = default;

    bool ReadOnePacket(std::ifstream &ioIn, char *buf, uint32_t &filledCount) override;
};

class CodecVp9Reader : public CodecPacketReader {
public:
    using Ptr = std::shared_ptr<CodecVp9Reader>;
    CodecVp9Reader();
    ~CodecVp9Reader() = default;

    bool ReadOnePacket(std::ifstream &ioIn, char *buf, uint32_t &filledCount) override;
};
#endif