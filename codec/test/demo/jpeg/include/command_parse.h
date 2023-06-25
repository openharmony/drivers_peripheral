/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PARSECOMMAND_H
#define PARSECOMMAND_H
#include <cinttypes>
#include <string>
enum class CodecMime { AVC, HEVC, MPEG4, VP9 };
enum class ColorFormat { YUV420SP = 0, RGBA8888, BGRA8888 };
enum class MyOptIndex {
    OPT_INDEX_UNKONWN = 0,
    OPT_INDEX_HELP,
    OPT_INDEX_HEIGHT = 'h',
    OPT_INDEX_INPUT = 'i',
    OPT_INDEX_OUTPUT = 'o',
    OPT_INDEX_WIDTH = 'w',
};
struct CommandOpt {
    std::string fileInput = "";
    std::string fileOutput = "";
    uint32_t width = 0;
    uint32_t height = 0;
};

class CommandParse {
public:
    CommandParse()
    {}
    ~CommandParse()
    {}
    bool Parse(int argc, char *argv[], CommandOpt &opt);

private:
    void ShowUsage();
};
#endif // PARSE_COMMAND_H
