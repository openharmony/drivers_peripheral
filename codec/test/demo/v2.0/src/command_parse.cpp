/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd.
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
#include "command_parse.h"
#include <getopt.h>
#include <iostream>
namespace {
enum class MyOptIndex {
    OPT_INDEX_UNKONWN = 0,
    OPT_INDEX_BUFFER_HANDLE,
    OPT_INDEX_HEVC,
    OPT_INDEX_HELP,
    OPT_INDEX_HEIGHT = 'h',
    OPT_INDEX_INPUT = 'i',
    OPT_INDEX_OUTPUT = 'o',
    OPT_INDEX_WIDTH = 'w',
    OPT_INDEX_COLOR = 'c'
};

static struct option g_longOptions[] = {
    {"width", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_WIDTH)},
    {"height", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_HEIGHT)},
    {"in", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_INPUT)},
    {"out", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_OUTPUT)},
    {"color", optional_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_COLOR)},
    {"nocopy", no_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_BUFFER_HANDLE)},
    {"HEVC", no_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_HEVC)},
    {"help", no_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_HELP)},
    {nullptr, 0, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_UNKONWN)}};
}  // namespace

bool CommandParse::Parse(int argc, char *argv[], CommandOpt &opt)
{
    while (1) {
        int optionIndex = 0;
        int c = getopt_long(argc, argv, "c::i:o:w:h:", g_longOptions, &optionIndex);
        if (c == -1) {
            break;
        }
        MyOptIndex index = static_cast<MyOptIndex>(c);
        switch (index) {
            case MyOptIndex::OPT_INDEX_BUFFER_HANDLE:
                opt.useBuffer = true;
                break;
            case MyOptIndex::OPT_INDEX_HEVC:
                opt.codec = codecMime::HEVC;
                break;
            case MyOptIndex::OPT_INDEX_HELP:
                ShowUsage();
                break;
            case MyOptIndex::OPT_INDEX_INPUT:
                opt.fileInput = optarg;
                break;
            case MyOptIndex::OPT_INDEX_OUTPUT:
                opt.fileOutput = optarg;
                break;
            case MyOptIndex::OPT_INDEX_WIDTH:
                opt.width = atoi(optarg);
                break;
            case MyOptIndex::OPT_INDEX_HEIGHT:
                opt.height = atoi(optarg);
                break;
            case MyOptIndex::OPT_INDEX_COLOR:
                if (optarg) {
                    opt.colorForamt = static_cast<ColorFormat>(atoi(optarg));
                }
                break;
            default:
                ShowUsage();
                break;
        }
    }
    if (opt.fileInput.empty() || opt.fileOutput.empty() || opt.width == 0 || opt.height == 0) {
        return false;
    }
    return true;
}

void CommandParse::ShowUsage()
{
    std::cout << "Options:" << std::endl;
    std::cout << " -w, --width=width          The video width." << std::endl;
    std::cout << " -h, --height=height        The video height." << std::endl;
    std::cout << " -o, --out=FILE             The file name for output file." << std::endl;
    std::cout << " -i, --in=FILE              The file name for input file." << std::endl;
    std::cout << " -cN, --color=N             The color format in the file. 0 is YUV420SP, 1 is RGBA888, 2 is BGRA888, "
                 "the default is 0."
              << std::endl;
    std::cout << " --HEVC                     HEVC decode or HEVC encode, AVC for default." << std::endl;
    std::cout << " --nocopy                   Support BufferHandle." << std::endl;
    std::cout << " --help                     The help info." << std::endl;
}
