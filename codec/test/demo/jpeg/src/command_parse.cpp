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

#include "command_parse.h"
#include <getopt.h>
#include <iostream>
namespace {
static struct option g_longOptions[] = {
    {"width", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_WIDTH)},
    {"height", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_HEIGHT)},
    {"in", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_INPUT)},
    {"out", required_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_OUTPUT)},
    {"help", no_argument, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_HELP)},
    {nullptr, 0, nullptr, static_cast<int>(MyOptIndex::OPT_INDEX_UNKONWN)}};
}

bool CommandParse::Parse(int argc, char *argv[], CommandOpt &opt)
{
    while (1) {
        int optionIndex = 0;
        int c = getopt_long(argc, argv, "i:o:w:h:", g_longOptions, &optionIndex);
        if (c == -1) {
            break;
        }
        MyOptIndex index = static_cast<MyOptIndex>(c);
        switch (index) {
            case MyOptIndex::OPT_INDEX_INPUT:
                opt.fileInput = optarg;
                break;
            case MyOptIndex::OPT_INDEX_OUTPUT:
                opt.fileOutput = optarg;
                break;
            case MyOptIndex::OPT_INDEX_WIDTH:
                opt.width = std::stoi(optarg);
                break;
            case MyOptIndex::OPT_INDEX_HEIGHT:
                opt.height = std::stoi(optarg);
                break;
            default:
                ShowUsage();
                break;
        }
    }
    if (opt.fileInput == "" || opt.fileOutput == ""  || opt.width == 0 || opt.height == 0) {
        return false;
    }
    return true;
}

void CommandParse::ShowUsage()
{
    std::cout << "Options:" << std::endl;
    std::cout << " --help                     Print this help info." << std::endl;
    std::cout << " -w, --width=width          The video width." << std::endl;
    std::cout << " -h, --height=height        The video height." << std::endl;
    std::cout << " -o, --out=FILE             The file name for output file." << std::endl;
    std::cout << " -i, --in=FILE              The file name for input file." << std::endl;
}
