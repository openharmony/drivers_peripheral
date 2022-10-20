/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "command_adapter_parse.h"
#include <getopt.h>

namespace {
    enum class MyOptIndex {
        OPT_INDEX_UNKONWN = 0,
        OPT_INDEX_BUFFER_HANDLE,
        OPT_INDEX_HEVC,
        OPT_INDEX_HELP,
        OPT_INDEX_HEIGHT = 'h',
        OPT_INDEX_INPUT = 'i',
        OPT_INDEX_OUTPUT = 'o',
        OPT_INDEX_WIDTH = 'w'
    };
}

bool CommandAdapterParse::Parse(int argc, char *argv[], CommandOpt &opt)
{
    while (1) {
        int optionIndex = 0;
        static struct option long_options[] = {
            {"width",  required_argument, 0,    (int)MyOptIndex::OPT_INDEX_WIDTH  },
            {"height", required_argument, 0,    (int)MyOptIndex::OPT_INDEX_HEIGHT },
            {"in",     required_argument, 0,    (int)MyOptIndex::OPT_INDEX_INPUT  },
            {"out",    required_argument, 0,    (int)MyOptIndex::OPT_INDEX_OUTPUT },
            {"help",   no_argument,       NULL, (int)MyOptIndex::OPT_INDEX_HELP   },
            {0,        0,                 0,    (int)MyOptIndex::OPT_INDEX_UNKONWN}
        };
        int c = getopt_long(argc, argv, "i:o:w:h:", long_options, &optionIndex);
        if (c == -1) {
            break;
        }
        MyOptIndex index = (MyOptIndex)c;
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

void CommandAdapterParse::ShowUsage()
{
    std::cout << "Options:" << std::endl;
    std::cout << " -w, --width=width          The video width." << std::endl;
    std::cout << " -h, --height=height        The video height." << std::endl;
    std::cout << " -o, --out=FILE             The file name for output file." << std::endl;
    std::cout << " -i, --in=FILE              The file name for input file." << std::endl;
    std::cout << " --help                     The help info." << std::endl;
}
