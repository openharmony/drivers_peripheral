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
#ifndef COMMAND_ADAPTER_PARSE_H
#define COMMAND_ADAPTER_PARSE_H
#include <iostream>

enum class codecMime { AVC, HEVC };

struct CommandOpt {
    std::string fileInput = "";
    std::string fileOutput = "";
    uint32_t width = 0;
    uint32_t height = 0;
    bool useBuffer = false;
    codecMime codec = codecMime::AVC;
};

class CommandAdapterParse {
public:
    CommandAdapterParse() {}
    ~CommandAdapterParse() {}
    bool Parse(int argc, char *argv[], CommandOpt &opt);

private:
    void ShowUsage();
};
#endif
