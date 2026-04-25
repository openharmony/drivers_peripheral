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

#include <iostream>
#include <memory>
#include <vector>
#include "command_parse.h"
#include "zencoder_tester.h"

using namespace OHOS::HDI::Codec::Zcodec;
using namespace OHOS::HDI::Codec::Zcodec;
using namespace std;

int main(int argc, char *argv[])
{
    CommandOpt opt = Parse(argc, argv);
    opt.Print();

    std::vector<std::shared_ptr<TestZEncoder>> encVec;
    int instanceNum = opt.instanceNum; // 多实例并发

    for (int i = 1; i <= instanceNum; i++) {
        auto instance = std::make_shared<TestZEncoder>(opt, i);  // 传入实例ID
        instance->RunOnThread();
        encVec.emplace_back(instance);
    }

    return 0;
}