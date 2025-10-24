/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "backtrace_local.h"
#include <hdf_log.h>
#include <sstream>
#include "dump_backtrace.h"
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
void Dumpbacktrace(void)
{
    std::string msg = "";
    msg = OHOS::HiviewDFX::GetProcessStacktrace();
    if (!msg.empty()) {
        std::vector<std::string> out;
        std::stringstream ss(msg);
        std::string s;
        while (std::getline(ss, s, '\n')) {
            out.push_back(s);
        }
        HDF_LOGI("capture current process stacks except current calling thread.");
        for (auto const& line : out) {
            HDF_LOGI("%{public}s", line.c_str());
        }
    }
}
#ifdef __cplusplus
}
#endif
