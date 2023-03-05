/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HDF_TRACE_H
#define HDF_TRACE_H

#include "hitrace_meter.h"

class HdfTrace {
public:
    inline HdfTrace(const std::string &value, const std::string &prefix = "")
    {
        StartTrace(HITRACE_TAG_HDF, prefix + value);
    }
    inline void End() const
    {
        FinishTrace(HITRACE_TAG_HDF);
    }
    inline ~HdfTrace()
    {
        End();
    }
};

#endif // HDF_TRACE_H
