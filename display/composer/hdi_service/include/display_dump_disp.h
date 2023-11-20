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

#ifndef DISPLAY_DUMP_DISP_H
#define DISPLAY_DUMP_DISP_H

#include <securec.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "hdf_sbuf.h"
#include "devhost_dump_reg.h"
#include "display_log.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
namespace V1_0 {

using namespace OHOS::HDI::Display::Composer::V1_0;

class DisplayDumper {
public:
    ~DisplayDumper() {};
    int32_t ShowDumpMenu(struct HdfSBuf *reply);
    int32_t ComposerHostDumpProcess(struct HdfSBuf *data, struct HdfSBuf *reply, uint32_t argsNum);
    static DisplayDumper& GetInstance()
    {
        static DisplayDumper instance_;
        return instance_;
    }
private:
    DisplayDumper() {};
};

} //namespace V1_0
} //namespace Composer
} //namespace Display
} //namespace HDI
} //namespace OHOS
#endif