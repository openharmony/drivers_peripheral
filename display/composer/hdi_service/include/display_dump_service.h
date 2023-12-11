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

#ifndef DISPLAY_DUMP_SERVICE_H
#define DISPLAY_DUMP_SERVICE_H

#include <securec.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "hdf_sbuf.h"
#include "devhost_dump_reg.h"
#include "display_log.h"
#include "display_dump_disp.h"
#include "display_dump_vdi.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
namespace V1_0 {

using namespace OHOS::HDI::Display::Composer::V1_0;
int32_t ComposerDumpEvent(struct HdfSBuf *data, struct HdfSBuf *reply);
} //namespace V1_0
} //namespace Composer
} //namespace Display
} //namespace HDI
} //namespace OHOS
#endif