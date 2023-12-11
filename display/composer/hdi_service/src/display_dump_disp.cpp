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

#include "display_dump_disp.h"

#include <string>
#include <securec.h>
#include <cstdio>
#include <dlfcn.h>

#include "devhost_dump_reg.h"
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG uhdf_composer_host

namespace OHOS {
namespace HDI {
namespace Display {
namespace Composer {
namespace V1_0 {

using namespace OHOS::HDI::Display::Composer::V1_0;

const char *g_dispComposerDumpHelp =
    " Get Display Dump Info options:\n"
    "     -cmd: operate display dump, not support\n";

int32_t DisplayDumper::ShowDumpMenu(struct HdfSBuf *reply)
{
    if (reply != nullptr) {
        (void)HdfSbufWriteString(reply, g_dispComposerDumpHelp);
        return HDF_SUCCESS;
    } else {
        return HDF_FAILURE;
    }
}

int32_t DisplayDumper::ComposerHostDumpProcess(struct HdfSBuf *data, struct HdfSBuf *reply, uint32_t argsNum)
{
    int32_t ret = ShowDumpMenu(reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get composer display dump failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
} //namespace V1_0
} //namespace Composer
} //namespace Display
} //namespace HDI
} //namespace OHOS