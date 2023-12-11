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

#include "display_dump_service.h"

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

using namespace std;
using namespace OHOS::HDI::Display::Composer::V1_0;

const char *g_composerDumpHelp =
    " Composer Host dump options:\n"
    "     -module [name]: get dump info.\n"
    "          [name]\n"
    "             vdi: get vdi dump info\n"
    "             display: get display dump info";

static int32_t ShowDumpMenu(struct HdfSBuf *reply)
{
    (void)HdfSbufWriteString(reply, g_composerDumpHelp);
    return HDF_SUCCESS;
}

enum {
    DUMP_EVENT_NONE,
    DUMP_EVENT_VDI,
    DUMP_EVENT_DISPLAY,
};

static int32_t GetDumpEvent(struct HdfSBuf *data, uint32_t *argsNum)
{
    if (!HdfSbufReadUint32(data, argsNum)) {
        HDF_LOGE("%{public}s: read argsNum failed!", __func__);
        return DUMP_EVENT_NONE;
    }
    const char *op1 = HdfSbufReadString(data);
    if (op1 == nullptr || strcmp(op1, "-module") != 0) {
        return DUMP_EVENT_NONE;
    }
    const char *op2 = HdfSbufReadString(data);
    if (op2 == nullptr) {
        return DUMP_EVENT_NONE;
    }
    if (strcmp(op2, "vdi") == 0) {
        return DUMP_EVENT_VDI;
    }
    if (strcmp(op2, "display") == 0) {
        return DUMP_EVENT_DISPLAY;
    }
    return DUMP_EVENT_NONE;
}

int32_t ComposerDumpEvent(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data == nullptr || reply == nullptr) {
        HDF_LOGE("%{public}s: %{public}s is nullptr", __func__, (data == nullptr) ? "data" : "reply");
        return HDF_FAILURE;
    }

    int32_t ret;
    uint32_t argsNum = 0;
    int32_t event = GetDumpEvent(data, &argsNum);
    VdiDumper &vdiDumper = VdiDumper::GetInstance();
    DisplayDumper &dispDumper = DisplayDumper::GetInstance();
    switch (event) {
        case DUMP_EVENT_VDI:
            ret = vdiDumper.ComposerHostDumpProcess(data, reply, argsNum);
            break;
        case DUMP_EVENT_DISPLAY:
            ret = dispDumper.ComposerHostDumpProcess(data, reply, argsNum);
            break;
        default:
            ret = ShowDumpMenu(reply);
            break;
    }
    
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get composer dump failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

} //namespace V1_0
} //namespace Composer
} //namespace Display
} //namespace HDI
} //namespace OHOS