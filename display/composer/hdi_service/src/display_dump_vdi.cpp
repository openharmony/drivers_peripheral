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

#include "display_dump_vdi.h"

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

const char *g_vdiComposerDumpHelp =
    " Get Vdi Dump Info options:\n"
    "     -cmd [name]: operate vdi dump.\n"
    "        [name]\n"
    "           buffer: dump buffer\n"
    "           user: update user config\n";

void VdiDumper::SetDumpInfoFunc(GetDumpInfoFunc DumpInfoFunc_)
{
    if (DumpInfoFunc_ == nullptr) {
        HDF_LOGE("%{public}s: SetDumpInfoFunc failed, DumpInfoFunc_ null", __func__);
    }

    getDumpInfoFunc_ = DumpInfoFunc_;
}

void VdiDumper::SetConfigFunc(UpdateConfigFunc ConfigFunc_)
{
    if (ConfigFunc_ == nullptr) {
        HDF_LOGE("%{public}s: SetConfigFunc failed, ConfigFunc_ null", __func__);
    }

    updateConfigFunc_ = ConfigFunc_;
}

int32_t VdiDumper::DumpBuffer(HdfSBuf *reply)
{
    string result;
    if (getDumpInfoFunc_ != nullptr) {
        getDumpInfoFunc_(result);
    } else {
        result += "vdi -cmd buffer not support.\n";
    }
    
    if (!HdfSbufWriteString(reply, result.c_str())) {
        HDF_LOGI("%{public}s: dump buffer failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t VdiDumper::UpdateUserConfig(HdfSBuf *reply)
{
    string result;
    if (updateConfigFunc_ != nullptr) {
        updateConfigFunc_(result);
    } else {
        result += "vdi -cmd user not support.\n";
    }
    
    if (!HdfSbufWriteString(reply, result.c_str())) {
        HDF_LOGI("%{public}s: udpate failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t VdiDumper::ShowDumpMenu(HdfSBuf *reply)
{
    if (reply != nullptr) {
        (void)HdfSbufWriteString(reply, g_vdiComposerDumpHelp);
        return HDF_SUCCESS;
    } else {
        return HDF_FAILURE;
    }
}

enum {
    DUMP_VDI_EVENT_NONE,
    DUMP_VDI_EVENT_USER,
    DUMP_VDI_EVENT_BUFFER,
};

int32_t GetDumpVdiEvent(struct HdfSBuf *data)
{
    const char *op1 = HdfSbufReadString(data);
    if (op1 == nullptr || strcmp(op1, "-cmd") != 0) {
        return DUMP_VDI_EVENT_NONE;
    }
    const char *op2 = HdfSbufReadString(data);
    if (op2 == nullptr) {
        return DUMP_VDI_EVENT_NONE;
    }
    if (strcmp(op2, "user") == 0) {
        return DUMP_VDI_EVENT_USER;
    }
    if (strcmp(op2, "buffer") == 0) {
        return DUMP_VDI_EVENT_BUFFER;
    }
    return DUMP_VDI_EVENT_NONE;
}

int32_t VdiDumper::ComposerHostDumpProcess(struct HdfSBuf *data, struct HdfSBuf *reply, uint32_t argsNum)
{
    if (reply == nullptr || data == nullptr) {
        return HDF_FAILURE;
    }
    int32_t ret;
    int32_t event = GetDumpVdiEvent(data);
    switch (event) {
        case DUMP_VDI_EVENT_USER:
            ret = UpdateUserConfig(reply);
            break;
        case DUMP_VDI_EVENT_BUFFER:
            ret = DumpBuffer(reply);
            break;
        default:
            ret = ShowDumpMenu(reply);
            break;
    }

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get composer vdi dump failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

} //namespace V1_0
} //namespace Composer
} //namespace Display
} //namespace HDI
} //namespace OHOS