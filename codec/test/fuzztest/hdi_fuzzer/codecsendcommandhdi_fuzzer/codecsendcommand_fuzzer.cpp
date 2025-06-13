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

#include "codecsendcommand_fuzzer.h"
#include "codeccommon_fuzzer.h"

#include <securec.h>
#include <unistd.h>

using namespace OHOS::HDI::Codec::V4_0;
using OHOS::HDI::Codec::V4_0::CodecCommandType;
using OHOS::HDI::Codec::V4_0::CodecStateType;

namespace {
    struct AllParameters {
        enum CodecCommandType cmd;
        uint32_t param;
        int8_t *cmdData;
        uint32_t cmdDataLen;
    };
    constexpr uint32_t WAIT_TIME = 1000;
    constexpr uint32_t MAX_WAIT = 50;
}

namespace OHOS {
namespace Codec {
    void WaitState(CodecStateType objState)
    {
        CodecStateType state = CODEC_STATE_INVALID;
        uint32_t count = 0;
        do {
            usleep(WAIT_TIME);
            g_component->GetState(state);
            count++;
        } while (state != objState && count <= MAX_WAIT);
    }

    bool CodecSendCommand(const uint8_t *data, size_t size)
    {
        struct AllParameters params;
        if (data == nullptr) {
            return false;
        }

        if (size < sizeof(params)) {
            return false;
        }

        if (memcpy_s(reinterpret_cast<void *>(&params), sizeof(params), data, sizeof(params)) != 0) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            return false;
        }

        bool result = Preconditions();
        if (!result) {
            HDF_LOGE("%{public}s: Preconditions failed\n", __func__);
            return false;
        }

        std::vector<int8_t> cmdData;
        ObjectToVector(params.cmdData, cmdData);

        int32_t ret = g_component->SendCommand(params.cmd, params.param, cmdData);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: SendCommand failed, ret is [%{public}x]\n", __func__, ret);
        }
        CodecStateType type = CodecStateType(params.param);
        WaitState(type);

        if (params.cmd == CODEC_COMMAND_STATE_SET && params.param == CODEC_STATE_IDLE) {
            g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
            WaitState(CODEC_STATE_LOADED);
        }

        result = Destroy();
        if (!result) {
            HDF_LOGE("%{public}s: Destroy failed\n", __func__);
            return false;
        }

        return true;
    }
} // namespace codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::CodecSendCommand(data, size);
    return 0;
}
