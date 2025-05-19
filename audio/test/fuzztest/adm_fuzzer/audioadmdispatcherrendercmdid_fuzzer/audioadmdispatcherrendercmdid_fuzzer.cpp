/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "audioadmdispatcherrendercmdid_fuzzer.h"
#include "hdf_log.h"
#include "audio_hdi_common.h"
#include "audio_adm_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioAdmDispatcherRenderCmdidFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        struct HdfIoService *admDisRenFuzzService = nullptr;
        struct HdfSBuf *sBuf = nullptr;
        struct HdfSBuf *reply = nullptr;
        struct AudioPcmHwParams hwParams {
            .streamType = AUDIO_RENDER_STREAM, .channels = AUDIO_CHANNEL_BOTH_RIGHT,
            .rate = BROADCAST_AM_RATE, .periodSize = FRAME_DATA / 2,
            .periodCount = 32, .format = AUDIO_FORMAT_TYPE_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
            .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
        };

        admDisRenFuzzService = HdfIoServiceBind(HDF_RENDER_SERVICE.c_str());
        if (admDisRenFuzzService == nullptr || admDisRenFuzzService->dispatcher == nullptr) {
            HDF_LOGE("%{public}s: HdfIoServiceBind failed \n", __func__);
            return false;
        }
        sBuf = HdfSbufObtainDefaultSize();
        if (sBuf == nullptr) {
            HDF_LOGE("%{public}s: sBuf is NULL \n", __func__);
            return false;
        }
        int32_t ret = WriteHwParamsToBuf(sBuf, hwParams);
        if (ret < 0) {
            HDF_LOGE("%{public}s: Write hwparams to buffer failed \n", __func__);
            return false;
        }
        if (size < sizeof(int32_t)) {
            return false;
        }
        int32_t cmdId = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data)));
        ret = admDisRenFuzzService->dispatcher->Dispatch(&admDisRenFuzzService->object, cmdId, sBuf, reply);
        if (ret == HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Dispatch sucess \n", __func__);
            result = true;
        }
        HdfSbufRecycle(sBuf);
        HdfIoServiceRecycle(admDisRenFuzzService);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioAdmDispatcherRenderCmdidFuzzTest(data, size);
    return 0;
}
