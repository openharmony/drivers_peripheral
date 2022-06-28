/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "audioadmdispatchercapturecmdid_fuzzer.h"
#include "hdf_log.h"
#include "audio_hdi_common.h"
#include "audio_adm_common.h"
using namespace HMOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioAdmDispatcherCaptureCmdidFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        struct HdfIoService *service = nullptr;
        struct HdfSBuf *sBuf = nullptr;
        struct HdfSBuf *reply = nullptr;
        struct AudioPcmHwParams hwParams {
            .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .rate = 11025, .periodSize = 8192,
            .periodCount = 32, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
            .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
        };

        service = HdfIoServiceBind(HDF_CAPTURE_SERVICE.c_str());
        if (service == nullptr || service->dispatcher == nullptr) {
            HDF_LOGE("%{public}s: HdfIoServiceBind failed\n", __func__);
            return false;
        }
        sBuf = HdfSbufObtainDefaultSize();
        if (sBuf == nullptr) {
            HDF_LOGE("%{public}s: sBuf is NULL\n", __func__);
            return false;
        }
        int32_t ret = WriteHwParamsToBuf(sBuf, hwParams);
        if (ret < 0) {
            HDF_LOGE("%{public}s: Write HwParams to buf failed\n", __func__);
            return false;
        }
        int32_t cmdId = *(int32_t *)(data);
        ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
        if (ret == HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Dispatch success\n", __func__);
            result = true;
        }
        HdfSbufRecycle(sBuf);
        HdfIoServiceRecycle(service);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioAdmDispatcherCaptureCmdidFuzzTest(data, size);
    return 0;
}