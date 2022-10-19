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

#include "audiocapturereqmmapbufferreqsize_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioCaptureReqmmapbufferReqsizeFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *reqSizeFuzzManager = nullptr;
        struct AudioAdapter *reqSizeFuzzAdapter = nullptr;
        struct AudioCapture *reqSizeFuzzCapture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(reqSizeFuzzManager, &reqSizeFuzzAdapter, &reqSizeFuzzCapture);
        if (ret < 0 || reqSizeFuzzAdapter == nullptr ||
            reqSizeFuzzCapture == nullptr || reqSizeFuzzManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
            return false;
        }
        FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
        if (fp == nullptr) {
            reqSizeFuzzAdapter->DestroyCapture(reqSizeFuzzAdapter, reqSizeFuzzCapture);
            reqSizeFuzzManager->UnloadAdapter(reqSizeFuzzManager, reqSizeFuzzAdapter);
            HDF_LOGE("%{public}s: fopen failed \n", __func__);
            return false;
        }
        ret = reqSizeFuzzCapture->control.Start((AudioHandle)reqSizeFuzzCapture);
        if (ret < 0) {
            reqSizeFuzzAdapter->DestroyCapture(reqSizeFuzzAdapter, reqSizeFuzzCapture);
            reqSizeFuzzManager->UnloadAdapter(reqSizeFuzzManager, reqSizeFuzzAdapter);
            fclose(fp);
            HDF_LOGE("%{public}s: Start failed \n", __func__);
            return false;
        }
        bool isRender = false;
        int32_t reqSize = 0;
        struct AudioMmapBufferDescripter desc = {};
        ret = InitMmapDesc(fp, desc, reqSize, isRender);
        if (ret < 0) {
            reqSizeFuzzAdapter->DestroyCapture(reqSizeFuzzAdapter, reqSizeFuzzCapture);
            reqSizeFuzzManager->UnloadAdapter(reqSizeFuzzManager, reqSizeFuzzAdapter);
            fclose(fp);
            HDF_LOGE("%{public}s: InitMmapDesc failed \n", __func__);
            return false;
        }
        reqSize = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data)));
        ret = reqSizeFuzzCapture->attr.ReqMmapBuffer((AudioHandle)reqSizeFuzzCapture, reqSize, &desc);
        if (ret == HDF_SUCCESS) {
            (void)munmap(desc.memoryAddress, reqSize);
            result = true;
        }
        reqSizeFuzzAdapter->DestroyCapture(reqSizeFuzzAdapter, reqSizeFuzzCapture);
        reqSizeFuzzManager->UnloadAdapter(reqSizeFuzzManager, reqSizeFuzzAdapter);
        (void)fclose(fp);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCaptureReqmmapbufferReqsizeFuzzTest(data, size);
    return 0;
}