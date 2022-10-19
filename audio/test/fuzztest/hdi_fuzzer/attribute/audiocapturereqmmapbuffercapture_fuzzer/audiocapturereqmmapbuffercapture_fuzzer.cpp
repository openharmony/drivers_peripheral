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

#include "audiocapturereqmmapbuffercapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioCaptureReqmmapbufferCaptureFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *mmapBufferFuzzManager = nullptr;
        struct AudioAdapter *mmapBufferFuzzAdapter = nullptr;
        struct AudioCapture *mmapBufferFuzzCapture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(mmapBufferFuzzManager,
            &mmapBufferFuzzAdapter, &mmapBufferFuzzCapture);
        if (ret < 0 || mmapBufferFuzzAdapter == nullptr ||
            mmapBufferFuzzCapture == nullptr || mmapBufferFuzzManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
            return false;
        }
        FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
        if (fp == nullptr) {
            mmapBufferFuzzAdapter->DestroyCapture(mmapBufferFuzzAdapter, mmapBufferFuzzCapture);
            mmapBufferFuzzManager->UnloadAdapter(mmapBufferFuzzManager, mmapBufferFuzzAdapter);
            HDF_LOGE("%{public}s: fopen failed \n", __func__);
            return false;
        }
        ret = mmapBufferFuzzCapture->control.Start((AudioHandle)mmapBufferFuzzCapture);
        if (ret < 0) {
            mmapBufferFuzzAdapter->DestroyCapture(mmapBufferFuzzAdapter, mmapBufferFuzzCapture);
            mmapBufferFuzzManager->UnloadAdapter(mmapBufferFuzzManager, mmapBufferFuzzAdapter);
            fclose(fp);
            HDF_LOGE("%{public}s: Start failed \n", __func__);
            return false;
        }
        bool isRender = true;
        int32_t reqSize = 0;
        struct AudioMmapBufferDescripter desc = {};
        ret = InitMmapDesc(fp, desc, reqSize, isRender);
        if (ret < 0) {
            mmapBufferFuzzAdapter->DestroyCapture(mmapBufferFuzzAdapter, mmapBufferFuzzCapture);
            mmapBufferFuzzManager->UnloadAdapter(mmapBufferFuzzManager, mmapBufferFuzzAdapter);
            (void)fclose(fp);
            HDF_LOGE("%{public}s: InitMmapDesc failed \n", __func__);
            return false;
        }

        struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
        ret = mmapBufferFuzzCapture->attr.ReqMmapBuffer((AudioHandle)captureFuzz, reqSize, &desc);
        if (ret == HDF_SUCCESS) {
            (void)munmap(desc.memoryAddress, reqSize);
            result = true;
        }
        mmapBufferFuzzAdapter->DestroyCapture(mmapBufferFuzzAdapter, mmapBufferFuzzCapture);
        mmapBufferFuzzManager->UnloadAdapter(mmapBufferFuzzManager, mmapBufferFuzzAdapter);
        (void)fclose(fp);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCaptureReqmmapbufferCaptureFuzzTest(data, size);
    return 0;
}