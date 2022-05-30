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
        TestAudioManager *manager = nullptr;
        struct AudioAdapter *adapter = nullptr;
        struct AudioCapture *capture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(manager, &adapter, &capture);
        if (ret < 0 || adapter == nullptr || capture == nullptr || manager == nullptr) {
            return false;
        }
        FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
        if (fp == nullptr) {
            adapter->DestroyCapture(adapter, capture);
            manager->UnloadAdapter(manager, adapter);
            return false;
        }
        ret = capture->control.Start((AudioHandle)capture);
        if (ret < 0 || manager == nullptr) {
            adapter->DestroyCapture(adapter, capture);
            manager->UnloadAdapter(manager, adapter);
            fclose(fp);
            return false;
        }
        bool isRender = false;
        int32_t reqSize = 0;
        struct AudioMmapBufferDescripter desc = {};
        ret = InitMmapDesc(fp, desc, reqSize, isRender);
        if (ret < 0 || manager == nullptr) {
            adapter->DestroyCapture(adapter, capture);
            manager->UnloadAdapter(manager, adapter);
            fclose(fp);
            return false;
        }
        reqSize = *(int32_t *)data;
        ret = capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, &desc);
        if (ret == HDF_SUCCESS) {
            (void)munmap(desc.memoryAddress, reqSize);
            result = true;
        }
        adapter->DestroyCapture(adapter, capture);
        manager->UnloadAdapter(manager, adapter);
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