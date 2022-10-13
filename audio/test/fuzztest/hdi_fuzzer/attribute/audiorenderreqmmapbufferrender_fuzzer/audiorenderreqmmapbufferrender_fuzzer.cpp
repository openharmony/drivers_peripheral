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

#include "audiorenderreqmmapbufferrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioRenderReqmmapbufferRenderFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *reqMmapBufManager = nullptr;
        FILE *fp = fopen(AUDIO_LOW_LATENCY_RENDER_FILE.c_str(), "wb+");
        if (fp == nullptr) {
            HDF_LOGE("%{public}s: fopen failed \n", __func__);
            return false;
        }
        struct AudioAdapter *adapter = nullptr;
        struct AudioRender *render = nullptr;
        int32_t ret = AudioGetManagerCreateStartRender(reqMmapBufManager, &adapter, &render);
        if (ret < 0 || adapter == nullptr || render == nullptr || reqMmapBufManager == nullptr) {
            fclose(fp);
            HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
            return false;
        }
        bool isRender = true;
        int32_t reqSize = 0;
        struct AudioMmapBufferDescripter desc = {};
        ret = InitMmapDesc(fp, desc, reqSize, isRender);
        if (ret < 0) {
            adapter->DestroyRender(adapter, render);
            reqMmapBufManager->UnloadAdapter(reqMmapBufManager, adapter);
            fclose(fp);
            HDF_LOGE("%{public}s: InitMmapDesc failed \n", __func__);
            return false;
        }

        struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
        ret = render->attr.ReqMmapBuffer((AudioHandle)renderFuzz, reqSize, &desc);
        if (ret == HDF_SUCCESS) {
            (void)munmap(desc.memoryAddress, reqSize);
            result = true;
        }
        adapter->DestroyRender(adapter, render);
        reqMmapBufManager->UnloadAdapter(reqMmapBufManager, adapter);
        ret = fclose(fp);
        if (ret != 0) {
            return false;
        }
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioRenderReqmmapbufferRenderFuzzTest(data, size);
    return 0;
}