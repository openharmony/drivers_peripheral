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

#include "audiorenderreqmmapbufferreqsize_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioRenderReqmmapbufferReqsizeFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *reqMmapReqManager = nullptr;
        FILE *fp = fopen(AUDIO_LOW_LATENCY_RENDER_FILE.c_str(), "wb+");
        if (fp == nullptr) {
            HDF_LOGE("%{public}s: fopen failed \n", __func__);
            return false;
        }
        struct AudioAdapter *reqMmapReqAdapter = nullptr;
        struct AudioRender *reqMmapReqRender = nullptr;
        int32_t ret = AudioGetManagerCreateStartRender(reqMmapReqManager, &reqMmapReqAdapter, &reqMmapReqRender);
        if (ret < 0 || reqMmapReqAdapter == nullptr || reqMmapReqRender == nullptr || reqMmapReqManager == nullptr) {
            fclose(fp);
            HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
            return false;
        }
        bool isRender = true;
        int32_t reqSize = 0;
        struct AudioMmapBufferDescripter desc = {};
        ret = InitMmapDesc(fp, desc, reqSize, isRender);
        if (ret < 0) {
            reqMmapReqAdapter->DestroyRender(reqMmapReqAdapter, reqMmapReqRender);
            reqMmapReqManager->UnloadAdapter(reqMmapReqManager, reqMmapReqAdapter);
            fclose(fp);
            HDF_LOGE("%{public}s: InitMmapDesc failed \n", __func__);
            return false;
        }
        reqSize = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data)));
        ret = reqMmapReqRender->attr.ReqMmapBuffer((AudioHandle)reqMmapReqRender, reqSize, &desc);
        if (ret == HDF_SUCCESS) {
            (void)munmap(desc.memoryAddress, reqSize);
            result = true;
        }
        reqMmapReqAdapter->DestroyRender(reqMmapReqAdapter, reqMmapReqRender);
        reqMmapReqManager->UnloadAdapter(reqMmapReqManager, reqMmapReqAdapter);
        (void)fclose(fp);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioRenderReqmmapbufferReqsizeFuzzTest(data, size);
    return 0;
}