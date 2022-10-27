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
#include "audio_hdi_fuzzer_common.h"
#include "audiodestroycapturecapture_fuzzer.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioDestroycaptureCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *destroyCapFuzzManager = nullptr;
    int32_t ret = GetManager(destroyCapFuzzManager);
    if (ret < 0 || destroyCapFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    struct AudioAdapter *destroyFuzzAdapter = nullptr;
    struct AudioPort *capturePort = nullptr;
    ret = GetLoadAdapter(destroyCapFuzzManager, &destroyFuzzAdapter, capturePort);
    if (ret < 0 || destroyFuzzAdapter == nullptr) {
        HDF_LOGE("%{public}s: GetLoadAdapter failed \n", __func__);
        return false;
    }

    struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = destroyFuzzAdapter->DestroyCapture(destroyFuzzAdapter, captureFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    destroyCapFuzzManager->UnloadAdapter(destroyCapFuzzManager, destroyFuzzAdapter);
    return result;
}
}
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioDestroycaptureCaptureFuzzTest(data, size);
    return 0;
}