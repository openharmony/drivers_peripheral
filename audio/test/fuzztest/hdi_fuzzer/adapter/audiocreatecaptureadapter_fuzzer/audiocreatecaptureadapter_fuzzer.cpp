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
#include "audiocreatecaptureadapter_fuzzer.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioCreateCaptureAdapterFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *adapterFuzzManager = nullptr;
    int32_t ret = GetManager(adapterFuzzManager);
    if (ret < 0 || adapterFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    struct AudioAdapter *adapterFuzzAdapter = nullptr;
    struct AudioPort *adapterFuzzCapturePort = nullptr;
    ret = GetLoadAdapter(adapterFuzzManager, &adapterFuzzAdapter, adapterFuzzCapturePort);
    if (ret < 0 || adapterFuzzAdapter == nullptr || adapterFuzzCapturePort == nullptr) {
        HDF_LOGE("%{public}s: GetLoadAdapter failed \n", __func__);
        return false;
    }
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    InitAttrs(attrs);
    InitDevDesc(devDesc, adapterFuzzCapturePort->portId, PIN_IN_MIC);

    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapterFuzz = reinterpret_cast<struct AudioAdapter *>(const_cast<uint8_t *>(data));
    ret = adapterFuzzAdapter->CreateCapture(adapterFuzz, &devDesc, &attrs, &capture);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    adapterFuzzAdapter->DestroyCapture(adapterFuzzAdapter, capture);
    adapterFuzzManager->UnloadAdapter(adapterFuzzManager, adapterFuzzAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCreateCaptureAdapterFuzzTest(data, size);
    return 0;
}