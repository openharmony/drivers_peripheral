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
#include "securec.h"
#include "audiocreaterenderattrs_fuzzer.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioCreaterenderAttrsFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *attrsFuzzManager = nullptr;
    int32_t ret = GetManager(attrsFuzzManager);
    if (ret < 0 || attrsFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    struct AudioAdapter *attrsFuzzAdapter = nullptr;
    struct AudioPort *renderPort = nullptr;
    ret = GetLoadAdapter(attrsFuzzManager, &attrsFuzzAdapter, renderPort);
    if (ret < 0 || attrsFuzzAdapter == nullptr || renderPort == nullptr) {
        HDF_LOGE("%{public}s: GetLoadAdapter failed \n", __func__);
        return false;
    }
    struct AudioDeviceDescriptor devDesc = {};
    InitDevDesc(devDesc, renderPort->portId, PIN_OUT_SPEAKER);

    struct AudioRender *attrsFuzzRender = nullptr;
    struct AudioSampleAttributes attrsFuzz = {};
    int32_t copySize = sizeof(attrsFuzz) > size ? size : sizeof(attrsFuzz);
    if (memcpy_s((void *)&attrsFuzz, sizeof(attrsFuzz), data, copySize) != 0) {
        return false;
    }
    ret = attrsFuzzAdapter->CreateRender(attrsFuzzAdapter, &devDesc, &attrsFuzz, &attrsFuzzRender);
    if (ret == HDF_SUCCESS) {
        attrsFuzzAdapter->DestroyRender(attrsFuzzAdapter, attrsFuzzRender);
        result = true;
    }
    attrsFuzzManager->UnloadAdapter(attrsFuzzManager, attrsFuzzAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCreaterenderAttrsFuzzTest(data, size);
    return 0;
}