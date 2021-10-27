/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

using namespace HMOS::Audio;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TestAudioManager *manager = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(manager, &adapter, &capture);
    if (ret < 0 || adapter == nullptr || capture == nullptr || manager == nullptr) {
        return ret;
    }
    uint64_t replyBytes = 0;
    char *frame = (char *)calloc(1, BUFFER_LENTH);
    if (frame == NULL) {
        return HDF_FAILURE;
    }
    uint64_t requestBytesFuzz = size;
    capture->CaptureFrame(capture, frame, requestBytesFuzz, &replyBytes);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
    capture = nullptr;
    free(frame);
    frame = nullptr;
    return 0;
}
