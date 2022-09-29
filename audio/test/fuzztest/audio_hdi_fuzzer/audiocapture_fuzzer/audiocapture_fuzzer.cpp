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
#include "audiocapture_fuzzer.h"
#include "hdi_service_common.h"
using namespace std;
namespace OHOS {
namespace Audio {
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;

enum CaptureCmdId {
    AUDIO_CAPTURE_SET_SAMPLE_ATTR,
    AUDIO_CAPTURE_CHECK_SCENE_CAPABILITY,
    AUDIO_CAPTURE_SELECT_SCENE,
    AUDIO_CAPTURE_SET_VOLUME,
    AUDIO_CAPTURE_SET_GAIN,
    AUDIO_CAPTURE_CAPTURE_FRAME,
    AUDIO_CAPTURE_SET_EXTRA_PARAMS,
    AUDIO_CAPTURE_REQ_MMAP_BUFFER, 
    AUDIO_CAPTURE_DEV_DUMP,
};

static uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}
void CaptureFucSwitch(struct IAudioCapture *&capture, uint32_t cmd, const uint8_t *&rawData)
{
    switch(cmd) {
        case AUDIO_CAPTURE_SET_SAMPLE_ATTR:
            capture->SetSampleAttributes(capture, reinterpret_cast<const struct AudioSampleAttributes *>(rawData));
            break;
        case AUDIO_CAPTURE_CHECK_SCENE_CAPABILITY: {
            bool supported = false;
            capture->CheckSceneCapability(capture, reinterpret_cast<const struct AudioSceneDescriptor *>(rawData),
                                          &supported);
            break;
        }
        case AUDIO_CAPTURE_SELECT_SCENE:
            capture->SelectScene(capture, reinterpret_cast<const struct AudioSceneDescriptor *>(rawData));
            break;
        case AUDIO_CAPTURE_SET_VOLUME:
            capture->SetVolume(capture, *(float *)rawData);
            break;
        case AUDIO_CAPTURE_SET_GAIN:
            capture->SetGain(capture, *(float *)rawData);
            break;
        case AUDIO_CAPTURE_CAPTURE_FRAME: {
            uint32_t replyBytes = 0;
            int8_t frame[BUFFER_LENTH] = {0};
            capture->CaptureFrame(capture, frame, &replyBytes, reinterpret_cast<const uint64_t>(rawData));
            break;
        }
        case AUDIO_CAPTURE_SET_EXTRA_PARAMS:
            capture->SetExtraParams(capture, reinterpret_cast<const char *>(rawData));
            break;
        case AUDIO_CAPTURE_REQ_MMAP_BUFFER:
            capture->ReqMmapBuffer(capture, *(int32_t *)rawData, 
                                   reinterpret_cast<const struct AudioMmapBufferDescripter *>(rawData));
        break;
        case AUDIO_CAPTURE_DEV_DUMP:
            capture->AudioDevDump(capture, *(int *)rawData, *(int *)rawData);
            break;
        default:
            return;
    }
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    uint32_t cmd = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;
    struct IAudioManager *manager = IAudioManagerGet(true);
    if (manager == nullptr) {
        return false;
    }
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    CaptureFucSwitch(capture, cmd, rawData);
    adapter->DestroyCapture(adapter, nullptr);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioManagerRelease(manager, true);
    return true;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::Audio::THRESHOLD) {
        return 0;
    }
    OHOS::Audio::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}