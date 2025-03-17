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
constexpr size_t THRESHOLD = 200;
constexpr int32_t OFFSET = 4;
struct AudioSceneDescriptor g_scene;
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
    return (ptr[BUFFER_INDEX_ZERO] << PCM_24_BIT) | (ptr[BUFFER_INDEX_ONE] << PCM_16_BIT) |
        (ptr[BUFFER_INDEX_TWO] << PCM_8_BIT) | (ptr[BUFFER_INDEX_THREE]);
}

static int32_t InitScene(const struct AudioSceneDescriptor *scene)
{
    if (scene == nullptr) {
        return HDF_FAILURE;
    }

    g_scene.scene = {0};
    g_scene.desc.portId = scene->desc.portId;
    g_scene.desc.pins = scene->desc.pins;
    g_scene.desc.desc = NULL;
    return HDF_SUCCESS;
}

void AudioCaptureReqMmapBuffer(struct IAudioCapture *&capture, uint8_t *&data)
{
    int32_t temp = *(reinterpret_cast<int32_t *>(data));
    struct AudioMmapBufferDescriptor desc = {
        .memoryAddress = reinterpret_cast<int8_t *>(data),
        .memoryAddressLen = *(reinterpret_cast<uint32_t *>(data)),
        .memoryFd = temp,
        .totalBufferFrames = temp,
        .transferFrameSize = temp,
        .isShareable = temp,
        .offset = temp,
        .filePath = reinterpret_cast<char *>(data),
    };
    capture->ReqMmapBuffer(capture, temp, &desc);
}

void CaptureFucSwitch(struct IAudioCapture *&capture, uint32_t cmd, const uint8_t *&rawData)
{
    uint8_t *data = const_cast<uint8_t *>(rawData);
    switch (cmd) {
        case AUDIO_CAPTURE_SET_SAMPLE_ATTR:
            capture->SetSampleAttributes(capture, reinterpret_cast<const struct AudioSampleAttributes *>(rawData));
            break;
        case AUDIO_CAPTURE_CHECK_SCENE_CAPABILITY: {
            bool supported = false;
            InitScene((const struct AudioSceneDescriptor *)(rawData));
            capture->CheckSceneCapability(capture, &g_scene, &supported);
            break;
        }
        case AUDIO_CAPTURE_SELECT_SCENE:
            InitScene((const struct AudioSceneDescriptor *)(rawData));
            capture->SelectScene(capture, &g_scene);
            break;
        case AUDIO_CAPTURE_SET_VOLUME:
            capture->SetVolume(capture, *(reinterpret_cast<float *>(data)));
            break;
        case AUDIO_CAPTURE_SET_GAIN:
            capture->SetGain(capture, *(reinterpret_cast<float *>(data)));
            break;
        case AUDIO_CAPTURE_CAPTURE_FRAME: {
            uint32_t frameLen = 0;
            uint64_t replyBytes = 0;
            int8_t frame[BUFFER_LENTH] = {0};
            capture->CaptureFrame(capture, frame, &frameLen, &replyBytes);
            break;
        }
        case AUDIO_CAPTURE_SET_EXTRA_PARAMS:
            capture->SetExtraParams(capture, reinterpret_cast<const char *>(rawData));
            break;
        case AUDIO_CAPTURE_REQ_MMAP_BUFFER: {
            AudioCaptureReqMmapBuffer(capture, data);
            break;
        }
        case AUDIO_CAPTURE_DEV_DUMP: {
            int32_t temp = *(reinterpret_cast<int32_t *>(data));
            capture->AudioDevDump(capture, temp, temp);
        }
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
    uint32_t captureId = 0;
    uint32_t cmd = Convert2Uint32(rawData);

    rawData = rawData + OFFSET;
    struct IAudioManager *manager = IAudioManagerGet(false);
    if (manager == nullptr) {
        return false;
    }
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    CaptureFucSwitch(capture, cmd, rawData);
    adapter->DestroyCapture(adapter, captureId);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioManagerRelease(manager, false);
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