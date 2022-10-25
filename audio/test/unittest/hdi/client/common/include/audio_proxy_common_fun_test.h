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

#ifndef AUDIO_PROXY_COMMON_FUN_TEST_H
#define AUDIO_PROXY_COMMON_FUN_TEST_H

#include <string>
#include "hdf_base.h"
#include "audio_types.h"
#include "audio_internal.h"
#include "audio_proxy_internal.h"
#include "audio_proxy_manager.h"
#include "audio_render.h"
#include "audio_capture.h"

namespace comfun {
    const int32_t PORTNUM = 1;
    const int32_t AUDIO_CHANNELCOUNT = 2;
    const int32_t AUDIO_SAMPLE_RATE_48K = 48000;
    const int32_t DEEP_BUFFER_RENDER_PERIOD_SIZE = 4096;
    const int32_t INT_32_MAX = 0x7fffffff;
    const int32_t SILENCE_THRESHOLD = 16 * 1024;
    const int32_t DEFAULT_RENDER_SAMPLING_RATE = 48000;
    const int32_t DEEP_BUFFER_RENDER_PERIOD_COUNT = 8;
    const int32_t AUDIO_FORMAT_PCM_BIT = 16;
    const int32_t MANAGER_ADAPTER_NAME_LEN = 32;
    const int32_t AUDIO_CAPTURE_BUF_TEST = 8192 * 2;
    const int32_t AUDIO_RENDER_BUF_TEST = 1024;
    const int32_t AUDIO_ADAPTER_BUF_TEST = 1024;
    const int32_t ADAPTER_COUNT = 32;
    const int32_t DYNAMIC_LIB_PATH_MAX = 256;
    const float HALF_OF_NORMAL_VALUE = 0.5;
    const float MIN_VALUE_OUT_OF_BOUNDS = -1;
    const float MAX_VALUE_OUT_OF_BOUNDS = 2;
    using TestAudioManager = struct AudioManager;
    const std::string ADAPTER_NAME_USB = "usb";
    const std::string FUNCTION_NAME = "GetAudioManagerFuncs";
    const std::string RESOLVED_PATH = HDF_LIBRARY_FULL_PATH("libhdi_audio_client");

    void *GetDynamicLibHandle(const std::string path);
    int32_t InitPort(struct AudioPort &portIndex);
    int32_t InitHwRender(struct AudioHwRender &hwRender,
        const struct AudioDeviceDescriptor &desc, const struct AudioSampleAttributes &attrs);
    int32_t InitHwCapture(struct AudioHwCapture &hwCapture, const struct AudioDeviceDescriptor &desc,
        const struct AudioSampleAttributes &attrs);
    int32_t InitAttrs(struct AudioSampleAttributes &attrs);
    int32_t InitDevDesc(struct AudioDeviceDescriptor &devDesc);
    int32_t InitDevDesc(struct AudioDeviceDescriptor &devDesc, const uint32_t portId, int pins);
    int32_t InitAttrsCapture(struct AudioSampleAttributes &attrs);
    int32_t InitDevDescCapture(struct AudioDeviceDescriptor &devDesc);
    int32_t AudioRenderCallbackUtTest(enum AudioCallbackType type, void *reserved, void *cookie);
    int32_t GetLoadAdapter(TestAudioManager *manager, int portType,
        const std::string &adapterName, struct AudioAdapter **adapter, struct AudioPort *&audioPort);
    int32_t GetAdapters(TestAudioManager *manager, struct AudioAdapterDescriptor **descs, int &size);
    int32_t SwitchAdapter(struct AudioAdapterDescriptor *descs, const std::string &adapterNameCase,
        int portFlag, struct AudioPort *&audioPort, int size);
}
#endif
