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

#ifndef BLUETOOTH_A2DP_DEVICE_H
#define BLUETOOTH_A2DP_DEVICE_H

#include <cstdint>

namespace OHOS {
namespace bluetooth {
namespace audio {

enum class BTAudioStreamState : uint8_t {
    INVALID,
    IDLE,
    STARTING,
    STARTED,
    SUSPENDING
};

typedef bool (*SetUpFunc)();
typedef void (*TearDownFunc)();
typedef BTAudioStreamState (*GetStateFunc)();
typedef bool (*StartPlayingFunc)(uint32_t sampleRate, uint32_t channelCount, uint32_t format);
typedef bool (*SuspendPlayingFunc)();
typedef bool (*StopPlayingFunc)();
typedef size_t (*WriteFrameFunc)(const void* data, size_t size);
typedef int32_t (*ReqMmapBufferFunc)(int32_t ashmemLength);
typedef void (*ReadMmapPositionFunc)(int64_t &sec, int64_t &nSec, uint64_t &frames);
typedef bool (*GetLatencyFunc)(uint32_t &latency);
}
}
}

#endif