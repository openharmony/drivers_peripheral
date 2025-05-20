/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_TEST_UTILS_H
#define OHOS_DAUDIO_TEST_UTILS_H

#include <v2_0/id_audio_manager.h>

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audioext {
namespace V2_0 {
class MockIDAudioCallback : public IDAudioCallback {
public:
    virtual ~MockIDAudioCallback() = default;

    int32_t CreateStream(int32_t streamId) override
    {
        return 0;
    }

    int32_t DestroyStream(int32_t streamId) override
    {
        return 0;
    }

    int32_t SetParameters(int32_t streamId, const AudioParameter &param) override
    {
        return 0;
    }

    int32_t NotifyEvent(int32_t streamId, const DAudioEvent &event) override
    {
        return 0;
    }

    int32_t WriteStreamData(int32_t streamId, const AudioData &data) override
    {
        return 0;
    }

    int32_t ReadStreamData(int32_t streamId, AudioData &data) override
    {
        return 0;
    }

    int32_t ReadMmapPosition(int32_t streamId, uint64_t &frames, CurrentTime &time) override
    {
        return 0;
    }

    int32_t RefreshAshmemInfo(int32_t streamId, int fd, int32_t ashmemLength, int32_t lengthPerTrans) override
    {
        return 0;
    }
};

class MockIDAudioHdfCallback : public IDAudioHdfCallback {
public:
    virtual ~MockIDAudioHdfCallback() = default;

    int32_t NotifyEvent(int32_t devId, const DAudioEvent& event) override
    {
        return 0;
    }
};
} // V2_0
} // AudioExt
} // Distributedaudio
} // HDI
} // OHOS
#endif // OHOS_DAUDIO_TEST_UTILS_H