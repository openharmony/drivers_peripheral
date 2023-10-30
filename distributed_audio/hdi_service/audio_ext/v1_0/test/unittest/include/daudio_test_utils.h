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

#ifndef OHOS_DAUDIO_TEST_UTILS_H
#define OHOS_DAUDIO_TEST_UTILS_H

#include <v1_0/id_audio_callback.h>

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audioext {
namespace V1_0 {
class MockIDAudioCallback : public IDAudioCallback {
public:
    virtual ~MockIDAudioCallback() = default;

    int32_t OpenDevice(const std::string &adpName, int32_t devId) override
    {
        return 0;
    }

    int32_t CloseDevice(const std::string &adpName, int32_t devId) override
    {
        return 0;
    }

    int32_t SetParameters(const std::string &adpName, int32_t devId, const AudioParameter &param) override
    {
        return 0;
    }

    int32_t NotifyEvent(const std::string &adpName, int32_t devId, const DAudioEvent &event) override
    {
        return 0;
    }

    int32_t WriteStreamData(const std::string &adpName, int32_t devId, const AudioData &data) override
    {
        return 0;
    }

    int32_t ReadStreamData(const std::string &adpName, int32_t devId, AudioData &data) override
    {
        return 0;
    }

    int32_t ReadMmapPosition(const std::string &adpName, int32_t devId, uint64_t &frames,
        CurrentTime &time) override
    {
        return 0;
    }

    int32_t RefreshAshmemInfo(const std::string &adpName, int32_t devId, int fd,
        int32_t ashmemLength, int32_t lengthPerTrans) override
    {
        return 0;
    }
};
} // V1_0
} // AudioExt
} // Distributedaudio
} // HDI
} // OHOS
#endif // OHOS_DAUDIO_TEST_UTILS_H