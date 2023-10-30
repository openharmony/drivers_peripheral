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

#ifndef HDF_I_AUDIO_VOLUME_H
#define HDF_I_AUDIO_VOLUME_H

namespace OHOS {
namespace DistributedHardware {
class IAudioVolume {
public:
    virtual int32_t SetMute(const bool mute) = 0;

    virtual int32_t GetMute(bool &mute) = 0;

    virtual int32_t SetVolume(const float volume) = 0;

    virtual int32_t GetVolume(float &volume) = 0;

    virtual int32_t GetGainThreshold(float &min, float &max) = 0;

    virtual int32_t SetGain(const float gain) = 0;

    virtual int32_t GetGain(float &gain) = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // HDF_I_AUDIO_VOLUME_H