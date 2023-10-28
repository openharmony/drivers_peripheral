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

#ifndef HDF_I_AUDIO_ATTRIBUTE_H
#define HDF_I_AUDIO_ATTRIBUTE_H

namespace OHOS {
namespace DistributedHardware {
class IAudioAttribute {
    virtual int32_t GetFrameSize(uint64_t &size) = 0;

    virtual int32_t GetFrameCount(uint64_t &count) = 0;

    virtual int32_t SetSampleAttributes(const AudioSampleAttributesHAL &attrs) = 0;

    virtual int32_t GetSampleAttributes(AudioSampleAttributesHAL &attrs) = 0;

    virtual int32_t GetCurrentChannelId(uint32_t &channelId) = 0;

    virtual int32_t SetExtraParams(const std::string &keyValueList) = 0;

    virtual int32_t GetExtraParams(std::string &keyValueList) = 0;

    virtual int32_t ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptorHAL &desc) = 0;

    virtual int32_t GetMmapPosition(uint64_t &frames, AudioTimeStampHAL &time) = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // HDF_I_AUDIO_ATTRIBUTE_H