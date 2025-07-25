/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_AUDIO_RENDER_EXT_IMPL_TEST_H
#define OHOS_AUDIO_RENDER_EXT_IMPL_TEST_H

#include <gtest/gtest.h>

#include <v1_0/audio_types.h>
#include <v1_0/iaudio_render.h>
#include <v2_1/id_audio_manager.h>

#include "audio_test_utils.h"
#include "audio_render_ext_impl.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
using OHOS::HDI::DistributedAudio::Audioext::V2_1::AudioData;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::AudioParameter;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::IDAudioCallback;

class AudioRenderExtImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::string adpName_;
    AudioDeviceDescriptor desc_;
    AudioSampleAttributes attrs_;
    sptr<IDAudioCallback> callback_;
    std::shared_ptr<AudioRenderExtImpl> audioRenderlatencyImpl_ = nullptr;
};
} // namespace V1_0
} // namespace Audio
} // namespace Distributedaudio
} // namespace HDI
} // namespace OHOS
#endif //OHOS_AUDIO_RENDER_EXT_IMPL_TEST_H
