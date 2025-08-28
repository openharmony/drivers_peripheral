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


#include <gtest/gtest.h>
#include "v5_0/audio_types.h"

using namespace std;
using namespace testing::ext;

namespace {
class HdfAudioUtTypesTest : public testing::Test {
public:
    virtual void SetUp();
    virtual void TearDown();
};

void HdfAudioUtTypesTest::SetUp()
{
}

void HdfAudioUtTypesTest::TearDown()
{
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioFormat001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_8_BIT, (AudioFormat)(1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_16_BIT, (AudioFormat)(1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_24_BIT, (AudioFormat)(1 << 1 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_32_BIT, (AudioFormat)(1 << 2));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_FLOAT, (AudioFormat)(1 << 2 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_MP3, (AudioFormat)(1 << 24));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_MAIN, (AudioFormat)(1 << 24 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_LC, (AudioFormat)(1 << 24 | 1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_LD, (AudioFormat)(1 << 24 | 1 << 1 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_ELD, (AudioFormat)(1 << 24 | 1 << 2));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_HE_V1, (AudioFormat)(1 << 24 | 1 << 2 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_HE_V2, (AudioFormat)(1 << 24 | 1 << 2 | 1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_EAC3, (AudioFormat)(1 << 24 | 1 << 2 | 1 << 1 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_G711A, (AudioFormat)(1 << 25 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_G711U, (AudioFormat)(1 << 25 | 1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_G726, (AudioFormat)(1 << 25 | 1 << 1 | 1 << 0));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioDeviceType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_LINEOUT, (AudioDeviceType)(1 << 0));
    EXPECT_EQ(AUDIO_HEADPHONE, (AudioDeviceType)(1 << 1));
    EXPECT_EQ(AUDIO_HEADSET, (AudioDeviceType)(1 << 2));
    EXPECT_EQ(AUDIO_USB_HEADSET, (AudioDeviceType)(1 << 3));
    EXPECT_EQ(AUDIO_USB_HEADPHONE, (AudioDeviceType)(1 << 4));
    EXPECT_EQ(AUDIO_USBA_HEADSET, (AudioDeviceType)(1 << 5));
    EXPECT_EQ(AUDIO_USBA_HEADPHONE, (AudioDeviceType)(1 << 6));
    EXPECT_EQ(AUDIO_PRIMARY_DEVICE, (AudioDeviceType)(1 << 7));
    EXPECT_EQ(AUDIO_USB_DEVICE, (AudioDeviceType)(1 << 8));
    EXPECT_EQ(AUDIO_A2DP_DEVICE, (AudioDeviceType)(1 << 9));
    EXPECT_EQ(AUDIO_HDMI_DEVICE, (AudioDeviceType)(1 << 10));
    EXPECT_EQ(AUDIO_ADAPTER_DEVICE, (AudioDeviceType)(1 << 11));
    EXPECT_EQ(AUDIO_DP_DEVICE, (AudioDeviceType)(1 << 12));
    EXPECT_EQ(AUDIO_ACCESSORY_DEVICE, (AudioDeviceType)(1 << 13));
    EXPECT_EQ(AUDIO_REMOTE_DEVICE, (AudioDeviceType)(1 << 14));
}
}