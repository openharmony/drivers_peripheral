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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Test audio-related APIs,functions for release audiomanager,
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio manager.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_hdimanager_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    TestAudioManager *manager = nullptr;
};

void AudioHdiManagerTest::SetUpTestCase(void) {}
void AudioHdiManagerTest::TearDownTestCase(void) {}
void AudioHdiManagerTest::SetUp(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiManagerTest::TearDown(void) {}

/**
* @tc.name  AudioReleaseAudioManagerObject_001
* @tc.desc  test ReleaseAudioManagerObject interface，Returns true if audiomanager is relaaseed successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiManagerTest, AudioReleaseAudioManagerObject_001, TestSize.Level1)
{
    bool ret;
    ASSERT_NE(nullptr, manager);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
    ASSERT_EQ(nullptr, manager->GetAllAdapters);
    ASSERT_EQ(nullptr, manager->LoadAdapter);
    ASSERT_EQ(nullptr, manager->UnloadAdapter);
}
/**
* @tc.name  AudioReleaseAudioManagerObject_002
* @tc.desc  test ReleaseAudioManagerObject interface，Returns false if setting the incoming
            parameter manager is nullptr
* @tc.type: FUNC
*/

HWTEST_F(AudioHdiManagerTest, AudioReleaseAudioManagerObject_002, TestSize.Level1)
{
    bool ret;
    ASSERT_NE(nullptr, manager);
    TestAudioManager *managerNull = nullptr;

    ret = manager->ReleaseAudioManagerObject(managerNull);
    EXPECT_FALSE(ret);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
}
/**
* @tc.name  AudioReleaseAudioManagerObject_003
* @tc.desc  test ReleaseAudioManagerObject interface，Returns false if setting the incoming
            parameter manager is illlegal
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiManagerTest, AudioReleaseAudioManagerObject_003, TestSize.Level1)
{
    bool ret;
    ASSERT_NE(nullptr, manager);
    TestAudioManager errorManager = {};

    ret = manager->ReleaseAudioManagerObject(&errorManager);
    EXPECT_FALSE(ret);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
}
/**
* @tc.name  AudioReleaseAudioManagerObject_004
* @tc.desc  test ReleaseAudioManagerObject interface，audiomanager can be getted after Releasing
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiManagerTest, AudioReleaseAudioManagerObject_004, TestSize.Level1)
{
    bool ret;
    ASSERT_NE(nullptr, manager);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);

    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
    ASSERT_NE(nullptr, manager->GetAllAdapters);
    ASSERT_NE(nullptr, manager->LoadAdapter);
    ASSERT_NE(nullptr, manager->UnloadAdapter);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
}
}
