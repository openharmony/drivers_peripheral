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
    static TestAudioManager *(*GetAudioManager)();
    static void *handleSo;
};

TestAudioManager *(*AudioHdiManagerTest::GetAudioManager)() = nullptr;
void *AudioHdiManagerTest::handleSo = nullptr;

void AudioHdiManagerTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    if (realpath(RESOLVED_PATH.c_str(), absPath) == nullptr) {
        return;
    }
    handleSo = dlopen(absPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (TestAudioManager *(*)())(dlsym(handleSo, FUNCTION_NAME.c_str()));
    if (GetAudioManager == nullptr) {
        return;
    }
}
    
void AudioHdiManagerTest::TearDownTestCase(void)
{
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
    }
void AudioHdiManagerTest::SetUp(void) {}

void AudioHdiManagerTest::TearDown(void) {}

/**
* @tc.name  Test ReleaseAudioManagerObject API via legal input
* @tc.number  SUB_Audio_HDI_ReleaseAudioManagerObject_0001
* @tc.desc  test ReleaseAudioManagerObject interface，Returns true if audiomanager is relaaseed successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiManagerTest, SUB_Audio_HDI_ReleaseAudioManagerObject_0001, TestSize.Level1)
{
    bool ret;
    TestAudioManager *manager = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = GetAudioManager();
    ASSERT_NE(nullptr, manager);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
    ASSERT_EQ(nullptr, manager->GetAllAdapters);
    ASSERT_EQ(nullptr, manager->LoadAdapter);
    ASSERT_EQ(nullptr, manager->UnloadAdapter);
}
/**
* @tc.name  Test ReleaseAudioManagerObject API via setting the incoming parameter manager is nullptr
* @tc.number  SUB_Audio_HDI_ReleaseAudioManagerObject_0002
* @tc.desc  test ReleaseAudioManagerObject interface，Returns false if setting the incoming
            parameter manager is nullptr
* @tc.author: liweiming
*/

HWTEST_F(AudioHdiManagerTest, SUB_Audio_HDI_ReleaseAudioManagerObject_0002, TestSize.Level1)
{
    bool ret;
    TestAudioManager *manager = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = GetAudioManager();
    ASSERT_NE(nullptr, manager);
    TestAudioManager *managerNull = nullptr;

    ret = manager->ReleaseAudioManagerObject(managerNull);
    EXPECT_FALSE(ret);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
}
/**
* @tc.name  Test ReleaseAudioManagerObject API via setting the incoming parameter manager is illlegal
* @tc.number  SUB_Audio_HDI_ReleaseAudioManagerObject_0003
* @tc.desc  test ReleaseAudioManagerObject interface，Returns false if setting the incoming
            parameter manager is illlegal
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiManagerTest, SUB_Audio_HDI_ReleaseAudioManagerObject_0003, TestSize.Level1)
{
    bool ret;
    TestAudioManager *manager = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = GetAudioManager();
    ASSERT_NE(nullptr, manager);
    TestAudioManager errorManager = {};

    ret = manager->ReleaseAudioManagerObject(&errorManager);
    EXPECT_FALSE(ret);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
}
/**
* @tc.name  Test ReleaseAudioManagerObject API via getting audiomanager one more time after Releasing
* @tc.number  SUB_Audio_HDI_ReleaseAudioManagerObject_0004
* @tc.desc  test ReleaseAudioManagerObject interface，audiomanager can be getted after Releasing
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiManagerTest, SUB_Audio_HDI_ReleaseAudioManagerObject_0004, TestSize.Level1)
{
    bool ret;
    TestAudioManager *manager = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = GetAudioManager();
    ASSERT_NE(nullptr, manager);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);

    manager = GetAudioManager();
    ASSERT_NE(nullptr, manager);
    ASSERT_NE(nullptr, manager->GetAllAdapters);
    ASSERT_NE(nullptr, manager->LoadAdapter);
    ASSERT_NE(nullptr, manager->UnloadAdapter);

    ret = manager->ReleaseAudioManagerObject(manager);
    EXPECT_TRUE(ret);
}
}
