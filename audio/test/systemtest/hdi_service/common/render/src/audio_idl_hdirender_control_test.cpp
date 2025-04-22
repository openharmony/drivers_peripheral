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

#include <gtest/gtest.h>
#include "hdi_service_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioIdlHdiRenderControlTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioRender *render = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    static TestAudioManager *manager;
    uint32_t renderId_ = 0;
};

TestAudioManager *AudioIdlHdiRenderControlTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiRenderControlTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiRenderControlTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiRenderControlTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render, &renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderControlTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render, renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
    * @tc.name  AudioRenderStart_001
    * @tc.desc    Test AudioRenderStart interface,return 0 if the audiorender object is created successfully.
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderStart_001, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderStartNull_002
    * @tc.desc    Test AudioRenderStart interface, return -3/-4 if the  incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderStartNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(renderNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioRenderStart_003
* @tc.desc    Test AudioRenderStart interface,return -7003 the second time if the RenderStart is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderStart_003, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Start(render);
    ASSERT_TRUE(ret == AUDIO_HAL_ERR_AO_BUSY || ret == HDF_FAILURE);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderStop_001
* @tc.desc    test AudioRenderStop interface. return 0 if the rendering is successfully stopped.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderStop_001, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderStop_002
* @tc.desc    test AudioRenderStop interface. return -4 if the render does not start and stop only
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderStop_002, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Stop(render);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_FAILURE);
}
/**
* @tc.name  AudioRenderStop_003
* @tc.desc    Test RenderStop interface,return -4 the second time if the RenderStop is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderStop_003, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_FAILURE);
}
/**
* @tc.name  AudioRenderStopNull_004
* @tc.desc    Test RenderStop interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderStopNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(renderNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderPause_01
    * @tc.desc    test HDI RenderPause interface，return 0 if the render is paused after start
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderPause_001, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderPause_002
* @tc.desc    Test AudioRenderPause interface, return -1 the second time if RenderPause is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderPause_002, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Pause(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    render->Stop(render);
}
/**
* @tc.name  AudioRenderPause_003
* @tc.desc    Test AudioRenderPause interface,return -1 if the render is paused after created.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderPause_003, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioRenderPause_004
* @tc.desc    Test AudioRenderPause interface,return 0 if the render is paused after resumed.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderPause_004, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Resume(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderPause_005
* @tc.desc    Test AudioRenderPause interface, return -1 the render is paused after stopped.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderPause_005, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioRenderPauseNull_006
* @tc.desc    Test RenderPause interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderPauseNull_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(renderNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderResume_001
    * @tc.desc    test HDI RenderResume interface,return -1 if the render is resumed after started
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderResume_001, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Resume(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderResume_002
    * @tc.desc    test HDI RenderResume interface,return -1 if the render is resumed after stopped
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderResume_002, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Resume(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
    * @tc.name  AudioRenderResume_003
    * @tc.desc    Test AudioRenderResume interface,return 0 if the render is resumed after paused
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderResume_003, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Resume(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderResume_004
    * @tc.desc    Test RenderResume interface,return -1 the second time if the RenderResume is called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderResume_004, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Resume(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Resume(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderResume_005
    * @tc.desc    test HDI RenderResume interface,return -1 if the render Continue to start after resume
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderResume_005, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Resume(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Start(render);
    ASSERT_TRUE(ret == AUDIO_HAL_ERR_AO_BUSY || ret == HDF_FAILURE);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderResumeNull_006
* @tc.desc    Test RenderResume interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderResumeNull_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Resume(renderNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderFlush_001
    * @tc.desc    Test RenderFlush interface,return -2 if the data in the buffer is flushed successfully after stop
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderFlush_001, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Flush(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
    * @tc.name  AudioRenderFlushNull_002
    * @tc.desc    Test RenderFlush, return -3/-4 if the data in the buffer is flushed
                  when handle is nullptr after paused
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderFlushNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->Flush(renderNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioAudioRenderTurnStandbyMode_001
* @tc.desc    Test RenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderTurnStandbyMode_001, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->TurnStandbyMode(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderTurnStandbyModeNull_002
* @tc.desc    Test RenderTurnStandbyMode interface,return -3/-4 setting the incoming parameter self is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderTurnStandbyModeNull_002, TestSize.Level0)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);

    ret = render->TurnStandbyMode(renderNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    render->Stop(render);
}

/**
* @tc.name  AudioAudioRenderAudioDevDump_001
* @tc.desc    Test RenderAudioDevDump interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderAudioDevDump_001, TestSize.Level0)
{
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, render);
    FILE *file = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, file);
    int fd = fileno(file);
    if (fd == -1) {
        fclose(file);
        ASSERT_NE(fd, -1);
    }
    struct PrepareAudioPara audiopara = {
        .render = render, .path = AUDIO_FILE.c_str()
    };
    int32_t ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret < 0) {
        fclose(file);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    FrameStatus(0);
    ret = audiopara.render->Pause(audiopara.render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = audiopara.render->AudioDevDump(audiopara.render, RANGE, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    sleep(1);
    FrameStatus(1);
    ret = audiopara.render->Resume(audiopara.render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    fclose(file);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioAudioRenderAudioDevDump_002
* @tc.desc    Test RenderAudioDevDump interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderAudioDevDump_002, TestSize.Level0)
{
    int32_t ret = -1;
    char path[] = "./DevDump.log";
    ASSERT_NE(nullptr, render);
    FILE *fp = fopen(path, "wb+");
    ASSERT_NE(nullptr, fp);
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        ASSERT_NE(fd, -1);
    }
    struct PrepareAudioPara audiopara = {
        .render = render, .path = AUDIO_FILE.c_str()
    };
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret < 0) {
        fclose(fp);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    FrameStatus(0);
    ret = audiopara.render->Pause(audiopara.render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = audiopara.render->AudioDevDump(audiopara.render, OUT_OF_RANGE-1, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    sleep(1);
    FrameStatus(1);
    ret = audiopara.render->Resume(audiopara.render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    fclose(fp);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioAudioRenderAudioDevDump_003
* @tc.desc    Test RenderAudioDevDump interface,return -3 if setting the incoming parameter range is out of range
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderAudioDevDump_003, TestSize.Level0)
{
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, render);
    FILE *fp = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, fp);
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        ASSERT_NE(fd, -1);
    }
    int32_t ret = render->AudioDevDump(render, RANGE-1, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->AudioDevDump(render, OUT_OF_RANGE, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    fclose(fp);
}
/**
* @tc.name  AudioRenderAudioDevDumpNull_004
* @tc.desc    Test RenderAudioDevDump interface,return -3/-4 if setting the incoming parameter self is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderAudioDevDumpNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, render);
    FILE *fp = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, fp);
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        ASSERT_NE(fd, -1);
    }
    ret = render->AudioDevDump(renderNull, RANGE, fd);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    fclose(fp);
}
/**
* @tc.name  AudioAudioRenderAudioDevDump_005
* @tc.desc    Test RenderAudioDevDump interface,return -3 if setting the incoming parameter fd is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderControlTest, AudioRenderAudioDevDump_005, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    int fd = 3;
    ret = render->AudioDevDump(render, RANGE, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
}

