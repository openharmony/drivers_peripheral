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

#include "hdf_remote_adapter_if.h"
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
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handleSo;
    static void (*AudioManagerRelease)(struct IAudioManager *);
    static void (*AudioAdapterRelease)(struct IAudioAdapter *);
    static void (*AudioRenderRelease)(struct IAudioRender *);
    void ReleaseAudioSource();
};
using THREAD_FUNC = void *(*)(void *);
TestAudioManager *(*AudioIdlHdiRenderControlTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiRenderControlTest::manager = nullptr;
void *AudioIdlHdiRenderControlTest::handleSo = nullptr;
void (*AudioIdlHdiRenderControlTest::AudioManagerRelease)(struct IAudioManager *) = nullptr;
void (*AudioIdlHdiRenderControlTest::AudioAdapterRelease)(struct IAudioAdapter *) = nullptr;
void (*AudioIdlHdiRenderControlTest::AudioRenderRelease)(struct IAudioRender *) = nullptr;

void AudioIdlHdiRenderControlTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    char *path = realpath(RESOLVED_PATH.c_str(), absPath);
    ASSERT_NE(nullptr, path);
    handleSo = dlopen(absPath, RTLD_LAZY);
    ASSERT_NE(nullptr, handleSo);
    GetAudioManager = (TestAudioManager *(*)(const char *))(dlsym(handleSo, FUNCTION_NAME.c_str()));
    ASSERT_NE(nullptr, GetAudioManager);
    (void)HdfRemoteGetCallingPid();
    manager = GetAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
    AudioManagerRelease = (void (*)(struct IAudioManager *))(dlsym(handleSo, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct IAudioAdapter *))(dlsym(handleSo, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioRenderRelease = (void (*)(struct IAudioRender *))(dlsym(handleSo, "AudioRenderRelease"));
    ASSERT_NE(nullptr, AudioRenderRelease);
}

void AudioIdlHdiRenderControlTest::TearDownTestCase(void)
{
    if (AudioManagerRelease != nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
}

void AudioIdlHdiRenderControlTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderControlTest::TearDown(void)
{
    ReleaseAudioSource();
}

void AudioIdlHdiRenderControlTest::ReleaseAudioSource(void)
{
    int32_t ret = -1;
    if (render != nullptr && AudioRenderRelease != nullptr) {
        ret = adapter->DestroyRender(adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioRenderRelease(render);
        render = nullptr;
    }
    if (adapter != nullptr && AudioAdapterRelease != nullptr) {
        ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioAdapterRelease(adapter);
        adapter = nullptr;
    }
}

/**
    * @tc.name    Test AudioRenderStart API via  legal input
    * @tc.number  SUB_Audio_HDI_RenderStart_001
    * @tc.desc    Test AudioRenderStart interface,return 0 if the audiorender object is created successfully.
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderStart_001, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test AudioRenderStart API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderStart_Null_002
    * @tc.desc    Test AudioRenderStart interface, return -3/-4 if the  incoming parameter handle is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderStart_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(renderNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name Test AudioRenderStart API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_RenderStart_003
* @tc.desc    Test AudioRenderStart interface,return -7003 the second time if the RenderStart is called twice
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderStart_003, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Start(render);
    EXPECT_EQ(AUDIO_HAL_ERR_AO_BUSY, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name Test AudioRenderStop API via legal input
* @tc.number  SUB_Audio_HDI_RenderStop_001
* @tc.desc    test AudioRenderStop interface. return 0 if the rendering is successfully stopped.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderStop_001, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name Test AudioRenderStop API via the render does not start and stop only
* @tc.number  SUB_Audio_HDI_RenderStop_002
* @tc.desc    test AudioRenderStop interface. return -4 if the render does not start and stop only
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderStop_002, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name Test RenderStop API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_RenderStop_003
* @tc.desc    Test RenderStop interface,return -4 the second time if the RenderStop is called twice
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderStop_003, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name Test RenderStop API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_RenderStop_Null_004
* @tc.desc    Test RenderStop interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderStop_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(renderNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderPause API via legal input
    * @tc.number  SUB_Audio_HDI_RenderPause_01
    * @tc.desc    test HDI RenderPause interface，return 0 if the render is paused after start
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderPause_001, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name Test AudioRenderPause API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_RenderPause_002
* @tc.desc    Test AudioRenderPause interface, return -1 the second time if RenderPause is called twice
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderPause_002, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Pause(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    render->Stop(render);
}
/**
* @tc.name Test AudioRenderPause API via the render is paused after created.
* @tc.number  SUB_Audio_HDI_RenderPause_003
* @tc.desc    Test AudioRenderPause interface,return -1 if the render is paused after created.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderPause_003, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->Pause(render);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name Test AudioRenderPause API via the render is paused after resumed.
* @tc.number  SUB_Audio_HDI_RenderPause_004
* @tc.desc    Test AudioRenderPause interface,return 0 if the render is paused after resumed.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderPause_004, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Resume(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name Test AudioRenderPause API via the render is paused after stopped.
* @tc.number  SUB_Audio_HDI_RenderPause_005
* @tc.desc    Test AudioRenderPause interface, return -1 the render is paused after stopped.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderPause_005, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->Pause(render);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name Test RenderPause API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_RenderPause_Null_006
* @tc.desc    Test RenderPause interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderPause_Null_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(renderNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderResume API via the render is resumed after started
    * @tc.number  SUB_Audio_HDI_RenderResume_001
    * @tc.desc    test HDI RenderResume interface,return -1 if the render is resumed after started
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderResume_001, TestSize.Level1)
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
    * @tc.name    Test RenderResume API via the render is resumed after stopped
    * @tc.number  SUB_Audio_HDI_RenderResume_002
    * @tc.desc    test HDI RenderResume interface,return -1 if the render is resumed after stopped
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderResume_002, TestSize.Level1)
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
    * @tc.name    Test RenderResume API via legal input
    * @tc.number  SUB_Audio_HDI_RenderResume_003
    * @tc.desc    Test AudioRenderResume interface,return 0 if the render is resumed after paused
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderResume_003, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Resume(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderResume API via the interface is called twice in a row
    * @tc.number  SUB_Audio_HDI_RenderResume_004
    * @tc.desc    Test RenderResume interface,return -1 the second time if the RenderResume is called twice
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderResume_004, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Resume(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Resume(render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderResume API via the render Continue to start after resume
    * @tc.number  SUB_Audio_HDI_RenderResume_005
    * @tc.desc    test HDI RenderResume interface,return -1 if the render Continue to start after resume
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderResume_005, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Resume(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Start(render);
    EXPECT_EQ(AUDIO_HAL_ERR_AO_BUSY, ret);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name Test RenderResume API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_RenderResume_Null_006
* @tc.desc    Test RenderResume interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderResume_Null_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Resume(renderNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderFlush API via legal input Verify that the data in the buffer is flushed after stop
    * @tc.number  SUB_Audio_HDI_RenderFlush_001
    * @tc.desc    Test RenderFlush interface,return -2 if the data in the buffer is flushed successfully after stop
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderFlush_001, TestSize.Level1)
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
    * @tc.name    Test RenderFlush that the data in the buffer is flushed when handle is nullptr after paused
    * @tc.number  SUB_Audio_HDI_RenderFlush_Null_002
    * @tc.desc    Test RenderFlush, return -3/-4 if the data in the buffer is flushed
                  when handle is nullptr after paused
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderFlush_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Pause(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Flush(renderNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test RenderTurnStandbyMode API
* @tc.number  SUB_Audio_HDI_AudioRenderTurnStandbyMode_001
* @tc.desc    Test RenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderTurnStandbyMode_001, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->TurnStandbyMode(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test RenderTurnStandbyMode API vai setting the incoming parameter self is nullptr
* @tc.number  SUB_Audio_HDI_RenderTurnStandbyMode_Null_002
* @tc.desc    Test RenderTurnStandbyMode interface,return -3/-4 setting the incoming parameter self is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderTurnStandbyMode_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->TurnStandbyMode(renderNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    render->Stop(render);
}

/**
* @tc.name    Test RenderAudioDevDump API via
* @tc.number  SUB_Audio_HDI_AudioRenderAudioDevDump_001
* @tc.desc    Test RenderAudioDevDump interface,return 0 if the interface use correctly.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderAudioDevDump_001, TestSize.Level1)
{
    int32_t ret = -1;
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, render);
    FILE *fp = fopen(pathBuf, "wb+");
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->AudioDevDump(audiopara.render, RANGE, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    FrameStatus(1);
    ret = audiopara.render->Resume(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    fclose(fp);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test RenderAudioDevDump API via
* @tc.number  SUB_Audio_HDI_AudioRenderAudioDevDump_002
* @tc.desc    Test RenderAudioDevDump interface,return 0 if the interface use correctly.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderAudioDevDump_002, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->AudioDevDump(audiopara.render, OUT_OF_RANGE-1, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    FrameStatus(1);
    ret = audiopara.render->Resume(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    fclose(fp);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name    Test RenderAudioDevDump API via setting the incoming parameter range is out of range
* @tc.number  SUB_Audio_HDI_AudioRenderAudioDevDump_003
* @tc.desc    Test RenderAudioDevDump interface,return -3 if setting the incoming parameter range is out of range
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderAudioDevDump_003, TestSize.Level1)
{
    int32_t ret = -1;
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, render);
    FILE *fp = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, fp);
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        ASSERT_NE(fd, -1);
    }
    ret = render->AudioDevDump(render, RANGE-1, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->AudioDevDump(render, OUT_OF_RANGE, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    fclose(fp);
}
/**
* @tc.name    Test RenderAudioDevDump API via setting the incoming parameter self is nullptr
* @tc.number  SUB_Audio_HDI_RenderAudioDevDump_Null_004
* @tc.desc    Test RenderAudioDevDump interface,return -3/-4 if setting the incoming parameter self is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderAudioDevDump_Null_004, TestSize.Level1)
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
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    fclose(fp);
}
/**
* @tc.name    Test RenderAudioDevDump API via setting the incoming parameter fd is illegal
* @tc.number  SUB_Audio_HDI_AudioRenderAudioDevDump_005
* @tc.desc    Test RenderAudioDevDump interface,return -3 if setting the incoming parameter fd is illegal
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderControlTest, SUB_Audio_HDI_RenderAudioDevDump_005, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    int fd = 3;
    ret = render->AudioDevDump(render, RANGE, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
}

