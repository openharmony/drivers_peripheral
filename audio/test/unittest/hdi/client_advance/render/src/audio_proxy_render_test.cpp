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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_proxy_common_fun_test.h"

using namespace std;
using namespace commonfun;
using namespace testing::ext;
namespace {
class AudioProxyRenderTest : public testing::Test {
public:
    struct AudioManager *managerFuncs = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioDeviceDescriptor devDescRender = {};
    struct AudioSampleAttributes attrsRender = {};
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyRenderTest::SetUp()
{
    managerFuncs = GetAudioManagerFuncs();
    ASSERT_NE(managerFuncs, nullptr);
    int32_t size = 0;
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->GetAllAdapters(managerFuncs, &descs, &size));
    ASSERT_NE(descs, nullptr);
    desc = &descs[0];
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->LoadAdapter(managerFuncs, desc, &adapter));
    ASSERT_NE(adapter, nullptr);
    ASSERT_EQ(HDF_SUCCESS, InitDevDesc(devDescRender));
    ASSERT_EQ(HDF_SUCCESS, InitAttrs(attrsRender));
    ASSERT_EQ(HDF_SUCCESS, adapter->CreateRender(adapter, &devDescRender, &attrsRender, &render));
}

void AudioProxyRenderTest::TearDown()
{
    if (adapter != nullptr) {
        adapter->DestroyRender(adapter, render);
        render = nullptr;
    }
    if (managerFuncs != nullptr) {
        managerFuncs->UnloadAdapter(managerFuncs, adapter);
        adapter = nullptr;
        managerFuncs->ReleaseAudioManagerObject(managerFuncs);
        managerFuncs = nullptr;
    }
}

HWTEST_F(AudioProxyRenderTest, RenderStart_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->control.Start(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderStart_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->control.Start((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderStart_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    EXPECT_EQ(HDF_SUCCESS, render->control.Start((AudioHandle)render));
    EXPECT_EQ(HDF_SUCCESS, render->control.Stop((AudioHandle)render));
}

HWTEST_F(AudioProxyRenderTest, RenderStop_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->control.Stop(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderStop_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->control.Stop((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameSize_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t size = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetFrameSize(nullptr, &size));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetFrameSize((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameSize_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t size = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetFrameSize((AudioHandle)render, &size));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameCount_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t count = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetFrameCount(nullptr, &count));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetFrameCount((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameCount_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t count = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetFrameCount((AudioHandle)render, &count));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetSampleAttributes_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.SetSampleAttributes(nullptr, &attrs));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.SetSampleAttributes((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderSetSampleAttributes_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.SetSampleAttributes((AudioHandle)render, &attrs));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetSampleAttributes_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetSampleAttributes(nullptr, &attrs));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetSampleAttributes((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetSampleAttributes_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetSampleAttributes((AudioHandle)render, &attrs));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetCurrentChannelId_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t channelId = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetCurrentChannelId(nullptr, &channelId));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetCurrentChannelId((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetCurrentChannelId_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t channelId = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetCurrentChannelId((AudioHandle)render, &channelId));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderCheckSceneCapability_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    bool supported = false;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->scene.CheckSceneCapability(nullptr, &scene, &supported));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->scene.CheckSceneCapability((AudioHandle)render, nullptr,
                                                                                &supported));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->scene.CheckSceneCapability((AudioHandle)render, &scene, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderCheckSceneCapability_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    bool supported = false;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->scene.CheckSceneCapability((AudioHandle)render, &scene,
                                                                                &supported));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSelectScene_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->scene.SelectScene(nullptr, &scene));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->scene.SelectScene((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderSelectScene_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->scene.SelectScene((AudioHandle)render, &scene));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSelectScene_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    AudioSceneDescriptor scene;
    scene.scene.id = 0; // 0 is Media
    scene.desc.pins = PIN_OUT_HEADSET;
    EXPECT_EQ(HDF_SUCCESS, render->scene.SelectScene((AudioHandle)render, &scene));
    scene.desc.pins = PIN_OUT_SPEAKER;
    EXPECT_EQ(HDF_SUCCESS, render->scene.SelectScene((AudioHandle)render, &scene));
}

HWTEST_F(AudioProxyRenderTest, RenderGetLatency_001, TestSize.Level1)
{
    uint32_t ms = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->GetLatency(nullptr, &ms));
}

HWTEST_F(AudioProxyRenderTest, RenderGetLatency_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t ms = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->GetLatency(render, &ms));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetLatency_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t ms = 0;
    EXPECT_EQ(HDF_SUCCESS, render->GetLatency(render, &ms));
}

HWTEST_F(AudioProxyRenderTest, RenderGetRenderPosition_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->GetRenderPosition(nullptr, &frames, &time));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->GetRenderPosition(render, nullptr, &time));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->GetRenderPosition(render, &frames, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetRenderPosition_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->GetRenderPosition(render, &frames, &time));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.SetExtraParams(nullptr, keyValueList));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.SetExtraParams((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderSetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.SetExtraParams((AudioHandle)render, keyValueList));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    int32_t listLenth = AUDIO_RENDER_BUF_TEST;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetExtraParams(nullptr, keyValueList, listLenth));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->attr.GetExtraParams((AudioHandle)render, nullptr, listLenth));
}

HWTEST_F(AudioProxyRenderTest, RenderGetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    int32_t listLenth = AUDIO_RENDER_BUF_TEST;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    int32_t ret = render->attr.GetExtraParams((AudioHandle)render, keyValueList, listLenth);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderTurnStandbyMode_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->control.TurnStandbyMode(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderTurnStandbyMode_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render->control.TurnStandbyMode((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}
}
