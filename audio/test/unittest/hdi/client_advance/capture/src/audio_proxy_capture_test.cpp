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

using namespace commonfun;
using namespace testing::ext;
namespace {
class AudioProxyCaptureTest : public testing::Test {
public:
    struct AudioManager *managerFuncs = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioPort *audioPort = nullptr;
    struct AudioDeviceDescriptor devDescCapture = {};
    struct AudioSampleAttributes attrsCapture = {};
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyCaptureTest::SetUp()
{
    managerFuncs = GetAudioManagerFuncs();
    ASSERT_NE(managerFuncs, nullptr);
    int32_t size = 0;
    ASSERT_EQ(HDF_SUCCESS,  managerFuncs->GetAllAdapters(managerFuncs, &descs, &size));

    desc = &descs[0];
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->LoadAdapter(managerFuncs, desc, &adapter));
    ASSERT_NE(adapter, nullptr);
    ASSERT_EQ(HDF_SUCCESS, InitDevDescCapture(devDescCapture));
    ASSERT_EQ(HDF_SUCCESS, InitAttrsCapture(attrsCapture));
    ASSERT_EQ(HDF_SUCCESS, adapter->CreateCapture(adapter, &devDescCapture, &attrsCapture, &capture));
}

void AudioProxyCaptureTest::TearDown()
{
    if (adapter != nullptr) {
        adapter->DestroyCapture(adapter, capture);
        capture = nullptr;
    }
    if (managerFuncs != nullptr) {
        managerFuncs->UnloadAdapter(managerFuncs, adapter);
        adapter = nullptr;
        managerFuncs->ReleaseAudioManagerObject(managerFuncs);
        managerFuncs = nullptr;
    }
}

HWTEST_F(AudioProxyCaptureTest, CaptureStart_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->control.Start(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureStart_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->control.Start((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureStart_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(HDF_SUCCESS, capture->control.Start((AudioHandle)capture));
    EXPECT_EQ(HDF_SUCCESS, capture->control.Stop((AudioHandle)capture));
}

HWTEST_F(AudioProxyCaptureTest, CaptureStop_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->control.Stop(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureStop_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->control.Stop((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameSize_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t size = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetFrameSize(nullptr, &size));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetFrameSize((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameSize_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint64_t size = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetFrameSize((AudioHandle)capture, &size));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameSize_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t size = 0;
    EXPECT_EQ(HDF_SUCCESS, capture->attr.GetFrameSize((AudioHandle)capture, &size));
    EXPECT_NE(size, 0);
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameCount_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t count = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetFrameCount(nullptr, &count));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetFrameCount((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameCount_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint64_t count = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetFrameCount((AudioHandle)capture, &count));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCurrentChannelId_001, TestSize.Level1)
{
    uint32_t channelId = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetCurrentChannelId(nullptr, &channelId));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetCurrentChannelId((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCurrentChannelId_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint32_t channelId = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetCurrentChannelId((AudioHandle)capture, &channelId));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureCheckSceneCapability_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    bool supported = false;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->scene.CheckSceneCapability(nullptr, &scene, &supported));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->scene.CheckSceneCapability((AudioHandle)capture, nullptr,
                                                                                 &supported));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->scene.CheckSceneCapability((AudioHandle)capture, &scene,
                                                                                 nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureCheckSceneCapability_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    bool supported = false;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->scene.CheckSceneCapability((AudioHandle)capture, &scene,
                                                                                 &supported));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSelectScene_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->scene.SelectScene(nullptr, &scene));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->scene.SelectScene((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSelectScene_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->scene.SelectScene((AudioHandle)capture, &scene));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSelectScene_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioSceneDescriptor *scene  = new AudioSceneDescriptor;
    scene->scene.id = 0; // 0 is Media
    scene->desc.pins = PIN_IN_HS_MIC;
    EXPECT_EQ(HDF_SUCCESS, capture->scene.SelectScene((AudioHandle)capture, scene));
    scene->desc.pins = PIN_IN_MIC;
    EXPECT_EQ(HDF_SUCCESS, capture->scene.SelectScene((AudioHandle)capture, scene));
    delete scene;
    scene = nullptr;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCapturePosition_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t frames;
    struct AudioTimeStamp time;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->GetCapturePosition(nullptr, &frames, &time));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->GetCapturePosition(capture, nullptr, &time));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->GetCapturePosition(capture, &frames, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCapturePosition_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint64_t frames;
    struct AudioTimeStamp time;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->GetCapturePosition(capture, &frames, &time));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.SetExtraParams(nullptr, keyValueList));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.SetExtraParams((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.SetExtraParams((AudioHandle)capture, keyValueList));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    int32_t listLenth = AUDIO_CAPTURE_BUF_TEST;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetExtraParams(nullptr, keyValueList, listLenth));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetExtraParams((AudioHandle)capture, nullptr, listLenth));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetExtraParams((AudioHandle)capture, keyValueList, 0));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    int32_t listLenth = AUDIO_CAPTURE_BUF_TEST;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->attr.GetExtraParams((AudioHandle)capture, keyValueList,
                                                                           listLenth));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureTurnStandbyMode_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->control.TurnStandbyMode(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureTurnStandbyMode_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, capture->control.TurnStandbyMode((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}
}
