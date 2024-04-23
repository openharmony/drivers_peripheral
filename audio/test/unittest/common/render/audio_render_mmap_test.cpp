/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "osal_mem.h"

#include "v3_0/audio_types.h"
#include "v3_0/iaudio_manager.h"
#include "v3_0/iaudio_render.h"

using namespace std;
using namespace testing::ext;

namespace {
const int BUFFER_LENTH = 1024 * 16;
const int DEEP_BUFFER_RENDER_PERIOD_SIZE = 4 * 1024;
const int32_t AUDIO_RENDER_CHANNELCOUNT = 2;
const int32_t AUDIO_SAMPLE_RATE_48K = 48000;
const int32_t MAX_AUDIO_ADAPTER_DESC = 5;
const int32_t MMAP_SUGGEST_BUFFER_SIZE = 1920;

class AudioUtRenderMmapTest : public testing::Test {
public:
    struct IAudioManager *manager_ = nullptr;
    struct AudioAdapterDescriptor descs_[MAX_AUDIO_ADAPTER_DESC];
    struct AudioAdapterDescriptor *desc_;
    struct IAudioAdapter *adapter_ = nullptr;
    struct IAudioRender *render_ = nullptr;
    struct AudioDeviceDescriptor devDescRender_ = {};
    struct AudioSampleAttributes attrsRender_ = {};
    uint32_t renderId_ = 0;
    char *devDescriptorName_ = nullptr;
    uint32_t size_ = MAX_AUDIO_ADAPTER_DESC;
    virtual void SetUp();
    virtual void TearDown();
    void InitRenderAttrs(struct AudioSampleAttributes &attrs);
    void InitRenderDevDesc(struct AudioDeviceDescriptor &devDesc);
    void FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen);
};

void AudioUtRenderMmapTest::InitRenderAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.channelCount = AUDIO_RENDER_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 0;
    attrs.type = AUDIO_MMAP_NOIRQ;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = AUDIO_FORMAT_TYPE_PCM_16_BIT * AUDIO_RENDER_CHANNELCOUNT;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.format * attrs.channelCount);
    attrs.stopThreshold = INT_MAX;
    attrs.silenceThreshold = BUFFER_LENTH;
}

void AudioUtRenderMmapTest::InitRenderDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    devDesc.pins = PIN_OUT_SPEAKER;
    devDescriptorName_ = strdup("cardname");
    devDesc.desc = devDescriptorName_;

    ASSERT_NE(desc_, nullptr);
    ASSERT_NE(desc_->ports, nullptr);
    for (uint32_t index = 0; index < desc_->portsLen; index++) {
        if (desc_->ports[index].dir == PORT_OUT) {
            devDesc.portId = desc_->ports[index].portId;
            return;
        }
    }
    free(devDesc.desc);
}

void AudioUtRenderMmapTest::FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == nullptr) {
        return;
    }

    OsalMemFree(dataBlock->adapterName);

    OsalMemFree(dataBlock->ports);

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void AudioUtRenderMmapTest::ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen)
{
    if (descs == nullptr || descsLen == 0) {
        return;
    }

    for (uint32_t i = 0; i < descsLen; i++) {
        FreeAdapterElements(&descs[i], false);
    }
}

void AudioUtRenderMmapTest::SetUp()
{
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);

    ASSERT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, descs_, &size_));
    ASSERT_NE(descs_, nullptr);
    EXPECT_GE(MAX_AUDIO_ADAPTER_DESC, size_);
    desc_ = &descs_[0];
    ASSERT_EQ(HDF_SUCCESS, manager_->LoadAdapter(manager_, desc_, &adapter_));
    ASSERT_NE(adapter_, nullptr);
    InitRenderDevDesc(devDescRender_);
    InitRenderAttrs(attrsRender_);

    int32_t ret = adapter_->CreateRender(adapter_, &devDescRender_, &attrsRender_, &render_, &renderId_);
    if (ret != HDF_SUCCESS) {
        attrsRender_.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
        ASSERT_EQ(HDF_SUCCESS, adapter_->CreateRender(adapter_, &devDescRender_, &attrsRender_, &render_, &renderId_));
    }
    ASSERT_NE(render_, nullptr);
}

void AudioUtRenderMmapTest::TearDown()
{
    ASSERT_NE(devDescriptorName_, nullptr);
    free(devDescriptorName_);

    if (adapter_ != nullptr) {
        adapter_->DestroyRender(adapter_, renderId_);
        render_ = nullptr;
    }
    if (manager_ != nullptr) {
        manager_->UnloadAdapter(manager_, desc_->adapterName);
        adapter_ = nullptr;
        ReleaseAllAdapterDescs(descs_, size_);

        IAudioManagerRelease(manager_, false);
    }
}

HWTEST_F(AudioUtRenderMmapTest, RenderReqMmapBufferNull001, TestSize.Level1)
{
    int32_t reqSize = MMAP_SUGGEST_BUFFER_SIZE;
    struct AudioMmapBufferDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->ReqMmapBuffer(nullptr, reqSize, &desc));
}

HWTEST_F(AudioUtRenderMmapTest, RenderReqMmapBufferIsValid001, TestSize.Level1)
{
    int32_t reqSize = MMAP_SUGGEST_BUFFER_SIZE;
    struct AudioMmapBufferDescriptor desc;

    int32_t ret = render_->ReqMmapBuffer(render_, reqSize, &desc);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderMmapTest, RenderReqMmapBufferInValid001, TestSize.Level1)
{
    int32_t reqSize = MMAP_SUGGEST_BUFFER_SIZE;
    struct AudioMmapBufferDescriptor desc;

    int32_t ret = render_->ReqMmapBuffer(render_, reqSize, &desc);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
    ret = render_->ReqMmapBuffer(render_, reqSize, &desc);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderMmapTest, RenderGetMmapPositionNull001, TestSize.Level1)
{
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetMmapPosition(nullptr, &frames, &time));
}

HWTEST_F(AudioUtRenderMmapTest, RenderGetMmapPositionInValid001, TestSize.Level1)
{
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;

    int32_t ret = render_->GetMmapPosition(render_, &frames, &time);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderMmapTest, RenderGetMmapPositionIsValid001, TestSize.Level1)
{
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;
    int32_t reqSize = MMAP_SUGGEST_BUFFER_SIZE;
    struct AudioMmapBufferDescriptor desc;

    int32_t ret = render_->ReqMmapBuffer(render_, reqSize, &desc);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);

    ret = render_->Start(render_);
    EXPECT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);

    ret = render_->GetMmapPosition(render_, &frames, &time);
    EXPECT_TRUE(ret == HDF_SUCCESS);
    render_->Stop(render_);
}

} // end of namespace