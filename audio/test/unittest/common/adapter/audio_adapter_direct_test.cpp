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

#include <climits>
#include <cstring>
#include <gtest/gtest.h>
#include "hdf_dlist.h"
#include "osal_mem.h"
#include "v3_0/audio_types.h"
#include "v3_0/iaudio_adapter.h"
#include "v3_0/iaudio_manager.h"

using namespace std;
using namespace testing::ext;

#define AUDIO_CHANNELCOUNT              2
#define AUDIO_SAMPLE_RATE_192K          192000
#define DEEP_BUFFER_RENDER_PERIOD_SIZE  4096
namespace {
static const uint32_t g_audioAdapterNumMax = 5;

class HdfAudioUtAdapterDirectTest : public testing::Test {
public:
    struct IAudioManager *manager_ = nullptr;
    struct IAudioAdapter *adapter_ = nullptr;
    struct AudioAdapterDescriptor *adapterDescs_ = nullptr;
    uint32_t renderId_ = 0;
    uint32_t captureId_ = 0;
    virtual void SetUp();
    virtual void TearDown();
    void InitDirectchannelAttrs(struct AudioSampleAttributes &attrs);
    void InitDevDesc(struct AudioDeviceDescriptor &devDesc);
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen);
};

void HdfAudioUtAdapterDirectTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == nullptr) {
        return;
    }

    if (dataBlock->adapterName != nullptr) {
        OsalMemFree(dataBlock->adapterName);
        dataBlock->adapterName = nullptr;
    }

    if (dataBlock->ports != nullptr) {
        OsalMemFree(dataBlock->ports);
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void HdfAudioUtAdapterDirectTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) != nullptr)) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}

void HdfAudioUtAdapterDirectTest::InitDirectchannelAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
    attrs.channelCount = AUDIO_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_192K;
    attrs.interleaved = 1;
    attrs.type = AUDIO_DIRECT;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = AUDIO_FORMAT_TYPE_PCM_32_BIT * AUDIO_CHANNELCOUNT;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.format * attrs.frameSize);
    attrs.stopThreshold = INT_MAX;
    attrs.silenceThreshold = 0;
}

void HdfAudioUtAdapterDirectTest::InitDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    ASSERT_NE(adapterDescs_, nullptr);
    ASSERT_NE(adapterDescs_->ports, nullptr);
    for (uint32_t index = 0; index < adapterDescs_->portsLen; index++) {
        if (adapterDescs_->ports[index].dir == PORT_OUT) {
            devDesc.portId = adapterDescs_->ports[index].portId;
            return;
        }
    }
}

void HdfAudioUtAdapterDirectTest::SetUp()
{
    uint32_t size = g_audioAdapterNumMax;
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);

    adapterDescs_ = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(adapterDescs_, nullptr);

    ASSERT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, adapterDescs_, &size));
    if (size > g_audioAdapterNumMax) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_LT(size, g_audioAdapterNumMax);
    }

    if (manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter_) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }
    if (adapter_ == nullptr) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }
}

void HdfAudioUtAdapterDirectTest::TearDown()
{
    ASSERT_NE(manager_, nullptr);
    ASSERT_NE(adapter_, nullptr);

    manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
    ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
    adapter_ = nullptr;
    IAudioManagerRelease(manager_, false);
    manager_ = nullptr;
}

HWTEST_F(HdfAudioUtAdapterDirectTest, HdfAudioAdapterDirectchannelCreateRenderIsvalid001, TestSize.Level1)
{
    struct IAudioRender *render = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = strdup("");
    devicedesc.pins = PIN_OUT_SPEAKER;
    InitDirectchannelAttrs(attrs);
    attrs.streamId = 0;
    int32_t ret = adapter_->CreateRender(adapter_, &devicedesc, &attrs, &render, &renderId_);
    EXPECT_TRUE(ret == HDF_SUCCESS);
    ret = adapter_->DestroyRender(adapter_, renderId_);
    EXPECT_TRUE(ret == HDF_SUCCESS);
}

}