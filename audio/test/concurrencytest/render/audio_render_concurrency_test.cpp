/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <atomic>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include "hdf_dlist.h"
#include "osal_mem.h"
#include "v6_1/audio_types.h"
#include "v6_1/iaudio_adapter.h"
#include "v6_1/iaudio_manager.h"

using namespace std;
using namespace testing::ext;

#define AUDIO_CHANNELCOUNT             2
#define AUDIO_SAMPLE_RATE_48K          48000
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define PCM_16_BIT                     16
#define PCM_8_BIT                      8
#define INT_32_MAX                     0x7fffffff
#define AUDIO_ADAPTER_NUM_MAX          5
#define AUDIO_THREAD_NUM               4

namespace {

class HdfAudioConcRenderTest : public testing::Test {
public:
    struct IAudioManager *manager_ = nullptr;
    struct IAudioAdapter *adapter_ = nullptr;
    struct AudioAdapterDescriptor *adapterDescs_ = nullptr;
    struct IAudioRender *render_ = nullptr;
    uint32_t renderId_ = 0;
    char *devDescriptorName_ = nullptr;
    virtual void SetUp();
    virtual void TearDown();
    void InitAttrs(struct AudioSampleAttributes &attrs);
    void InitDevDesc(struct AudioDeviceDescriptor &devDesc);
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen);
};

void HdfAudioConcRenderTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock,
    bool freeSelf)
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

void HdfAudioConcRenderTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) != nullptr)) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}

void HdfAudioConcRenderTest::InitAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.channelCount = AUDIO_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 1;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = PCM_16_BIT * attrs.channelCount / PCM_8_BIT;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.frameSize);
    attrs.stopThreshold = INT_32_MAX;
}

void HdfAudioConcRenderTest::InitDevDesc(struct AudioDeviceDescriptor &devDesc)
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

void HdfAudioConcRenderTest::SetUp()
{
    uint32_t size = AUDIO_ADAPTER_NUM_MAX;
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);

    adapterDescs_ = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_NUM_MAX));
    ASSERT_NE(adapterDescs_, nullptr);

    ASSERT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, adapterDescs_, &size));
    if (size > AUDIO_ADAPTER_NUM_MAX) {
        ReleaseAdapterDescs(&adapterDescs_, AUDIO_ADAPTER_NUM_MAX);
        ASSERT_LT(size, AUDIO_ADAPTER_NUM_MAX);
    }

    if (manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter_) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&adapterDescs_, AUDIO_ADAPTER_NUM_MAX);
        ASSERT_TRUE(false);
    }
    if (adapter_ == nullptr) {
        ReleaseAdapterDescs(&adapterDescs_, AUDIO_ADAPTER_NUM_MAX);
        ASSERT_TRUE(false);
    }

    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devDesc);
    devDescriptorName_ = strdup("cardname");
    devDesc.desc = devDescriptorName_;
    devDesc.pins = PIN_OUT_SPEAKER;
    InitAttrs(attrs);
    attrs.silenceThreshold = 0;
    attrs.streamId = 0;

    int32_t ret = adapter_->CreateRender(adapter_, &devDesc, &attrs, &render_, &renderId_);
    if (ret != HDF_SUCCESS) {
        attrs.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
        ASSERT_EQ(HDF_SUCCESS, adapter_->CreateRender(adapter_, &devDesc, &attrs, &render_, &renderId_));
    }
    ASSERT_NE(render_, nullptr);
}

void HdfAudioConcRenderTest::TearDown()
{
    ASSERT_NE(devDescriptorName_, nullptr);
    free(devDescriptorName_);
    devDescriptorName_ = nullptr;

    if (adapter_ != nullptr) {
        adapter_->DestroyRender(adapter_, renderId_);
        render_ = nullptr;
    }
    if (manager_ != nullptr && adapterDescs_ != nullptr) {
        manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
    }
    ReleaseAdapterDescs(&adapterDescs_, AUDIO_ADAPTER_NUM_MAX);
    if (manager_ != nullptr) {
        IAudioManagerRelease(manager_, false);
        manager_ = nullptr;
    }
}

HWTEST_F(HdfAudioConcRenderTest, HdfAudioRenderConcStartStopMutiThread001, TestSize.Level1)
{
    ASSERT_EQ(HDF_SUCCESS, render_->Start(render_));
    std::atomic<int32_t> stopCnt(0);
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < AUDIO_THREAD_NUM; i++) {
        threads.push_back(std::thread([&stopCnt, this]() {
            if (render_->Stop(render_) == HDF_SUCCESS) {
                stopCnt++;
            }
        }));
    }
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_EQ(1, stopCnt.load());
    render_->Stop(render_);
}

HWTEST_F(HdfAudioConcRenderTest, HdfAudioRenderConcGetAttrsMutiThread001, TestSize.Level1)
{
    ASSERT_EQ(HDF_SUCCESS, render_->Start(render_));
    std::atomic<int32_t> successCnt(0);
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < AUDIO_THREAD_NUM; i++) {
        threads.push_back(std::thread([&successCnt, this]() {
            struct AudioSampleAttributes attrs = {};
            if (render_->GetSampleAttributes(render_, &attrs) == HDF_SUCCESS) {
                successCnt++;
            }
        }));
    }
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_EQ(AUDIO_THREAD_NUM, successCnt.load());
    render_->Stop(render_);
}

} // namespace
