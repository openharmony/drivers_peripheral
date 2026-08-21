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

class HdfAudioConcAdapterTest : public testing::Test {
public:
    struct IAudioManager *manager_ = nullptr;
    struct IAudioAdapter *adapter_ = nullptr;
    struct AudioAdapterDescriptor *adapterDescs_ = nullptr;
    uint32_t adapterNum_ = 0;
    virtual void SetUp();
    virtual void TearDown();
    void InitAttrs(struct AudioSampleAttributes &attrs);
    void InitDevDesc(struct AudioDeviceDescriptor &devDesc, enum AudioPortDirection dir);
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen);
};

void HdfAudioConcAdapterTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock,
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

void HdfAudioConcAdapterTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) != nullptr)) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}

void HdfAudioConcAdapterTest::InitAttrs(struct AudioSampleAttributes &attrs)
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

void HdfAudioConcAdapterTest::InitDevDesc(struct AudioDeviceDescriptor &devDesc, enum AudioPortDirection dir)
{
    ASSERT_NE(adapterDescs_, nullptr);
    ASSERT_NE(adapterDescs_->ports, nullptr);
    for (uint32_t index = 0; index < adapterDescs_->portsLen; index++) {
        if (adapterDescs_->ports[index].dir == dir) {
            devDesc.portId = adapterDescs_->ports[index].portId;
            return;
        }
    }
}

void HdfAudioConcAdapterTest::SetUp()
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
    adapterNum_ = size;

    if (manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter_) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&adapterDescs_, AUDIO_ADAPTER_NUM_MAX);
        ASSERT_TRUE(false);
    }
    if (adapter_ == nullptr) {
        ReleaseAdapterDescs(&adapterDescs_, AUDIO_ADAPTER_NUM_MAX);
        ASSERT_TRUE(false);
    }
}

void HdfAudioConcAdapterTest::TearDown()
{
    ASSERT_NE(manager_, nullptr);
    ASSERT_NE(adapter_, nullptr);

    manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
    ReleaseAdapterDescs(&adapterDescs_, AUDIO_ADAPTER_NUM_MAX);
    adapter_ = nullptr;
    IAudioManagerRelease(manager_, false);
    manager_ = nullptr;
}

HWTEST_F(HdfAudioConcAdapterTest, HdfAudioAdapterConcInitAllPortsMutiThread001, TestSize.Level1)
{
    std::atomic<int32_t> successCnt(0);
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < AUDIO_THREAD_NUM; i++) {
        threads.push_back(std::thread([&successCnt, this]() {
            if (adapter_->InitAllPorts(adapter_) == HDF_SUCCESS) {
                successCnt++;
            }
        }));
    }
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_EQ(AUDIO_THREAD_NUM, successCnt.load());
}

HWTEST_F(HdfAudioConcAdapterTest, HdfAudioAdapterConcCreateRenderMutiThread001, TestSize.Level1)
{
    std::atomic<int32_t> successCnt(0);
    std::vector<uint32_t> renderIds(AUDIO_THREAD_NUM, 0);
    std::vector<int32_t> results(AUDIO_THREAD_NUM, HDF_FAILURE);
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < AUDIO_THREAD_NUM; i++) {
        threads.push_back(std::thread([&successCnt, &renderIds, &results, i, this]() {
            struct IAudioRender *render = nullptr;
            struct AudioDeviceDescriptor devDesc = {};
            struct AudioSampleAttributes attrs = {};
            InitDevDesc(devDesc, PORT_OUT);
            devDesc.desc = const_cast<char *>("primary");
            devDesc.pins = PIN_OUT_SPEAKER;
            InitAttrs(attrs);
            attrs.silenceThreshold = 0;
            attrs.streamId = 0;
            results[i] = adapter_->CreateRender(adapter_, &devDesc, &attrs, &render, &renderIds[i]);
            if (results[i] == HDF_SUCCESS) {
                successCnt++;
            }
        }));
    }
    for (auto &thread : threads) {
        thread.join();
    }
    for (uint32_t i = 0; i < AUDIO_THREAD_NUM; i++) {
        if (results[i] == HDF_SUCCESS) {
            adapter_->DestroyRender(adapter_, renderIds[i]);
        }
    }
    EXPECT_GE(successCnt.load(), 1);
}

} // namespace
