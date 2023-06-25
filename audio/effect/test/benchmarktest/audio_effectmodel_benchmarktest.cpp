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

#include <benchmark/benchmark.h>
#include <climits>
#include <gtest/gtest.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "v1_0/effect_types.h"
#include "v1_0/ieffect_control.h"
#include "v1_0/ieffect_model.h"
#include "osal_mem.h"

using namespace std;
using namespace testing::ext;
constexpr bool IS_DIRECTLY_CALL = false;
constexpr uint32_t MAX_DESCRIPTOR_NUM = 20;

namespace {
const int32_t ITERATION_FREQUENCY = 100;
const int32_t REPETITION_FREQUENCY = 3;
const int32_t HDF_EFFECT_NUM_MAX = 32;

class AudioEffectModelBenchmarkTest : public benchmark::Fixture {
public:
    struct IEffectModel *model_ = nullptr;
    struct ControllerId contollerId_;
    char *libName_ = nullptr;
    char *effectId_ = nullptr;
    virtual void SetUp(const ::benchmark::State &state);
    virtual void TearDown(const ::benchmark::State &state);
};

void EffectControllerReleaseDesc(struct EffectControllerDescriptor *desc)
{
    if (desc == nullptr) {
        return;
    }

    OsalMemFree(desc->effectId);
    desc->effectId = nullptr;

    OsalMemFree(desc->effectName);
    desc->effectName = nullptr;

    OsalMemFree(desc->libName);
    desc->libName = nullptr;

    OsalMemFree(desc->supplier);
    desc->supplier = nullptr;
}

void EffectControllerReleaseDescs(struct EffectControllerDescriptor *descs, const uint32_t *descsLen)
{
    if (descs == nullptr || descsLen == nullptr || *descsLen == 0 || *descsLen > HDF_EFFECT_NUM_MAX) {
        return;
    }

    for (uint32_t i = 0; i < *descsLen; i++) {
        EffectControllerReleaseDesc(&descs[i]);
    }
}

void AudioEffectModelBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    // input testcase setup step,setup invoked before each testcases
    libName_ = strdup("libmock_effect_lib");
    effectId_ = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff");
    model_ = IEffectModelGet(IS_DIRECTLY_CALL);
    ASSERT_NE(nullptr, model_);
}

void AudioEffectModelBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    // input testcase teardown step,teardown invoked after each testcases
    if (libName_ != nullptr) {
        free(libName_);
        libName_ = nullptr;
    }

    if (effectId_ != nullptr) {
        free(effectId_);
        effectId_ = nullptr;
    }

    if (model_ != nullptr) {
        IEffectModelRelease(model_, IS_DIRECTLY_CALL);
    }
}

BENCHMARK_F(AudioEffectModelBenchmarkTest, IsSupplyEffectLibs)(benchmark::State &state)
{
    ASSERT_NE(model_, nullptr);
    int32_t ret;
    bool isSupport = false;

    for (auto _ : state) {
        ret = model_->IsSupplyEffectLibs(model_, &isSupport);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioEffectModelBenchmarkTest, IsSupplyEffectLibs)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioEffectModelBenchmarkTest, GetAllEffectDescriptors)(benchmark::State &state)
{
    ASSERT_NE(model_, nullptr);
    int32_t ret;
    uint32_t descsLen = MAX_DESCRIPTOR_NUM;
    struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];

    for (auto _ : state) {
        ret = model_->GetAllEffectDescriptors(model_, descs, &descsLen);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    EXPECT_GE(MAX_DESCRIPTOR_NUM, descsLen);

    for (uint32_t i = 0; i < descsLen; i++) {
        EXPECT_NE(nullptr, descs[i].effectId);
    }

    EffectControllerReleaseDescs(descs, &descsLen);
}

BENCHMARK_REGISTER_F(AudioEffectModelBenchmarkTest, GetAllEffectDescriptors)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioEffectModelBenchmarkTest, CreateAndDestroyEffectController)(benchmark::State &state)
{
    ASSERT_NE(model_, nullptr);
    int32_t ret;
    struct EffectInfo info = {
        .libName = libName_,
        .effectId = effectId_,
        .ioDirection = 1,
    };
    struct IEffectControl *contoller = NULL;

    for (auto _ : state) {
        ret = model_->CreateEffectController(model_, &info, &contoller, &contollerId_);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = model_->DestroyEffectController(model_, &contollerId_);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioEffectModelBenchmarkTest, CreateAndDestroyEffectController)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioEffectModelBenchmarkTest, GetEffectDescriptor)(benchmark::State &state)
{
    ASSERT_NE(model_, nullptr);
    int32_t ret;
    struct EffectControllerDescriptor desc;

    for (auto _ : state) {
        ret = model_->GetEffectDescriptor(model_, effectId_, &desc);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    EXPECT_STREQ(desc.effectId, effectId_);
    EXPECT_STREQ(desc.effectName, "mock_effect");
    EXPECT_STREQ(desc.libName, libName_);
    EXPECT_STREQ(desc.supplier, "mock");
    EffectControllerReleaseDesc(&desc);
}

BENCHMARK_REGISTER_F(AudioEffectModelBenchmarkTest, GetEffectDescriptor)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}
