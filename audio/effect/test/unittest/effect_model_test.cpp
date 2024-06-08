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
#include "hdf_base.h"
#include "hdf_log.h"
#include "v1_0/effect_types.h"
#include "v1_0/ieffect_control.h"
#include "v1_0/ieffect_model.h"
#include "effect_common.h"
#include "osal_mem.h"

using namespace std;
using namespace testing::ext;
constexpr bool IS_DIRECTLY_CALL = false;
constexpr uint32_t MAX_DESCRIPTOR_NUM = 20;

namespace {
class EffectModelTest : public testing::Test {
public:
    struct IEffectModel *model_ = nullptr;
    struct ControllerId contollerId_;
    char *libName_ = nullptr;
    char *effectId_ = nullptr;
    virtual void SetUp();
    virtual void TearDown();
};

void EffectModelTest::SetUp()
{
    // input testcase setup step,setup invoked before each testcases
    libName_ = strdup("libmock_effect_lib");
    effectId_ = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff");
    model_ = IEffectModelGet(IS_DIRECTLY_CALL);
    ASSERT_NE(nullptr, model_);
}

void EffectModelTest::TearDown()
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

/**
 * @tc.name: HdfAudioIsSupplyEffectLibs001
 * @tc.desc: Verify the EffectModelIsSupplyEffectLibs function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioIsSupplyEffectLibs001, TestSize.Level1)
{
    bool isSupport = false;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->IsSupplyEffectLibs(nullptr, &isSupport));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->IsSupplyEffectLibs(model_, nullptr));
}

/**
 * @tc.name: HdfAudioIsSupplyEffectLibs002
 * @tc.desc: Verify the EffectModelIsSupplyEffectLibs function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioIsSupplyEffectLibs002, TestSize.Level1)
{
    bool isSupport = false;
    int32_t ret = model_->IsSupplyEffectLibs(model_, &isSupport);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioGetAllEffectDescriptors001
 * @tc.desc: Verify the EffectModelGetAllEffectDescriptors function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioGetAllEffectDescriptors001, TestSize.Level1)
{
    uint32_t descsLen = MAX_DESCRIPTOR_NUM;
    struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, descs, &descsLen));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetAllEffectDescriptors(model_, nullptr, &descsLen));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetAllEffectDescriptors(model_, descs, nullptr));
}

/**
 * @tc.name: HdfAudioGetAllEffectDescriptors002
 * @tc.desc: Verify the EffectModelGetAllEffectDescriptors function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioGetAllEffectDescriptors002, TestSize.Level1)
{
    uint32_t descsLen = MAX_DESCRIPTOR_NUM;
    struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];

    int32_t ret = model_->GetAllEffectDescriptors(model_, descs, &descsLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
    EXPECT_GE(MAX_DESCRIPTOR_NUM, descsLen);
}

/**
 * @tc.name: HdfAudioGetAllEffectDescriptors003
 * @tc.desc: Verify the descs of EffectModelGetAllEffectDescriptors function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioGetAllEffectDescriptors003, TestSize.Level1)
{
    uint32_t descsLen = MAX_DESCRIPTOR_NUM;
    struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];

    int32_t ret = model_->GetAllEffectDescriptors(model_, descs, &descsLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
    EXPECT_GE(MAX_DESCRIPTOR_NUM, descsLen);

    for (uint32_t i = 0; i < descsLen; i++) {
        EXPECT_NE(nullptr, descs[i].effectId);
    }

    OHOS::Audio::EffectControllerReleaseDescs(descs, &descsLen);
}

/**
 * @tc.name: HdfAudioCreateEffectController001
 * @tc.desc: Verify the CreateEffectController function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I71E1I
 */
HWTEST_F(EffectModelTest, HdfAudioCreateEffectController001, TestSize.Level1)
{
    struct EffectInfo info = {
        .libName = libName_,
        .effectId = effectId_,
        .ioDirection = 1,
    };

    struct IEffectControl *contoller = NULL;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->CreateEffectController(nullptr, &info, &contoller, &contollerId_));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->CreateEffectController(model_, nullptr, &contoller, &contollerId_));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->CreateEffectController(model_, &info, &contoller, nullptr));
}

/**
 * @tc.name: HdfAudioDestroyEffectController001
 * @tc.desc: Verify the DestroyEffectController function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I71E1I
 */
HWTEST_F(EffectModelTest, HdfAudioDestroyEffectController001, TestSize.Level1)
{
    struct EffectInfo info = {
        .libName = libName_,
        .effectId = effectId_,
        .ioDirection = 1,
    };

    struct IEffectControl *contoller = NULL;
    ASSERT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &contoller, &contollerId_));
    ASSERT_NE(contoller, nullptr);

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->DestroyEffectController(nullptr, &contollerId_));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->DestroyEffectController(model_, nullptr));
}

/**
 * @tc.name: HdfAudioCreateDestroyController001
 * @tc.desc: Verify the EffectModelCreateEffectController and EffectModelDestroyEffectController function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioCreateDestroyController001, TestSize.Level1)
{
    struct EffectInfo info = {
        .libName = libName_,
        .effectId = effectId_,
        .ioDirection = 1,
    };

    struct IEffectControl *contoller = NULL;
    int32_t ret = model_->CreateEffectController(model_, &info, &contoller, &contollerId_);
    if (ret == HDF_SUCCESS) {
        ASSERT_NE(contoller, nullptr);
    }

    if (contoller != nullptr) {
        ret = model_->DestroyEffectController(model_, &contollerId_);
    }
}

/**
 * @tc.name: HdfAudioGetEffectDescriptor001
 * @tc.desc: Verify the EffectModelGetEffectDescriptor function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioGetEffectDescriptor001, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, effectId_, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, effectId_, nullptr));
}

/**
 * @tc.name: HdfAudioGetEffectDescriptor002
 * @tc.desc: Verify the EffectModelGetEffectDescriptor function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectModelTest, HdfAudioGetEffectDescriptor002, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;

    int32_t ret = model_->GetEffectDescriptor(model_, effectId_, &desc);
    ASSERT_EQ(ret, HDF_SUCCESS);
    EXPECT_STREQ(desc.effectId, effectId_);
    EXPECT_STREQ(desc.effectName, "mock_effect");
    EXPECT_STREQ(desc.libName, libName_);
    EXPECT_STREQ(desc.supplier, "mock");
    OHOS::Audio::EffectControllerReleaseDesc(&desc);
}
} // end of namespace
