/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "effect_common.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "v1_0/effect_types.h"
#include "v1_0/ieffect_control.h"
#include "v1_0/ieffect_model.h"
#include <gtest/gtest.h>

using namespace std;
using namespace testing::ext;

namespace {
constexpr bool IS_DIRECTLY_CALL = false;
constexpr uint32_t MAX_DESCRIPTOR_NUM = 20;

class EffectModelTestAdditional : public testing::Test {
public:
    struct IEffectModel *model_ = nullptr;
    struct ControllerId controllerId_;
    virtual void SetUp();
    virtual void TearDown();
};

void EffectModelTestAdditional::SetUp()
{
    model_ = IEffectModelGet(IS_DIRECTLY_CALL);
    if (model_ == nullptr) {
        GTEST_SKIP() << "model_ is nullptr" << std::endl;
        return;
    }
}

void EffectModelTestAdditional::TearDown()
{
    if (model_ != nullptr) {
        IEffectModelRelease(model_, IS_DIRECTLY_CALL);
    }
}

/**
 * @tc.number  SUB_Driver_Audio_IsSupplyEffectLibs_0100
 * @tc.name  testEffectIsSupplyEffectLibs001
 * @tc.desc  supply indicates the state whether the vendor/OEM supplies effect libraries.
 */
HWTEST_F(EffectModelTestAdditional, testEffectIsSupplyEffectLibs001, TestSize.Level2)
{
    int32_t ret = model_->IsSupplyEffectLibs(nullptr, nullptr);
    EXPECT_EQ(ret, HDF_ERR_INVALID_OBJECT);
}

/**
 * @tc.number  SUB_Driver_Audio_IsSupplyEffectLibs_0200
 * @tc.name  testEffectIsSupplyEffectLibs002
 * @tc.desc  supply indicates the state whether the vendor/OEM supplies effect libraries.
 */
HWTEST_F(EffectModelTestAdditional, testEffectIsSupplyEffectLibs002, TestSize.Level2)
{
    int32_t ret;
    for (int i = 0; i < 50; i++) {
        ret = model_->IsSupplyEffectLibs(nullptr, nullptr);
        EXPECT_EQ(ret, HDF_ERR_INVALID_OBJECT);
    }
}

/**
 * @tc.number  SUB_Driver_Audio_IsSupplyEffectLibs_0300
 * @tc.name  testEffectIsSupplyEffectLibs003
 * @tc.desc  supply indicates the state whether the vendor/OEM supplies effect libraries.
 */
HWTEST_F(EffectModelTestAdditional, testEffectIsSupplyEffectLibs003, TestSize.Level1)
{
    bool isSupport = true;
    EXPECT_EQ(HDF_SUCCESS, model_->IsSupplyEffectLibs(model_, &isSupport));
}

/**
 * @tc.number  SUB_Driver_Audio_IsSupplyEffectLibs_0400
 * @tc.name  testEffectIsSupplyEffectLibs004
 * @tc.desc  supply indicates the state whether the vendor/OEM supplies effect libraries.
 */
HWTEST_F(EffectModelTestAdditional, testEffectIsSupplyEffectLibs004, TestSize.Level1)
{
    bool isSupport = true;
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_SUCCESS, model_->IsSupplyEffectLibs(model_, &isSupport));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_IsSupplyEffectLibs_0500
 * @tc.name  testEffectIsSupplyEffectLibs005
 * @tc.desc  supply indicates the state whether the vendor/OEM supplies effect libraries.
 */
HWTEST_F(EffectModelTestAdditional, testEffectIsSupplyEffectLibs005, TestSize.Level2)
{
    bool isSupport = true;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->IsSupplyEffectLibs(nullptr, &isSupport));
}

/**
 * @tc.number  SUB_Driver_Audio_IsSupplyEffectLibs_0600
 * @tc.name  testEffectIsSupplyEffectLibs006
 * @tc.desc  supply indicates the state whether the vendor/OEM supplies effect libraries.
 */
HWTEST_F(EffectModelTestAdditional, testEffectIsSupplyEffectLibs006, TestSize.Level2)
{
    bool isSupport = true;
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->IsSupplyEffectLibs(nullptr, &isSupport));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_IsSupplyEffectLibs_0700
 * @tc.name  testEffectIsSupplyEffectLibs007
 * @tc.desc  supply indicates the state whether the vendor/OEM supplies effect libraries.
 */
HWTEST_F(EffectModelTestAdditional, testEffectIsSupplyEffectLibs007, TestSize.Level1)
{
    bool isSupport = false;
    int32_t ret = HDF_SUCCESS;
    for (int32_t i = 0; i < 1000; i++) {
        ret = model_->IsSupplyEffectLibs(model_, &isSupport);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0100
 * @tc.name  testEffectGetAllEffectDescriptors001
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors001, TestSize.Level2)
{
    uint32_t descsLen = MAX_DESCRIPTOR_NUM;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, &descsLen));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0200
 * @tc.name  testEffectGetAllEffectDescriptors002
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors002, TestSize.Level2)
{
    uint32_t descsLen = MAX_DESCRIPTOR_NUM;
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, &descsLen));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0300
 * @tc.name  testEffectGetAllEffectDescriptors003
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors003, TestSize.Level2)
{
    struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, descs, nullptr));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0400
 * @tc.name  testEffectGetAllEffectDescriptors004
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors004, TestSize.Level2)
{
    struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, descs, nullptr));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0500
 * @tc.name  testEffectGetAllEffectDescriptors005
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors005, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, nullptr));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0600
 * @tc.name  testEffectGetAllEffectDescriptors006
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors006, TestSize.Level2)
{
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, nullptr));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0700
 * @tc.name  testEffectGetAllEffectDescriptors007
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors007, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetAllEffectDescriptors(model_, nullptr, nullptr));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0800
 * @tc.name  testEffectGetAllEffectDescriptors008
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors008, TestSize.Level2)
{
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetAllEffectDescriptors(model_, nullptr, nullptr));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_0900
 * @tc.name  testEffectGetAllEffectDescriptors009
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors009, TestSize.Level1)
{
    uint32_t descsLen = 0;
    struct EffectControllerDescriptor descs[1];
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetAllEffectDescriptors(model_, descs, &descsLen));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1000
 * @tc.name  testEffectGetAllEffectDescriptors010
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors010, TestSize.Level2)
{
    struct EffectControllerDescriptor descs[0];
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, descs, nullptr));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1100
 * @tc.name  testEffectGetAllEffectDescriptors011
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors011, TestSize.Level2)
{
    struct EffectControllerDescriptor descs[0];
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, descs, nullptr));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1200
 * @tc.name  testEffectGetAllEffectDescriptors012
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors012, TestSize.Level2)
{
    struct EffectControllerDescriptor descs[100];
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, descs, nullptr));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1300
 * @tc.name  testEffectGetAllEffectDescriptors013
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors013, TestSize.Level2)
{
    struct EffectControllerDescriptor descs[100];
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, descs, nullptr));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1400
 * @tc.name  testEffectGetAllEffectDescriptors014
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors014, TestSize.Level2)
{
    uint32_t descsLen = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, &descsLen));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1500
 * @tc.name  testEffectGetAllEffectDescriptors015
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors015, TestSize.Level2)
{
    uint32_t descsLen = 0;
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, &descsLen));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1600
 * @tc.name  testEffectGetAllEffectDescriptors016
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors016, TestSize.Level2)
{
    uint32_t descsLen = 4294967295;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, &descsLen));
}

/**
 * @tc.number  SUB_Driver_Audio_GetAllEffectDescriptors_1700
 * @tc.name  testEffectGetAllEffectDescriptors017
 * @tc.desc  Get descriptors of all supported audio effects.
 */
HWTEST_F(EffectModelTestAdditional, testEffectGetAllEffectDescriptors017, TestSize.Level2)
{
    uint32_t descsLen = 4294967295;
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetAllEffectDescriptors(nullptr, nullptr, &descsLen));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0100
 * @tc.name  testEffectCreateEffectController001
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController001, TestSize.Level2)
{
    struct IEffectControl *controller = NULL;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->CreateEffectController(nullptr, nullptr, &controller, &controllerId_));
}

/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0200
 * @tc.name  testEffectCreateEffectController002
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController002, TestSize.Level2)
{
    struct IEffectControl *controller = NULL;
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
                  model_->CreateEffectController(nullptr, nullptr, &controller, &controllerId_));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0300
 * @tc.name  testEffectCreateEffectController003
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController003, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->CreateEffectController(model_, nullptr, nullptr, &controllerId_));
}

/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0400
 * @tc.name  testEffectCreateEffectController004
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController004, TestSize.Level2)
{
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->CreateEffectController(model_, nullptr, nullptr, &controllerId_));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0500
 * @tc.name  testEffectCreateEffectController005
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController005, TestSize.Level2)
{
    struct IEffectControl *controller = NULL;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->CreateEffectController(model_, nullptr, &controller, nullptr));
}
/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0600
 * @tc.name  testEffectCreateEffectController006
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController006, TestSize.Level2)
{
    struct IEffectControl *controller = NULL;
    for (int i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->CreateEffectController(model_, nullptr, &controller, nullptr));
    }
}

/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0700
 * @tc.name  testEffectCreateEffectController007
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController007, TestSize.Level1)
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };
    struct IEffectControl *controller = NULL;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->CreateEffectController(model_, nullptr, nullptr, &controllerId_));
    EXPECT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &controller, &controllerId_));
    EXPECT_EQ(HDF_SUCCESS, model_->DestroyEffectController(model_, &controllerId_));
}

/**
 * @tc.number  SUB_Driver_Audio_CreateEffectController_0800
 * @tc.name  testEffectCreateEffectController008
 * @tc.desc  Create an effect controller which is used to operate the effect instance.
 */
HWTEST_F(EffectModelTestAdditional, testEffectCreateEffectController008, TestSize.Level1)
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };
    struct IEffectControl *controller = NULL;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->CreateEffectController(nullptr, nullptr, &controller, &controllerId_));
    EXPECT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &controller, &controllerId_));
    EXPECT_EQ(HDF_SUCCESS, model_->DestroyEffectController(model_, &controllerId_));
}

/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0100
 * @tc.name   : testGetEffectDescriptor001
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor001, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_SUCCESS,
              model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0200
 * @tc.name   : testGetEffectDescriptor002
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor002, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
              model_->GetEffectDescriptor(nullptr, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0300
 * @tc.name   : testGetEffectDescriptor003
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor003, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0400
 * @tc.name   : testGetEffectDescriptor004
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor004, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM,
              model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), nullptr));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0500
 * @tc.name   : testGetEffectDescriptor005
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor005, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_SUCCESS,
                  model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0600
 * @tc.name   : testGetEffectDescriptor006
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor006, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
                  model_->GetEffectDescriptor(nullptr, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0700
 * @tc.name   : testGetEffectDescriptor007
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor007, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0800
 * @tc.name   : testGetEffectDescriptor008
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor008, TestSize.Level2)
{
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_PARAM,
                  model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), nullptr));
    }
}

/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_0900
 * @tc.name   : testGetEffectDescriptor009
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor009, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
              model_->GetEffectDescriptor(nullptr, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
    EXPECT_EQ(HDF_SUCCESS,
              model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1000
 * @tc.name   : testGetEffectDescriptor010
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor010, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
    EXPECT_EQ(HDF_SUCCESS,
              model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1100
 * @tc.name   : testGetEffectDescriptor011
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor011, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM,
              model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), nullptr));
    EXPECT_EQ(HDF_SUCCESS,
              model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1200
 * @tc.name   : testGetEffectDescriptor012
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor012, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
              model_->GetEffectDescriptor(nullptr, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1300
 * @tc.name   : testGetEffectDescriptor013
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor013, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM,
              model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), nullptr));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1400
 * @tc.name   : testGetEffectDescriptor014
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor014, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, nullptr));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1500
 * @tc.name   : testGetEffectDescriptor015
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor015, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1600
 * @tc.name   : testGetEffectDescriptor016
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor016, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, &desc));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1700
 * @tc.name   : testGetEffectDescriptor017
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor017, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1800
 * @tc.name   : testGetEffectDescriptor018
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor018, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_SUCCESS,
                  model_->GetEffectDescriptor(model_, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_1900
 * @tc.name   : testGetEffectDescriptor019
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor019, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
    }
}

/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2000
 * @tc.name   : testGetEffectDescriptor020
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor020, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    }
}

/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2100
 * @tc.name   : testGetEffectDescriptor021
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor021, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
                  model_->GetEffectDescriptor(nullptr, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), &desc));
    }
}

/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2200
 * @tc.name   : testGetEffectDescriptor022
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor022, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, &desc));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2300
 * @tc.name   : testGetEffectDescriptor023
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor023, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
                  model_->GetEffectDescriptor(nullptr, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), nullptr));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2400
 * @tc.name   : testGetEffectDescriptor024
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor024, TestSize.Level2)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, nullptr));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2500
 * @tc.name   : testGetEffectDescriptor025
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor025, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT,
              model_->GetEffectDescriptor(nullptr, strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"), nullptr));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2600
 * @tc.name   : testGetEffectDescriptor026
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor026, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
}
/**
 * @tc.number : SUB_Driver_Audio_GetEffectDescriptor_2700
 * @tc.name   : testGetEffectDescriptor027
 * @tc.desc   : Reliability of function(GetEffectDescriptor)
 */
HWTEST_F(EffectModelTestAdditional, testGetEffectDescriptor027, TestSize.Level2)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->GetEffectDescriptor(nullptr, nullptr, nullptr));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->GetEffectDescriptor(model_, nullptr, nullptr));
}
/**
 * @tc.number : SUB_Driver_Audio_DestroyEffectController_0100
 * @tc.name   : testAudioDestroyEffectController001
 * @tc.desc   : Reliability of function(DestroyEffectController)
 */
HWTEST_F(EffectModelTestAdditional, testAudioDestroyEffectController001, TestSize.Level2)
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };

    struct IEffectControl *controller = NULL;
    ASSERT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &controller, &controllerId_));
    ASSERT_NE(controller, nullptr);
    int32_t i;
    for (i = 0; i < 50; i++) {
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->DestroyEffectController(nullptr, &controllerId_));
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->DestroyEffectController(model_, nullptr));
    }
    EXPECT_EQ(HDF_SUCCESS, model_->DestroyEffectController(model_, &controllerId_));
}
/**
 * @tc.number : SUB_Driver_Audio_DestroyEffectController_0200
 * @tc.name   : testAudioDestroyEffectController002
 * @tc.desc   : Reliability of function(DestroyEffectController)
 */
HWTEST_F(EffectModelTestAdditional, testAudioDestroyEffectController002, TestSize.Level1)
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };

    struct IEffectControl *controller = NULL;
    ASSERT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &controller, &controllerId_));
    ASSERT_NE(controller, nullptr);
    EXPECT_EQ(HDF_SUCCESS, model_->DestroyEffectController(model_, &controllerId_));
}
/**
 * @tc.number : SUB_Driver_Audio_DestroyEffectController_0300
 * @tc.name   : testAudioDestroyEffectController003
 * @tc.desc   : Reliability of function(DestroyEffectController)
 */
HWTEST_F(EffectModelTestAdditional, testAudioDestroyEffectController003, TestSize.Level1)
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };

    struct IEffectControl *controller = NULL;
    int32_t i;
    for (i = 0; i < 50; i++) {
        ASSERT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &controller, &controllerId_));
        ASSERT_NE(controller, nullptr);
        EXPECT_EQ(HDF_SUCCESS, model_->DestroyEffectController(model_, &controllerId_));
    }
}
/**
 * @tc.number : SUB_Driver_Audio_DestroyEffectController_0400
 * @tc.name   : testAudioDestroyEffectController004
 * @tc.desc   : Reliability of function(DestroyEffectController)
 */
HWTEST_F(EffectModelTestAdditional, testAudioDestroyEffectController004, TestSize.Level2)
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };

    struct IEffectControl *controller = NULL;
    ASSERT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &controller, &controllerId_));
    ASSERT_NE(controller, nullptr);

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, model_->DestroyEffectController(nullptr, &controllerId_));
    EXPECT_EQ(HDF_SUCCESS, model_->DestroyEffectController(model_, &controllerId_));
}
/**
 * @tc.number : SUB_Driver_Audio_DestroyEffectController_0500
 * @tc.name   : testAudioDestroyEffectController005
 * @tc.desc   : Reliability of function(DestroyEffectController)
 */
HWTEST_F(EffectModelTestAdditional, testAudioDestroyEffectController005, TestSize.Level2)
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };

    struct IEffectControl *controller = NULL;
    ASSERT_EQ(HDF_SUCCESS, model_->CreateEffectController(model_, &info, &controller, &controllerId_));
    ASSERT_NE(controller, nullptr);

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, model_->DestroyEffectController(model_, nullptr));
    EXPECT_EQ(HDF_SUCCESS, model_->DestroyEffectController(model_, &controllerId_));
}
} // end of namespace
