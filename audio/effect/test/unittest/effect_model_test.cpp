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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "v1_0/effect_types.h"
#include "v1_0/ieffect_control.h"
#include "v1_0/ieffect_model.h"

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
    libName_ = strdup("libmock_effect_lib");
    effectId_ = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff");
    model_ = IEffectModelGet(IS_DIRECTLY_CALL);
    ASSERT_NE(nullptr, model_);
}

void EffectModelTest::TearDown()
{
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

HWTEST_F(EffectModelTest, HdfAudioIsSupplyEffectLibs001, TestSize.Level1)
{
    bool isSupport = false;
    int32_t ret = model_->IsSupplyEffectLibs(model_, &isSupport);
    ASSERT_EQ(ret, HDF_SUCCESS);

    if (isSupport == false) {
        HDF_LOGE("remind that the vendor doesn't supply effect libs");
    }
}

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

HWTEST_F(EffectModelTest, HdfAudioGetAllEffecctDescriptor001, TestSize.Level1)
{
    uint32_t descsLen = MAX_DESCRIPTOR_NUM;
    struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];

    int32_t ret = model_->GetAllEffectDescriptors(model_, descs, &descsLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectModelTest, HdfAudioGetEffectDescriptor001, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;

    int32_t ret = model_->GetEffectDescriptor(model_, effectId_, &desc);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

} // end of namespace