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
/* the input buffer len of the send command */
constexpr uint32_t SEND_COMMAND_LEN = 10;
/* the output buffer len of the command */
constexpr uint32_t GET_BUFFER_LEN = 10;

namespace {
class EffectControlTest : public testing::Test {
public:
    struct IEffectControl *controller_ = nullptr;
    struct IEffectModel *model_ = nullptr;
    struct ControllerId contollerId_;
    virtual void SetUp();
    virtual void TearDown();
    char *libName_ = nullptr;
    char *effectId_ = nullptr;
};

void EffectControlTest::SetUp()
{
    libName_ = strdup("libmock_effect_lib");
    effectId_ = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff");
    struct EffectInfo info = {
        .libName = libName_,
        .effectId = effectId_,
        .ioDirection = 1,
    };

    model_ = IEffectModelGet(IS_DIRECTLY_CALL);
    ASSERT_NE(model_, nullptr);

    int32_t ret = model_->CreateEffectController(model_, &info, &controller_, &contollerId_);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(controller_, nullptr);
}

void EffectControlTest::TearDown()
{
    if (libName_ != nullptr) {
        free(libName_);
        libName_ = nullptr;
    }

    if (effectId_ != nullptr) {
        free(effectId_);
        effectId_ = nullptr;
    }

    if (controller_ != nullptr && model_ != nullptr) {
        int32_t ret = model_->DestroyEffectController(model_, &contollerId_);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }

    if (model_ != nullptr) {
        IEffectModelRelease(model_, IS_DIRECTLY_CALL);
    }
}

HWTEST_F(EffectControlTest, HdfAudioEffectProcess001, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectProcess(controller_, &input, &output);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandInit001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandSetConf001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandGetConf001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandRest001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandEnable001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandDisable001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandSetParam001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(EffectControlTest, HdfAudioSendCommandGetParam001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_PARAM,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

} // end of namespace