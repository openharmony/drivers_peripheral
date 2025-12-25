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
constexpr bool IS_DIRECTLY_CALL = false;
/* the input buffer len of the send command */
constexpr uint32_t SEND_COMMAND_LEN = 10;
constexpr uint32_t SEND_COMMAND_LEN_TEST1 = 0;
/* the output buffer len of the command */
constexpr uint32_t GET_BUFFER_LEN = 10;

namespace {
class EffectControlTestAdditional : public testing::Test {
public:
    struct IEffectControl *controller_ = nullptr;
    struct IEffectModel *model_ = nullptr;
    struct ControllerId contollerId_;
    virtual void SetUp();
    virtual void TearDown();
};

void EffectControlTestAdditional::SetUp()
{
    struct EffectInfo info = {
        .libName = strdup("libmock_effect_lib"),
        .effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff"),
        .ioDirection = 1,
    };

    model_ = IEffectModelGet(IS_DIRECTLY_CALL);
    if (model_ == nullptr) {
        GTEST_SKIP() << "model_ is nullptr" << std::endl;
        return;
    }

    int32_t ret = model_->CreateEffectController(model_, &info, &controller_, &contollerId_);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(controller_, nullptr);
}

void EffectControlTestAdditional::TearDown()
{
    if (controller_ != nullptr && model_ != nullptr) {
        int32_t ret = model_->DestroyEffectController(model_, &contollerId_);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }

    if (model_ != nullptr) {
        IEffectModelRelease(model_, IS_DIRECTLY_CALL);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectProcess_0400
 * @tc.name: testEffectProcess001
 * @tc.desc: Verify the EffectControlEffectProcess function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectProcess001, TestSize.Level2)
{
    EXPECT_NE(HDF_SUCCESS, controller_->EffectProcess(controller_, nullptr, nullptr));
}

/**
 * @tc.number: SUB_Driver_Audio_EffectProcess_0500
 * @tc.name: testEffectProcess002
 * @tc.desc: Verify the reliability of the EffectControlEffectProcess function.
 */
HWTEST_F(EffectControlTestAdditional, testEffectProcess002, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0};
    struct AudioEffectBuffer output = {0};
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->EffectProcess(controller_, &input, &output);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1000
 * @tc.name: testEffectSendCommand001
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is
 * AUDIO_EFFECT_COMMAND_INIT_CONTOLLER.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER, input, SEND_COMMAND_LEN,
                                       output, &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1100
 * @tc.name: testEffectSendCommand002
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_INIT_CONTOLLER.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand002, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER, input,
                                           SEND_COMMAND_LEN_TEST1, output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1300
 * @tc.name: testEffectSendCommand004
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand004, TestSize.Level2)
{
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER, nullptr, SEND_COMMAND_LEN,
                                           nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1400
 * @tc.name: testEffectSendCommand005
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is
 * AUDIO_EFFECT_COMMAND_SET_PARAM.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand005, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM, input, SEND_COMMAND_LEN, output,
                                       &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1500
 * @tc.name: testEffectSendCommand006
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_SET_PARAM.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand006, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM, input, SEND_COMMAND_LEN_TEST1,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1600
 * @tc.name: testEffectSendCommand007
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand007, TestSize.Level2)
{
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM, nullptr, SEND_COMMAND_LEN,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1700
 * @tc.name: testEffectSendCommand008
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand008, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM, input, SEND_COMMAND_LEN,
                                           nullptr, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1800
 * @tc.name: testEffectSendCommand009
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand009, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM, input, SEND_COMMAND_LEN, output, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_1900
 * @tc.name: testEffectSendCommand010
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand010, TestSize.Level2)
{
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM, nullptr, SEND_COMMAND_LEN,
                                           nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2000
 * @tc.name: testEffectSendCommand011
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is
 * AUDIO_EFFECT_COMMAND_SET_CONFIG.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand011, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG, input, SEND_COMMAND_LEN, output,
                                       &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2100
 * @tc.name: testEffectSendCommand012
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_SET_CONFIG.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand012, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG, input, SEND_COMMAND_LEN_TEST1,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2200
 * @tc.name: testEffectSendCommand013
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand013, TestSize.Level2)
{
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG, nullptr, SEND_COMMAND_LEN,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2300
 * @tc.name: testEffectSendCommand014
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand014, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG, input, SEND_COMMAND_LEN,
                                           nullptr, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2400
 * @tc.name: testEffectSendCommand015
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand015, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG, input, SEND_COMMAND_LEN,
                                           output, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2500
 * @tc.name: testEffectSendCommand016
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand016, TestSize.Level2)
{
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG, nullptr, SEND_COMMAND_LEN,
                                           nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2600
 * @tc.name: testEffectSendCommand017
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is
 * AUDIO_EFFECT_COMMAND_GET_CONFIG.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand017, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG, input, SEND_COMMAND_LEN, output,
                                       &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2700
 * @tc.name: testEffectSendCommand018
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_GET_CONFIG.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand018, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG, input, SEND_COMMAND_LEN_TEST1,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2800
 * @tc.name: testEffectSendCommand019
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand019, TestSize.Level2)
{
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG, nullptr, SEND_COMMAND_LEN,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_2900
 * @tc.name: testEffectSendCommand020
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand020, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG, input, SEND_COMMAND_LEN,
                                           nullptr, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3000
 * @tc.name: testEffectSendCommand021
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand021, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG, input, SEND_COMMAND_LEN,
                                           output, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3100
 * @tc.name: testEffectSendCommand022
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand022, TestSize.Level2)
{
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG, nullptr, SEND_COMMAND_LEN,
                                           nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3200
 * @tc.name: testEffectSendCommand023
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_RESET.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand023, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET, input, SEND_COMMAND_LEN, output,
                                       &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3300
 * @tc.name: testEffectSendCommand024
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_RESET.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand024, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET, input, SEND_COMMAND_LEN_TEST1,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3400
 * @tc.name: testEffectSendCommand025
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand025, TestSize.Level2)
{
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET, nullptr, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3500
 * @tc.name: testEffectSendCommand026
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand026, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET, input, SEND_COMMAND_LEN, nullptr, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3600
 * @tc.name: testEffectSendCommand027
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand027, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET, input, SEND_COMMAND_LEN, output, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3700
 * @tc.name: testEffectSendCommand028
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand028, TestSize.Level2)
{
    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET, nullptr, SEND_COMMAND_LEN, nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3800
 * @tc.name: testEffectSendCommand029
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_ENABLE.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand029, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE, input, SEND_COMMAND_LEN, output,
                                       &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_3900
 * @tc.name: testEffectSendCommand030
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_ENABLE.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand030, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE, input, SEND_COMMAND_LEN_TEST1,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4000
 * @tc.name: testEffectSendCommand031
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand031, TestSize.Level2)
{
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE, nullptr, SEND_COMMAND_LEN, output,
                                           &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4100
 * @tc.name: testEffectSendCommand032
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand032, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE, input, SEND_COMMAND_LEN, nullptr, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4200
 * @tc.name: testEffectSendCommand033
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand033, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE, input, SEND_COMMAND_LEN, output, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4300
 * @tc.name: testEffectSendCommand034
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand034, TestSize.Level2)
{
    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE, nullptr, SEND_COMMAND_LEN, nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4400
 * @tc.name: testEffectSendCommand035
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_DISABLE.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand035, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN, output,
                                       &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4500
 * @tc.name: testEffectSendCommand036
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_DISABLE.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand036, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN_TEST1,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4600
 * @tc.name: testEffectSendCommand037
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand037, TestSize.Level2)
{
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, nullptr, SEND_COMMAND_LEN, output,
                                           &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4700
 * @tc.name: testEffectSendCommand038
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand038, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN, nullptr,
                                           &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4800
 * @tc.name: testEffectSendCommand039
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand039, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN, output, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_4900
 * @tc.name: testEffectSendCommand040
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand040, TestSize.Level2)
{
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, nullptr, SEND_COMMAND_LEN,
                                           nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_5000
 * @tc.name: testEffectSendCommand041
 * @tc.desc: Verify the reliability of the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_DISABLE.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand041, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = HDF_SUCCESS;

    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN, output,
                                       &replyLen);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_5100
 * @tc.name: testEffectSendCommand042
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_DISABLE.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand042, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN_TEST1,
                                           output, &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_5200
 * @tc.name: testEffectSendCommand043
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand043, TestSize.Level2)
{
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, nullptr, SEND_COMMAND_LEN, output,
                                           &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_5300
 * @tc.name: testEffectSendCommand044
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand044, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN, nullptr,
                                           &replyLen);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_5400
 * @tc.name: testEffectSendCommand045
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand045, TestSize.Level2)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};

    int32_t ret =
        controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, input, SEND_COMMAND_LEN, output, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_EffectSendCommand_5500
 * @tc.name: testEffectSendCommand046
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectSendCommand046, TestSize.Level2)
{
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE, nullptr, SEND_COMMAND_LEN,
                                           nullptr, nullptr);
    EXPECT_NE(ret, HDF_SUCCESS);
}

/**
 * @tc.number: SUB_Driver_Audio_GetEffectDescriptor_0300
 * @tc.name: testEffectGetEffectDescriptor001
 * @tc.desc: Verify the GetEffectDescriptor function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectGetEffectDescriptor001, TestSize.Level2)
{
    EXPECT_NE(HDF_SUCCESS, controller_->GetEffectDescriptor(nullptr, nullptr));
}

/**
 * @tc.number: SUB_Driver_Audio_GetEffectDescriptor_0400
 * @tc.name: testEffectGetEffectDescriptor002
 * @tc.desc: Verify the reliability of the GetEffectDescriptor function.
 */
HWTEST_F(EffectControlTestAdditional, testEffectGetEffectDescriptor002, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;
    int32_t ret = HDF_SUCCESS;
    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->GetEffectDescriptor(controller_, &desc);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.number: SUB_Driver_Audio_EffectReverse_0300
 * @tc.name: testEffectEffectReverse001
 * @tc.desc: Verify the EffectReverse function when the input parameter is invalid.
 */
HWTEST_F(EffectControlTestAdditional, testEffectEffectReverse001, TestSize.Level2)
{
    EXPECT_NE(HDF_SUCCESS, controller_->EffectReverse(nullptr, nullptr, nullptr));
}

/**
 * @tc.number: SUB_Driver_Audio_EffectReverse_0400
 * @tc.name: testEffectEffectReverse002
 * @tc.desc: Verify the reliability of the EffectReverse function.
 */
HWTEST_F(EffectControlTestAdditional, testEffectEffectReverse002, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0};
    struct AudioEffectBuffer output = {0};
    int32_t ret = HDF_SUCCESS;
    for (int32_t i = 0; i < 1000; i++) {
        ret = controller_->EffectReverse(controller_, &input, &output);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}
} // end of namespace
