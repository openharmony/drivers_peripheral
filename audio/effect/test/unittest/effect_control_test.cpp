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
/* the input buffer len of the send command */
constexpr uint32_t SEND_COMMAND_LEN = 10;
/* the output buffer len of the command */
constexpr uint32_t GET_BUFFER_LEN = 10;
# define AUDIO_EFFECT_COMMAND_INVALID_LARGE 20

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
    // input testcase setup step,setup invoked before each testcases
    libName_ = strdup("libmock_effect_lib");
    ASSERT_NE(libName_, nullptr);
    effectId_ = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff");
    ASSERT_NE(effectId_, nullptr);
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
    // input testcase teardown step,teardown invoked after each testcases
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
        EXPECT_EQ(ret, HDF_SUCCESS);
    }

    if (model_ != nullptr) {
        IEffectModelRelease(model_, IS_DIRECTLY_CALL);
    }
}

/**
 * @tc.name: HdfAudioEffectProcess001
 * @tc.desc: Verify the EffectControlEffectProcess function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioEffectProcess001, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0};
    struct AudioEffectBuffer output = {0};

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, controller_->EffectProcess(nullptr, &input, &output));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, controller_->EffectProcess(controller_, nullptr, &output));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, controller_->EffectProcess(controller_, &input, nullptr));
}

/**
 * @tc.name: HdfAudioEffectProcess002
 * @tc.desc: Verify the EffectControlEffectProcess function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioEffectProcess002, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectProcess(controller_, &input, &output);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioEffectProcess003
 * @tc.desc: Verify the EffectControlEffectProcess function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioEffectProcess003, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0, EFFECT_BUFFER_VOID_TYPE, 0, 0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectProcess(controller_, &input, &output);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioEffectProcess004
 * @tc.desc: Verify the EffectControlEffectProcess function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioEffectProcess004, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0, EFFECT_BUFFER_FLOAT_SIGNED_32, 0, 0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectProcess(controller_, &input, &output);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioEffectProcess005
 * @tc.desc: Verify the EffectControlEffectProcess function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioEffectProcess005, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0, EFFECT_BUFFER_SIGNED_32, 0, 0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectProcess(controller_, &input, &output);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioEffectProcess006
 * @tc.desc: Verify the EffectControlEffectProcess function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioEffectProcess006, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0, EFFECT_BUFFER_SIGNED_16, 0, 0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectProcess(controller_, &input, &output);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioEffectProcess007
 * @tc.desc: Verify the EffectControlEffectProcess function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioEffectProcess007, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0, EFFECT_BUFFER_UNSIGNED_8, 0, 0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectProcess(controller_, &input, &output);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommand001
 * @tc.desc: Verify the EffectControlSendCommand function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommand001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(nullptr, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

    ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER,
                                           nullptr, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER,
                                           input, SEND_COMMAND_LEN, nullptr, &replyLen);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER,
                                           input, SEND_COMMAND_LEN, output, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INVALID_LARGE,
                                           input, SEND_COMMAND_LEN, nullptr, &replyLen);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
 * @tc.name: HdfAudioSendCommandInit001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_INIT_CONTOLLER.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandInit001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_INIT_CONTOLLER,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommandSetConf001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_SET_CONFIG.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandSetConf001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_CONFIG,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommandGetConf001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_GET_CONFIG.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandGetConf001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_CONFIG,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommandRest001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_RESET.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandRest001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_RESET,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommandEnable001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_ENABLE.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandEnable001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_ENABLE,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommandDisable001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_DISABLE.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandDisable001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;
    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_DISABLE,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommandSetParam001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_SET_PARAM.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandSetParam001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_SET_PARAM,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioSendCommandGetParam001
 * @tc.desc: Verify the EffectControlSendCommand function when cmdId is AUDIO_EFFECT_COMMAND_GET_PARAM.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioSendCommandGetParam001, TestSize.Level1)
{
    int8_t input[SEND_COMMAND_LEN] = {0};
    int8_t output[GET_BUFFER_LEN] = {0};
    uint32_t replyLen = GET_BUFFER_LEN;

    int32_t ret = controller_->SendCommand(controller_, AUDIO_EFFECT_COMMAND_GET_PARAM,
                                           input, SEND_COMMAND_LEN, output, &replyLen);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
 * @tc.name: HdfAudioGetDescriptor001
 * @tc.desc: Verify the EffectGetOwnDescriptor function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioGetDescriptor001, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, controller_->GetEffectDescriptor(nullptr, &desc));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, controller_->GetEffectDescriptor(controller_, nullptr));
}

/**
 * @tc.name: HdfAudioGetDescriptor002
 * @tc.desc: Verify the EffectGetOwnDescriptor function.
 * @tc.type: FUNC
 * @tc.require: I6I658
 */
HWTEST_F(EffectControlTest, HdfAudioGetDescriptor002, TestSize.Level1)
{
    struct EffectControllerDescriptor desc;
    int32_t ret = controller_->GetEffectDescriptor(controller_, &desc);
    ASSERT_EQ(ret, HDF_SUCCESS);
    EXPECT_STREQ(desc.effectId, effectId_);
    EXPECT_STREQ(desc.effectName, "mock_effect");
    EXPECT_STREQ(desc.libName, libName_);
    EXPECT_STREQ(desc.supplier, "mock");
    OHOS::Audio::EffectControllerReleaseDesc(&desc);
}

/**
 * @tc.name: HdfAudioEffectReverse001
 * @tc.desc: Verify the EffectControlEffectReverse function when the input parameter is invalid.
 * @tc.type: FUNC
 * @tc.require: I7ASKC
 */
HWTEST_F(EffectControlTest, HdfAudioEffectReverse001, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0};
    struct AudioEffectBuffer output = {0};

    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, controller_->EffectReverse(nullptr, &input, &output));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, controller_->EffectReverse(controller_, nullptr, &output));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, controller_->EffectReverse(controller_, &input, nullptr));
}

/**
 * @tc.name: HdfAudioEffectReverse002
 * @tc.desc: Verify the EffectControlEffectReverse function.
 * @tc.type: FUNC
 * @tc.require: I7ASKC
 */
HWTEST_F(EffectControlTest, HdfAudioEffectReverse002, TestSize.Level1)
{
    struct AudioEffectBuffer input = {0};
    struct AudioEffectBuffer output = {0};

    int32_t ret = controller_->EffectReverse(controller_, &input, &output);
    EXPECT_EQ(ret, HDF_SUCCESS);
}
} // end of namespace
