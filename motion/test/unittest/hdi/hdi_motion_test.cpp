/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hdf_base.h"
#include "motion_callback_impl.h"
#include "osal_time.h"
#include "v1_1/imotion_interface.h"
#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include <unistd.h>
#include <vector>

#define DATA_NUM 12
#define DATA_VALUE 6

using namespace OHOS::HDI::Motion::V1_1;
using namespace testing::ext;

namespace {
sptr<OHOS::HDI::Motion::V1_1::IMotionInterface> g_motionInterface = nullptr;
sptr<IMotionCallback> g_motionCallback = new MotionCallbackImpl();
sptr<IMotionCallback> g_motionCallbackUnregistered = new MotionCallbackImpl();
std::vector<uint8_t> g_motionConfigData(DATA_NUM, DATA_VALUE);
} // namespace

class HdfMotionTestAdditional : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfMotionTestAdditional::SetUpTestCase() { g_motionInterface = OHOS::HDI::Motion::V1_1::IMotionInterface::Get(); }

void HdfMotionTestAdditional::TearDownTestCase() {}

void HdfMotionTestAdditional::SetUp()
{
    if (g_motionInterface == nullptr) {
        printf("Motion is not supported ");
        GTEST_SKIP() << "Device not exist" << std::endl;
        return;
    }
}

void HdfMotionTestAdditional::TearDown() {}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0100
 * @tc.name   : testHdiEnableMotion001
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion001, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t ret = g_motionInterface->EnableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_CLOSE_TO_EAR);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0200
 * @tc.name   : testHdiEnableMotion002
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion002, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t ret = g_motionInterface->EnableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_POCKET_MODE);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0300
 * @tc.name   : testHdiEnableMotion003
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion003, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t ret = g_motionInterface->EnableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_LEAVE_EAR);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0400
 * @tc.name   : testHdiEnableMotion004
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion004, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t ret = g_motionInterface->EnableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_WRIST_UP);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0600
 * @tc.name   : testHdiEnableMotion006
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion006, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = 0;
    for (size_t i = 0; i < 1000; i++) {
        ret = g_motionInterface->EnableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_CLOSE_TO_EAR);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0700
 * @tc.name   : testHdiEnableMotion007
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion007, Function | MediumTest | Level2)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->EnableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_MAX);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0800
 * @tc.name   : testHdiEnableMotion008
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion008, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->EnableMotion(0);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdienablemotion_0900
 * @tc.name   : testHdiEnableMotion009
 * @tc.desc   : Testing the effectiveness of the EnableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiEnableMotion009, Function | MediumTest | Level2)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->EnableMotion(-1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0100
 * @tc.name   : testHdiDisableMotion001
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion001, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->DisableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_CLOSE_TO_EAR);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0200
 * @tc.name   : testHdiDisableMotion002
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion002, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->DisableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_POCKET_MODE);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0300
 * @tc.name   : testHdiDisableMotion003
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion003, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->DisableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_LEAVE_EAR);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0400
 * @tc.name   : testHdiDisableMotion004
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion004, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->DisableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_WRIST_UP);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0600
 * @tc.name   : testHdiDisableMotion006
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion006, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = 0;
    for (size_t i = 0; i < 1000; i++) {
        ret = g_motionInterface->DisableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_CLOSE_TO_EAR);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0700
 * @tc.name   : testHdiDisableMotion007
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion007, Function | MediumTest | Level2)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->DisableMotion(OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_MAX);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0800
 * @tc.name   : testHdiDisableMotion008
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion008, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->DisableMotion(0);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdidisablemotion_0900
 * @tc.name   : testHdiDisableMotion009
 * @tc.desc   : Testing the effectiveness of the DisableMotion function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiDisableMotion009, Function | MediumTest | Level2)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->DisableMotion(-1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdiregister_0100
 * @tc.name   : testHdiRegister001
 * @tc.desc   : Testing the effectiveness of the Register function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiRegister001, Function | MediumTest | Level2)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->Register(g_motionCallback);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_motionInterface->Register(g_motionCallback);
    EXPECT_EQ(HDF_FAILURE, ret);
    g_motionInterface->Unregister(g_motionCallback);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdiregister_0200
 * @tc.name   : testHdiRegister002
 * @tc.desc   : Testing the effectiveness of the Register function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiRegister002, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = 0;
    for (size_t i = 0; i < 1000; i++) {
        ret = g_motionInterface->Register(g_motionCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalMSleep(50);
        ret = g_motionInterface->Unregister(g_motionCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalMSleep(50);
    }
}

/**
 * @tc.number : SUB_Driver_Motion_Hdiunregister_0100
 * @tc.name   : testHdiUnregister001
 * @tc.desc   : Testing the effectiveness of the Unregister function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiUnregister001, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->Register(g_motionCallback);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_motionInterface->Unregister(g_motionCallback);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdiunregister_0200
 * @tc.name   : testHdiUnregister002
 * @tc.desc   : Testing the effectiveness of the Unregister function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiUnregister002, Function | MediumTest | Level2)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }

    int32_t ret = g_motionInterface->Register(g_motionCallback);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_motionInterface->Unregister(g_motionCallback);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_motionInterface->Unregister(g_motionCallback);
    EXPECT_EQ(HDF_FAILURE, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0100
 * @tc.name   : testHdiSetMotionConfig001
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig001, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_PICKUP;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0200
 * @tc.name   : testHdiSetMotionConfig002
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig002, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_FLIP;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0300
 * @tc.name   : testHdiSetMotionConfig003
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig003, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_CLOSE_TO_EAR;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0400
 * @tc.name   : testHdiSetMotionConfig004
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig004, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_SHAKE;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0500
 * @tc.name   : testHdiSetMotionConfig005
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig005, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_ROTATION;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0600
 * @tc.name   : testHdiSetMotionConfig006
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig006, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_POCKET_MODE;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0700
 * @tc.name   : testHdiSetMotionConfig007
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig007, Function | MediumTest | Level1)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_LEAVE_EAR;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.number : SUB_Driver_Motion_Hdisetmotionconfig_0900
 * @tc.name   : testHdiSetMotionConfig009
 * @tc.desc   : Testing the effectiveness of the SetMotionConfig function
 */
HWTEST_F(HdfMotionTestAdditional, testHdiSetMotionConfig010, Function | MediumTest | Level2)
{
    if (g_motionInterface == nullptr) {
        ASSERT_NE(nullptr, g_motionInterface);
        return;
    }
    int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_MAX;
    int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
