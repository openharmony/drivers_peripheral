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

#include "camera_utils_utest.h"
#include "camera_host_selfkiller.h"
#include "string"
#include "parameters.h"
using namespace OHOS;
using namespace OHOS::CameraUtest;
using namespace testing::ext;
constexpr const char *DEBUG_SELF_KILL_PARAM_NAME = "debug.camera.setting.selfkill.enable";
void CameraUtilsUTest::SetUpTestCase(void)
{
    CAMERA_LOGD("Camera::CameraUtilsUTest SetUpTestCase");
}

void CameraUtilsUTest::TearDownTestCase(void)
{
    CAMERA_LOGD("Camera::CameraUtilsUTest TearDownTestCase");
}

void CameraUtilsUTest::SetUp(void)
{
    CAMERA_LOGD("Camera::CameraUtilsUTest SetUp");
}

void CameraUtilsUTest::TearDown(void)
{
    CAMERA_LOGD("Camera::CameraUtilsUTest TearDown..");
}

/**
 * @tc.name: CameraUtilsUTest
 * @tc.desc: Test camera host selfkill, the system param is enabled, the camera devices count is 0 and the timing
 * conditions are also met.‌
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraUtilsUTest, TestSelfKiller001, TestSize.Level0)
{
    CAMERA_LOGI("Camera::CameraUtilsUTest TestSelfKiller001");
    OHOS::system::SetParameter(DEBUG_SELF_KILL_PARAM_NAME, "true");
    std::unique_ptr<CameraHostSelfkiller> usbCameraSelfKiller = std::make_unique<CameraHostSelfkiller>(1, 5);
    uint8_t cameraCount = 0;
    bool selfkillNotifyFlag = false;
    EXPECT_EQ(selfkillNotifyFlag, false);
    usbCameraSelfKiller->Init([&cameraCount]() { return cameraCount == 0; },
        [&selfkillNotifyFlag]() {
            CAMERA_LOGI("TestSelfKiller001 selfkill notify.");
            selfkillNotifyFlag = true;
        },
        "debug.camera.setting.selfkill.enable",
        "invlid_service_name");
    cameraCount = 1;
    sleep(3);
    EXPECT_EQ(selfkillNotifyFlag, false);
    sleep(3);
    EXPECT_EQ(selfkillNotifyFlag, false);
    sleep(3);
    EXPECT_EQ(selfkillNotifyFlag, false);
    cameraCount = 0;
    sleep(3);
    EXPECT_EQ(selfkillNotifyFlag, false);
    sleep(4);
    EXPECT_EQ(selfkillNotifyFlag, true);
    usbCameraSelfKiller->DeInit();
}

/**
 * @tc.name: CameraUtilsUTest
 * @tc.desc: Test camera host selfkill, the param is disabled, so it will not self kill
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraUtilsUTest, TestSelfKiller002, TestSize.Level0)
{
    CAMERA_LOGI("Camera::CameraUtilsUTest TestSelfKiller002");
    OHOS::system::SetParameter(DEBUG_SELF_KILL_PARAM_NAME, "false");
    std::unique_ptr<CameraHostSelfkiller> usbCameraSelfKiller = std::make_unique<CameraHostSelfkiller>(1, 3);
    uint8_t cameraCount = 0;
    bool selfkillNotifyFlag = false;
    EXPECT_EQ(selfkillNotifyFlag, false);
    usbCameraSelfKiller->Init([&cameraCount]() { return cameraCount == 0; },
        [&selfkillNotifyFlag]() {
            CAMERA_LOGI("TestSelfKiller002 selfkill notify.");
            selfkillNotifyFlag = true;
        },
        DEBUG_SELF_KILL_PARAM_NAME,
        "invlid_service_name");
    sleep(10);
    EXPECT_EQ(selfkillNotifyFlag, false);
    usbCameraSelfKiller->DeInit();
}

/**
 * @tc.name: CameraUtilsUTest
 * @tc.desc: Test camera host selfkill, the CameraHostSelfkiller Deinited, so it will not self kill
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraUtilsUTest, TestSelfKiller003, TestSize.Level0)
{
    CAMERA_LOGI("Camera::CameraUtilsUTest TestSelfKiller003");
    OHOS::system::SetParameter(DEBUG_SELF_KILL_PARAM_NAME, "true");
    std::unique_ptr<CameraHostSelfkiller> usbCameraSelfKiller = std::make_unique<CameraHostSelfkiller>(1, 5);
    uint8_t cameraCount = 0;
    bool selfkillNotifyFlag = false;
    EXPECT_EQ(selfkillNotifyFlag, false);
    usbCameraSelfKiller->Init([&cameraCount]() { return cameraCount == 0; },
        [&selfkillNotifyFlag]() {
            CAMERA_LOGI("TestSelfKiller002 selfkill notify.");
            selfkillNotifyFlag = true;
        },
        DEBUG_SELF_KILL_PARAM_NAME,
        "invlid_service_name");
    sleep(3);
    usbCameraSelfKiller->DeInit();
    usbCameraSelfKiller = nullptr;
    sleep(10);
    EXPECT_EQ(selfkillNotifyFlag, false);
}