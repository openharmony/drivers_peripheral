/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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
#include "camera_prelaunch_uttest_v1_1.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraPrelaunchUtTestV1_1::SetUpTestCase(void) {}
void CameraPrelaunchUtTestV1_1::TearDownTestCase(void) {}
void CameraPrelaunchUtTestV1_1::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_1>();
    cameraTest->Init(); // assert inside
}

void CameraPrelaunchUtTestV1_1::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:device/0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraPrelaunchUtTestV1_1, Camera_Device_Hdi_V1_1_001, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/0";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->Open(DEVICE_0);
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:device/1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraPrelaunchUtTestV1_1, Camera_Device_Hdi_V1_1_002, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/1";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->Open(DEVICE_0);
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:device/10
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraPrelaunchUtTestV1_1, Camera_Device_Hdi_V1_1_003, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/10";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);

    cameraTest->Open(DEVICE_0);
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:ABC
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraPrelaunchUtTestV1_1, Camera_Device_Hdi_V1_1_004, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "ABC";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);

    cameraTest->Open(DEVICE_0);
}