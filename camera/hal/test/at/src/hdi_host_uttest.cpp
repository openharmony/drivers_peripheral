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
#include "hdi_host_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void HdiHostUtTest::SetUpTestCase(void) {}
void HdiHostUtTest::TearDownTestCase(void) {}
void HdiHostUtTest::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init();
}

void HdiHostUtTest::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: GitCameraIds
 * @tc.desc: CamRetCode GetCameraIds([out] String[] ipds)
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_001, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->rc = cameraTest->service->GetCameraIds(cameraTest->cameraIds);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        EXPECT_LT(0, cameraTest->cameraIds.size());
        CAMERA_LOGE("check hdi_host: cameraIds.size() = %{public}zu", cameraTest->cameraIds.size());
    }
}

/**
 * @tc.name: GetCameraAbility
 * @tc.desc: GetCameraAbility, abnormal cameraId = ''
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_002, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "";
        cameraTest->rc = cameraTest->service->GetCameraAbility(testCameraId, cameraTest->abilityVec);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: GetCameraAbility
 * @tc.desc: GetCameraAbility, abnormal cameraId = ' '
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_003, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "";
        cameraTest->rc = cameraTest->service->GetCameraAbility(testCameraId, cameraTest->abilityVec);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: OpenCamera
 * @tc.desc: OpenCamera, normal cameraId
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_004, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->service->GetCameraIds(cameraTest->cameraIds);
        cameraTest->deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();
        cameraTest->rc = cameraTest->service->OpenCamera(cameraTest->cameraIds.front(), cameraTest->deviceCallback,
            cameraTest->cameraDevice);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR || cameraTest->cameraDevice == nullptr) {
            CAMERA_LOGE("check hdi_host: OpenCamera failed");
            return;
        }
    }
}

/**
 * @tc.name: OpenCamera
 * @tc.desc: OpenCamera, cameraId is not found
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_005, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "qwerty";
        cameraTest->deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();
        cameraTest->rc = cameraTest->service->OpenCamera(testCameraId, cameraTest->deviceCallback,
            cameraTest->cameraDevice);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: OpenCamera
 * @tc.desc: OpenCamera, cameraId is illegal
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_006, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "1";
        cameraTest->deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();
        cameraTest->rc = cameraTest->service->OpenCamera(testCameraId, cameraTest->deviceCallback,
            cameraTest->cameraDevice);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: OpenCamera
 * @tc.desc: OpenCamera, cameraId is empty
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_007, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "";
        cameraTest->deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();
        cameraTest->rc = cameraTest->service->OpenCamera(testCameraId, cameraTest->deviceCallback,
            cameraTest->cameraDevice);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: OpenCamera
 * @tc.desc: OpenCamera, callback is null
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_008, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->service->GetCameraIds(cameraTest->cameraIds);
        cameraTest->deviceCallback = nullptr;
        cameraTest->rc = cameraTest->service->OpenCamera(cameraTest->cameraIds.front(), cameraTest->deviceCallback,
            cameraTest->cameraDevice);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: OpenCamera
 * @tc.desc: cameraId is not found, callback is null
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_009, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "abc";
        cameraTest->deviceCallback = nullptr;
        cameraTest->rc = cameraTest->service->OpenCamera(testCameraId, cameraTest->deviceCallback,
            cameraTest->cameraDevice);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: SetFlashlight
 * @tc.desc: SetFlashlight, normal cameraId
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_010, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->service->GetCameraIds(cameraTest->cameraIds);
        cameraTest->status = true;
        cameraTest->rc = cameraTest->service->SetFlashlight(cameraTest->cameraIds.front(), cameraTest->status);
        EXPECT_EQ(true, cameraTest->rc == HDI::Camera::V1_0::NO_ERROR);
    }
}

/**
 * @tc.name: SetFlashlight
 * @tc.desc: SetFlashlight, cameraId is not found
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_011, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "abc";
        cameraTest->status = true;
        cameraTest->rc = cameraTest->service->SetFlashlight(testCameraId, cameraTest->status);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: SetFlashlight
 * @tc.desc: SetFlashlight, cameraId is not found
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_012, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        std::string testCameraId = "";
        cameraTest->status = true;
        cameraTest->rc = cameraTest->service->SetFlashlight(testCameraId, cameraTest->status);
        EXPECT_EQ(true, cameraTest->rc == INVALID_ARGUMENT);
    }
}

/**
 * @tc.name: SetFlashlight
 * @tc.desc: SetFlashlight, status is false
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_014, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->service->GetCameraIds(cameraTest->cameraIds);
        cameraTest->status = false;
        cameraTest->rc = cameraTest->service->SetFlashlight(cameraTest->cameraIds.front(), cameraTest->status);
        EXPECT_EQ(true, cameraTest->rc == HDI::Camera::V1_0::NO_ERROR);
    }
}

/**
 * @tc.name: GetCameraAbility
 * @tc.desc: GetCameraAbility, normal cameraId
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(HdiHostUtTest, Camera_Host_Hdi_0015, TestSize.Level0)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->rc = cameraTest->service->GetCameraIds(cameraTest->cameraIds);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        for (int i = 0; i < cameraTest->cameraIds.size(); i++) {
            cameraTest->rc = cameraTest->service->GetCameraAbility(cameraTest->cameraIds[i], cameraTest->abilityVec);
            CAMERA_LOGE("check hdi_host: cameraId = %{public}s", cameraTest->cameraIds[i].c_str());
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        }
    }
}