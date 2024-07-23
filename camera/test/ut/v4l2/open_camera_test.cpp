/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "open_camera_test.h"

void UtestOpenCameraTest::SetUpTestCase(void)
{}
void UtestOpenCameraTest::TearDownTestCase(void)
{}
void UtestOpenCameraTest::SetUp(void)
{
    if (cameraBase == nullptr) {
        cameraBase = std::make_shared<TestCameraBase>();
        cameraBase->Init();
    }
}
void UtestOpenCameraTest::TearDown(void)
{
    cameraBase->Close();
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: OpenCamera, success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0001)
{
    CAMERA_LOGD("OpenCamera, success.");
    std::vector<std::string> cameraIds;
    cameraBase->cameraHost->GetCameraIds(cameraIds);
    for (const auto &cameraId : cameraIds) {
        CAMERA_LOGI("cameraId = %{public}s", cameraId.c_str());
    }
    std::string cameraId = cameraIds.front();
    const OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    OHOS::sptr<ICameraDevice> cameraDevice;
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraDevice);
    EXPECT_EQ(true, cameraBase->rc == HDI::Camera::V1_0::NO_ERROR);
}

/**
  * @tc.name: OpenCamera cameraID input error
  * @tc.desc: OpenCamera, cameraID is not found.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0010)
{
    CAMERA_LOGD("OpenCamera, cameraID is not found.");
    std::string cameraId = "qwerty";
    OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    CAMERA_LOGD("opencamera begin");
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
    CAMERA_LOGD("opencamera end");
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
}

/**
  * @tc.name: OpenCamera cameraID input error
  * @tc.desc: OpenCamera, cameraID is illegal.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0011)
{
    CAMERA_LOGD("OpenCamera, cameraID is illegal.");
    std::string cameraId = "1";
    OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
}

/**
  * @tc.name: OpenCamera cameraID input error
  * @tc.desc: OpenCamera, cameraID is Empty.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0012)
{
    CAMERA_LOGD("OpenCamera, cameraID is Empty.");
    std::string cameraId;
    OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
}

/**
  * @tc.name: OpenCamera Callback input error
  * @tc.desc: OpenCamera, Callback is Null.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0020)
{
    CAMERA_LOGD("OpenCamera, Callback is Null.");
    std::string cameraId = "CAMERA_FIRST";
    OHOS::sptr<ICameraDeviceCallback> callback = nullptr;
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
}

/**
  * @tc.name: OpenCamera cameraID & Callback input error
  * @tc.desc: OpenCamera, cameraID is not found, callback is null.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0030)
{
    CAMERA_LOGD("OpenCamera, cameraID is not found, callback is null.");
    std::string cameraId = "qwerty";
    OHOS::sptr<ICameraDeviceCallback> callback = nullptr;
    CAMERA_LOGD("opencamera begin");
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
    CAMERA_LOGD("opencamera end");
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase-> rc);
}

/**
  * @tc.name: OpenCamera cameraID & Callback input error
  * @tc.desc: OpenCamera, cameraID is illegal, callback is null.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0031)
{
    CAMERA_LOGD("OpenCamera, cameraID is illegal, callback is null.");
    std::string cameraId = "1";
    OHOS::sptr<ICameraDeviceCallback> callback = nullptr;
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase-> rc);
}

/**
  * @tc.name: OpenCamera cameraID & Callback input error
  * @tc.desc: OpenCamera, cameraID is Empty, callback is null.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0032)
{
    CAMERA_LOGD("OpenCamera, cameraID is Empty, callback is null.");
    std::string cameraId;
    OHOS::sptr<ICameraDeviceCallback> callback = nullptr;
    cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
}

/**
  * @tc.name: Open all Cameras
  * @tc.desc: Open every Cameras what the getCameraId get.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestOpenCameraTest, camera_open_0050)
{
    CAMERA_LOGD("Open all Cameras.");
    std::vector<std::string> cameraIds;
    cameraBase->cameraHost->GetCameraIds(cameraIds);
    for (auto &cameraId : cameraIds) {
        CAMERA_LOGI("cameraId = %{public}s", cameraId.c_str());
        const OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
        cameraBase->rc = (CamRetCode)cameraBase->cameraHost->OpenCamera(cameraId, callback, cameraBase->cameraDevice);
        EXPECT_EQ(true, cameraBase->rc == HDI::Camera::V1_0::NO_ERROR);
        if (cameraBase->rc == HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGI("OpenCamera success, cameraId = %{public}s", cameraId.c_str());
        } else {
            CAMERA_LOGE("OpenCamera fail, rc = %{public}d, cameraId = %{public}s", cameraBase->rc, cameraId.c_str());
        }
    }
}
