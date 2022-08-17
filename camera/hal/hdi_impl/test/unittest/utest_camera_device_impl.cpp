/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "utest_camera_device_impl.h"

using namespace OHOS::HDI::Camera::V1_0;

void CameraDeviceImplTest::SetUpTestCase(void)
{
}

void CameraDeviceImplTest::TearDownTestCase(void)
{
    std::cout << "Camera::CameraDeviceImpl TearDownTestCase" << std::endl;
}

void CameraDeviceImplTest::SetUp(void)
{
    bool ret = InitCameraHost();
    if (!ret) {
        std::cout << "CameraDeviceImplTest init camerahost failed" << std::endl;
        return;
    }

    ret = GetCameraIds();
    if (!ret) {
        std::cout << "CameraDeviceImplTest init GetCameraIds failed" << std::endl;
        return;
    }

    ret = GetCameraDevice();
    if (!ret) {
        std::cout << "CameraDeviceImplTest init GetCameraDevice failed" << std::endl;
        return;
    }
}

void CameraDeviceImplTest::TearDown(void)
{
}

HWTEST_F(CameraDeviceImplTest, UTestGetStreamOperator, TestSize.Level0)
{
    EXPECT_EQ(false, cameraHost_ == nullptr);
    EXPECT_EQ(false, cameraDevice_ == nullptr);

    bool ret = GetStreamOperator();
    EXPECT_EQ(true, ret);
}

HWTEST_F(CameraDeviceImplTest, UTestUpdateSettings, TestSize.Level0)
{
    EXPECT_EQ(false, cameraHost_ == nullptr);
    EXPECT_EQ(false, cameraDevice_ == nullptr);

    std::vector<std::string> cameraIds;
    CamRetCode ret = (CamRetCode)cameraHost_->GetCameraIds(cameraIds);
    EXPECT_EQ(true, ret == HDI::Camera::V1_0::NO_ERROR);

    std::vector<uint8_t> ability;
    std::string cameraId = cameraIds.front();
    ret = (CamRetCode)cameraHost_->GetCameraAbility(cameraId, ability);
    EXPECT_EQ(true, ret == HDI::Camera::V1_0::NO_ERROR);

    ret = (CamRetCode)cameraDevice_->UpdateSettings(ability);
    EXPECT_EQ(true, ret == HDI::Camera::V1_0::NO_ERROR);
    std::cout << "UTestUpdateSettings ret = " << ret << std::endl;
}

HWTEST_F(CameraDeviceImplTest, UTestSetResultMode, TestSize.Level0)
{
    EXPECT_EQ(false, cameraHost_ == nullptr);
    EXPECT_EQ(false, cameraDevice_ == nullptr);

    ResultCallbackMode mode = PER_FRAME;
    CamRetCode rc = (CamRetCode)cameraDevice_->SetResultMode(mode);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
}

HWTEST_F(CameraDeviceImplTest, UTestGetEnabledResults, TestSize.Level0)
{
    EXPECT_EQ(false, cameraHost_ == nullptr);
    EXPECT_EQ(false, cameraDevice_ == nullptr);

    std::vector<int32_t> results;
    CamRetCode rc = (CamRetCode)cameraDevice_->GetEnabledResults(results);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);

    for (auto &type : results) {
        std::cout << "MetaType = " << type << std::endl;
    }
}

HWTEST_F(CameraDeviceImplTest, UTestEnableResult, TestSize.Level0)
{
    EXPECT_EQ(false, cameraHost_ == nullptr);
    EXPECT_EQ(false, cameraDevice_ == nullptr);

    std::vector<int32_t> results;
    results.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    results.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);
    CamRetCode rc = (CamRetCode)cameraDevice_->EnableResult(results);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
}

HWTEST_F(CameraDeviceImplTest, UTestDisableResult, TestSize.Level0)
{
    EXPECT_EQ(false, cameraHost_ == nullptr);
    EXPECT_EQ(false, cameraDevice_ == nullptr);

    std::vector<int32_t> results;
    results.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    results.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);
    CamRetCode rc = (CamRetCode)cameraDevice_->EnableResult(results);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
    std::vector<int32_t> disable_tag;
    rc = (CamRetCode)cameraDevice_->GetEnabledResults(disable_tag);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);

    rc = (CamRetCode)cameraDevice_->DisableResult(disable_tag);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
}

HWTEST_F(CameraDeviceImplTest, UTestClose, TestSize.Level0)
{
    EXPECT_EQ(false, cameraHost_ == nullptr);
    EXPECT_EQ(false, cameraDevice_ == nullptr);

    if (cameraDevice_ != nullptr) {
        cameraDevice_->Close();
        cameraDevice_ = nullptr;
    }
}
