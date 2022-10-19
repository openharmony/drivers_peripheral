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
    ASSERT_EQ(true, ret);

    ret = GetCameraIds();
    ASSERT_EQ(true, ret);

    ret = GetCameraDevice();
    ASSERT_EQ(true, ret);
}

void CameraDeviceImplTest::TearDown(void)
{
}

HWTEST_F(CameraDeviceImplTest, UTestGetStreamOperator, TestSize.Level0)
{
    bool ret = GetStreamOperator();
    ASSERT_EQ(true, ret);
}

HWTEST_F(CameraDeviceImplTest, UTestUpdateSettings, TestSize.Level0)
{
    std::vector<std::string> cameraIds;
    CamRetCode ret = (CamRetCode)cameraHost_->GetCameraIds(cameraIds);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, ret);

    std::vector<uint8_t> ability;
    std::string cameraId = cameraIds.front();
    ret = (CamRetCode)cameraHost_->GetCameraAbility(cameraId, ability);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, ret);

    ret = (CamRetCode)cameraDevice_->UpdateSettings(ability);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, ret);
    std::cout << "UTestUpdateSettings ret = " << ret << std::endl;
}

HWTEST_F(CameraDeviceImplTest, UTestSetResultMode, TestSize.Level0)
{
    ResultCallbackMode mode = PER_FRAME;
    CamRetCode rc = (CamRetCode)cameraDevice_->SetResultMode(mode);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);
}

HWTEST_F(CameraDeviceImplTest, UTestGetEnabledResults, TestSize.Level0)
{
    std::vector<int32_t> results;
    CamRetCode rc = (CamRetCode)cameraDevice_->GetEnabledResults(results);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    for (const auto &type : results) {
        std::cout << "MetaType = " << type << std::endl;
    }
}

HWTEST_F(CameraDeviceImplTest, UTestEnableResult, TestSize.Level0)
{
    std::vector<int32_t> results;
    results.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    results.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);
    CamRetCode rc = (CamRetCode)cameraDevice_->EnableResult(results);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);
}

HWTEST_F(CameraDeviceImplTest, UTestDisableResult, TestSize.Level0)
{
    std::vector<int32_t> results;
    results.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    results.push_back(OHOS_SENSOR_COLOR_CORRECTION_GAINS);
    CamRetCode rc = (CamRetCode)cameraDevice_->EnableResult(results);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);
    std::vector<int32_t> disable_tag;
    rc = (CamRetCode)cameraDevice_->GetEnabledResults(disable_tag);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    rc = (CamRetCode)cameraDevice_->DisableResult(disable_tag);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);
}

HWTEST_F(CameraDeviceImplTest, UTestClose, TestSize.Level0)
{
    if (cameraDevice_ != nullptr) {
        cameraDevice_->Close();
        cameraDevice_ = nullptr;
    }
}
