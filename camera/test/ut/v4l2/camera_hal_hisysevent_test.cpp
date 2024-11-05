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
#include "camera_hal_hisysevent_test.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraHalHisyseventTest::SetUpTestCase(void) {}
void CameraHalHisyseventTest::TearDownTestCase(void) {}
void CameraHalHisyseventTest::SetUp(void)
{
    cameraBase_ = std::make_shared<TestCameraBase>();
    cameraBase_->Init();
}

void CameraHalHisyseventTest::TearDown(void)
{
    cameraBase_->Close();
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHalHisyseventTest, Camera_Hal_Hisysevent_001, TestSize.Level1)
{
    cameraBase_->AchieveStreamOperator();
    cameraBase_->DefaultInfosPreview();
    cameraBase_->streamInfoPre.format_ = 9990;
    cameraBase_->DefaultInfosCapture();
    cameraBase_->streamInfoCapture.format_ = 9990;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(cameraBase_->streamInfos);
    EXPECT_EQ(false, cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(OperationMode::NORMAL, cameraBase_->ability_);
    EXPECT_EQ(false, cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    sleep(1);
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}