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
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init();
    cameraTest->Open();
}

void CameraHalHisyseventTest::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHalHisyseventTest, Camera_Hal_Hisysevent_001, TestSize.Level1)
{
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("GetStreamOperator success");
    } else {
        CAMERA_LOGE("GetStreamOperator fail, rc = %{public}d", cameraTest->rc);
    }
    cameraTest->streamInfoPre = std::make_shared<StreamInfo>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfoPre->format_ = 9990;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfoPre);
    cameraTest->streamInfoCapture = std::make_shared<StreamInfo>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfoCapture->format_ = 9990;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfoCapture);
    cameraTest->rc = cameraTest->streamOperator->CreateStreams(cameraTest->streamInfos);
    EXPECT_EQ(false, cameraTest->rc != HDI::Camera::V1_0::NO_ERROR);
    cameraTest->rc = cameraTest->streamOperator->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(false, cameraTest->rc != HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    sleep(1);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}