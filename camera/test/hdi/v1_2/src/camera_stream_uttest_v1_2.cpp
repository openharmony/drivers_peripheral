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
#include "camera_stream_uttest_v1_2.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraStreamUtTestV1_2::SetUpTestCase(void) {}
void CameraStreamUtTestV1_2::TearDownTestCase(void) {}
void CameraStreamUtTestV1_2::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->OpenCameraV1_2(DEVICE_0); // assert inside
}

void CameraStreamUtTestV1_2::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_036
 * @tc.desc: updateColorSpace by updateStreams
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraStreamUtTestV1_2, Camera_Stream_Hdi_V1_2_036, TestSize.Level1)
{
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    EXPECT_NE(cameraTest->streamOperator_V1_2, nullptr);
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = OHOS_CAMERA_SRGB_FULL;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    // capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfoCapture->v1_0.dataspace_ = OHOS_CAMERA_SRGB_FULL;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CommitStreams(
        OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->streamOperator_V1_2->CancelCapture(cameraTest->captureIdPreview);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = OHOS_CAMERA_P3_FULL;
    cameraTest->streamInfoCapture->v1_0.dataspace_ = OHOS_CAMERA_P3_FULL;
    cameraTest->rc = cameraTest->streamOperator_V1_2->UpdateStreams(cameraTest->streamInfosV1_1);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}