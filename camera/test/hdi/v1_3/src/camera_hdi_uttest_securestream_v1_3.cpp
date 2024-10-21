/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_hdi_uttest_securestream_v1_3.h"
#include <functional>

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
void CameraHdiUtTestSecureStreamV1_3::SetUpTestCase(void) {}
void CameraHdiUtTestSecureStreamV1_3::TearDownTestCase(void) {}
void CameraHdiUtTestSecureStreamV1_3::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_3>();
    cameraTest->Init(); // assert inside
    cameraTest->OpenSecureCamera(DEVICE_1); // assert inside
}

void CameraHdiUtTestSecureStreamV1_3::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: Camera_Hdi_SecureStream_V1_3_002
 * @tc.desc: invoke GetSecureCameraSeq, verification
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestSecureStreamV1_3, Camera_Hdi_SecureStream_V1_3_002, TestSize.Level1)
{
    EXPECT_NE(cameraTest, nullptr);
    EXPECT_NE(cameraTest->cameraDeviceV1_3, nullptr);
    uint64_t SeqId;
    int32_t res = cameraTest->cameraDeviceV1_3->GetSecureCameraSeq(SeqId);
    std::cout << "SeqId: " << SeqId << std::endl;
    (void)res;
}

/**
 * @tc.name: Camera_Hdi_SecureStream_V1_3_003
 * @tc.desc: invoke Secure stream
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestSecureStreamV1_3, Camera_Hdi_SecureStream_V1_3_003, TestSize.Level1)
{
    // PREVIEW stream
    cameraTest->intents = {PREVIEW};

    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::HdiCommonV1_3::TestStreamOperatorCallbackV1_3();

    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_EQ(false, cameraTest->rc != HDI::Camera::V1_0::NO_ERROR);
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    std::shared_ptr<OHOS::Camera::HdiCommonV1_1::StreamConsumer> consumer_pre =
		std::make_shared<OHOS::Camera::HdiCommonV1_1::StreamConsumer>();
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo =
    {
        .type = static_cast<OHOS::HDI::Camera::V1_1::ExtendedStreamInfoType>(
            OHOS::HDI::Camera::V1_3::EXTENDED_STREAM_INFO_SECURE),
        .width = 1024,
        .height = 768,
        .format = PIXEL_FMT_YCRCB_420_SP,
        .dataspace = UT_DATA_SIZE,
        .bufferQueue = consumer_pre->CreateProducerSeq([this](void* addr, uint32_t size) {
            cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
        })
    };
    cameraTest->consumerMap_[StreamIntent::PREVIEW] = consumer_pre;
    cameraTest->streamInfoPre->extendedStreamInfos = {extendedStreamInfo};
    cameraTest->streamInfos.push_back(*(cameraTest->streamInfoPre));
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfos);
    EXPECT_EQ(false, cameraTest->rc != HDI::Camera::V1_0::NO_ERROR);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::OperationMode::SECURE),
        cameraTest->abilityVec);
    EXPECT_EQ(false, cameraTest->rc != HDI::Camera::V1_0::NO_ERROR);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    //release stream
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}
