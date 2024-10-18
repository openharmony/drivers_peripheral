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
#include "front_camera_hdi_uttest_v1_2.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;
constexpr uint32_t DATA_COUNT = 1;
void FrontCameraHdiUtTestV1_2::SetUpTestCase(void) {}
void FrontCameraHdiUtTestV1_2::TearDownTestCase(void) {}
void FrontCameraHdiUtTestV1_2::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_2>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_1); // assert inside
}

void FrontCameraHdiUtTestV1_2::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: Front_Camera_Hdi_V1_2_001
 * @tc.desc: OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(FrontCameraHdiUtTestV1_2, Front_Camera_Device_Hdi_V1_2_001, TestSize.Level1)
{
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Get Stream Operator
    cameraTest->streamOperatorCallback = new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // capture streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // create and commitstreams
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::PORTRAIT),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float virtualApertureValue = 1.6;
    meta->addEntry(OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualApertureValue, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_2::CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);

    // stop stream
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Front_Camera_Hdi_V1_2_002
 * @tc.desc: OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_RANGE, all value
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(FrontCameraHdiUtTestV1_2, Front_Camera_Device_Hdi_V1_2_002, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        for (size_t i = 0; i < entry.count; i++) {
            // Get Stream Operator
            cameraTest->streamOperatorCallback = new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
            cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
                cameraTest->streamOperator_V1_1);
            EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            // preview streamInfo
            cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

            // capture streamInfo
            cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosCapture(cameraTest->streamInfoV1_1);
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

            // create and commitstreams
            cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
            cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
                static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::PORTRAIT),
                cameraTest->abilityVec);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            //update settings
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            float virtualApertureValue = entry.data.f[i];
            meta->addEntry(OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualApertureValue, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (OHOS::HDI::Camera::V1_2::CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            // start capture
            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);

            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
            sleep(1);
            cameraTest->streamInfosV1_1.clear();
        }
    }
}
