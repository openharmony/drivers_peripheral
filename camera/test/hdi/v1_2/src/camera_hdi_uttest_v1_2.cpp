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
#include "camera_hdi_uttest_v1_2.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

int64_t OHOS::Camera::Test::StreamConsumer::g_timestamp[2] = {0};
void CameraHdiUtTestV1_2::SetUpTestCase(void) {}
void CameraHdiUtTestV1_2::TearDownTestCase(void) {}
void CameraHdiUtTestV1_2::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(); // assert inside
}

void CameraHdiUtTestV1_2::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_001
 * @tc.desc: OHOS_ABILITY_SKETCH_ENABLE_RATIO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_001, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_2 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return;
    }

    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SKETCH_ENABLE_RATIO, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_ENABLE_RATIO> f value start.");
        constexpr size_t step = 2; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_ENABLE_RATIO> f value end.");
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_002
 * @tc.desc: OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_002, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_2_002 start");
    cameraTest->Init();
    if (cameraTest->serviceV1_2 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return;
    }
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO> f value start.");
        constexpr size_t step = 2; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO> f value end.");
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_003
 * @tc.desc: sketch
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_003, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_2_003 start");
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_1(
        cameraTest->streamOperatorCallback, cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreviewV1_2(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // sketch streamInfo
    cameraTest->streamInfoSketch = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    // sketch extended streamInfo
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo {
        .type = static_cast<OHOS::HDI::Camera::V1_1::ExtendedStreamInfoType>(
            OHOS::HDI::Camera::V1_2::EXTENDED_STREAM_INFO_SKETCH),
	    .width = 0,
   	    .height = 0,
   	    .format = 0,
	    .dataspace = 0,
	    .bufferQueue = nullptr
    };
    cameraTest->streamInfoSketch->extendedStreamInfos = {extendedStreamInfo};
    cameraTest->DefaultInfosSketch(cameraTest->streamInfoSketch);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoSketch);
    
    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(100, 200);
    float zoomRatio = 20;
    modeSetting->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
    cameraTest->cameraDeviceV1_2->UpdateSettings(metaVec);

    // capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(
		    OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdSketch, cameraTest->captureIdSketch, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdSketch};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdSketch};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: NotifyDeviceStateChangeInfo
 * @tc.desc: notifyType fallingState deviceState fallingState
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_005, TestSize.Level1)
{
    int32_t notifyType = 1;
    int32_t deviceState = 1008;
    cameraTest->rc = cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: NotifyDeviceStateChangeInfo
 * @tc.desc: notifyType foldState deviceState unknown
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_006, TestSize.Level1)
{
    int32_t notifyType = 2;
    int32_t deviceState = 0;
    cameraTest->rc = cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: NotifyDeviceStateChangeInfo
 * @tc.desc: notifyType foldState deviceState expand
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_007, TestSize.Level1)
{
    int32_t notifyType = 2;
    int32_t deviceState = 1;
    cameraTest->rc = cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: NotifyDeviceStateChangeInfo
 * @tc.desc: notifyType foldState deviceState folded
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_008, TestSize.Level1)
{
    int32_t notifyType = 2;
    int32_t deviceState = 2;
    cameraTest->rc = cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: NotifyDeviceStateChangeInfo
 * @tc.desc: notifyType foldState deviceState halfFolded
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_009, TestSize.Level1)
{
    int32_t notifyType = 2;
    int32_t deviceState = 3;
    cameraTest->rc = cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: NotifyDeviceStateChangeInfo
 * @tc.desc: notifyType foldState deviceState error
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_010, TestSize.Level1)
{
    int32_t notifyType = 2;
    int32_t deviceState = 10;
    cameraTest->rc = cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

HWTEST_F(CameraHdiUtTestV1_2, Device_Ability_0001, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SUPPORTED_COLOR_MODES, &entry);
    if (ret == 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        CAMERA_LOGI("OHOS_ABILITY_SUPPORTED_COLOR_MODES: %{public}d", entry.data.u8[0]);
    } else {
        CAMERA_LOGI("XMage not supported");
    }
}

HWTEST_F(CameraHdiUtTestV1_2, Device_Ability_0002, TestSize.Level1)
{
    // Start Xmage control setting and verify
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t xmageMode = CAMERA_CUSTOM_COLOR_NORMAL;
    meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &xmageMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartStream(cameraTest->intents);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    sleep(1);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: Camera_Device_Ability__0001
 * @tc.desc: OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Ability__0001, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Ability__0001 start");
    cameraTest->Init();
    if (cameraTest->serviceV1_2 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return;
    }
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME> f value start.");
        constexpr size_t step = 2; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME> f value end.");
    }
}

/**
 * @tc.name: Camera_Device_Ability__0002
 * @tc.desc: OHOS_CAMERA_MESURE_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Ability__0002, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Ability__0002 start");
    cameraTest->Init();
    if (cameraTest->serviceV1_2 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return;
    }
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_MESURE_EXPOSURE_TIME, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_CAMERA_MESURE_EXPOSURE_TIME> f value start.");
        constexpr size_t step = 2; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_CAMERA_MESURE_EXPOSURE_TIME> f value end.");
    }
}

/**
 * @tc.name: Camera_Device_Ability__0003
 * @tc.desc: OHOS_CAMERA_MANUAL_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Ability__0003, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Ability__0003 start");
    cameraTest->Init();
    if (cameraTest->serviceV1_2 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return;
    }
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_MANUAL_EXPOSURE_TIME, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_CAMERA_MANUAL_EXPOSURE_TIME> f value start.");
        constexpr size_t step = 2; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_CAMERA_MANUAL_EXPOSURE_TIME> f value end.");
    }
}

/**
 * @tc.name: Camera_Device_Ability__0004
 * @tc.desc: OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Ability__0004, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Ability__0004 start");
    cameraTest->Init();
    if (cameraTest->serviceV1_2 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return;
    }
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE> f value start.");
        constexpr size_t step = 2; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE> f value end.");
    }
}

/**
 * @tc.name: Camera_Device_Ability__0005
 * @tc.desc: OHOS_CONTROL_NIGHT_MODE_TRY_AE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Ability__0005, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Ability__0005 start");
    cameraTest->Init();
    if (cameraTest->serviceV1_2 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return;
    }
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_NIGHT_MODE_TRY_AE, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_CONTROL_NIGHT_MODE_TRY_AE> f value start.");
        constexpr size_t step = 2; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_CONTROL_NIGHT_MODE_TRY_AE> f value end.");
    }
}

