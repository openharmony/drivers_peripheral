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
constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;
constexpr uint32_t DATA_COUNT = 1;
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

bool IsTagValueExistsU8(std::shared_ptr<CameraMetadata> ability, uint32_t tag, uint8_t value)
{
    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, tag, &entry);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(entry.count, 0);
    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == value) {
            return true;
        }
    }
    return false;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_001
 * @tc.desc: OHOS_ABILITY_SKETCH_ENABLE_RATIO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_001, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SKETCH_ENABLE_RATIO, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_ENABLE_RATIO> f value start.");
        printf("OHOS_ABILITY_SKETCH_ENABLE_RATIO f value count %d\n", entry.count);
        constexpr size_t step = 4; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_SKETCH_ENABLE_RATIO %s\n", ss.str().c_str());
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
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO> f value start.");
        printf("OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO f value count %d\n", entry.count);
        constexpr size_t step = 4; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                printf("OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO %s\n", ss.str().c_str());
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
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(
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
    cameraTest->cameraDeviceV1_1->UpdateSettings(metaVec);

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
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
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
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
}

/**
 * @tc.name: CommitStreams_V1_1_SCAN_CODE
 * @tc.desc: CommitStreams_V1_1 for Scan code, preview and video
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_011, TestSize.Level1)
{
    // Get Stream Operator
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // video streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // is streams supported V1_1
    std::shared_ptr<CameraMetadata> modeSetting = std::make_shared<CameraMetadata>(2, 128);
    int64_t expoTime = 0;
    modeSetting->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &expoTime, 1);
    int64_t colorGains[4] = {0};
    modeSetting->addEntry(OHOS_SENSOR_COLOR_CORRECTION_GAINS, &colorGains, 4);
    std::vector<uint8_t> modeSettingVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, modeSettingVec);
    StreamSupportType pType;
    cameraTest->rc = cameraTest->streamOperator_V1_1->IsStreamsSupported_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SCAN_CODE),
        modeSettingVec, cameraTest->streamInfosV1_1, pType);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    // create and commitstreams
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SCAN_CODE),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);

    // start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    sleep(UT_SECOND_TIMES);

    // stop stream
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_012, TestSize.Level1)
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

HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_013, TestSize.Level1)
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

#define TODEFINESTRING(x) #x

static std::string TranslateXMageAbilityToString(camera_xmage_color_type mode)
{
    std::string res;

    switch (mode) {
        case CAMERA_CUSTOM_COLOR_NORMAL:
        {
            res = TODEFINESTRING(CAMERA_CUSTOM_COLOR_NORMAL);
            break;
        }
        case CAMERA_CUSTOM_COLOR_BRIGHT:
        {
            res = TODEFINESTRING(CAMERA_CUSTOM_COLOR_BRIGHT);
            break;
        }
        case CAMERA_CUSTOM_COLOR_SOFT:
        {
            res = TODEFINESTRING(CAMERA_CUSTOM_COLOR_SOFT);
            break;
        }
        default:
            break;
    }
    return res;
}

HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_014, TestSize.Level1)
{
    // Start Xmage control setting and verify
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SUPPORTED_COLOR_MODES, &entry);

    std::vector<uint8_t> xmageAbilities;
    // 查询支持的Xmage所有模式
    if (ret == 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        EXPECT_NE(entry.count, 0);

        for (uint32_t i = 0; i < entry.count; ++i) {
            // 打印并保存当前相机所支持的xmage能力
            CAMERA_LOGI("Current camera xmage ability %{public}s supported!",
                TranslateXMageAbilityToString(static_cast<camera_xmage_color_type>(entry.data.u8[i])).c_str());

            xmageAbilities.push_back(entry.data.u8[i]);
        }
    } else {
        CAMERA_LOGI("XMage not supported");
    }

    CAMERA_LOGI("%{public}lu xmage abilities supported",
                          static_cast<unsigned long>(xmageAbilities.size()));

    // 打开文件dump开关
    cameraTest->imageDataSaveSwitch = SWITCH_ON;

    // 遍历所有的xmage能力，并获取预览 图片 视频
    for (uint32_t i = 0; i < xmageAbilities.size(); ++i) {
        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
        // 设置模式
        uint8_t xmageMode = xmageAbilities[i];
        meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &xmageMode, 1);
        std::vector<uint8_t> metaVec;
        MetadataUtils::ConvertMetadataToVec(meta, metaVec);
        cameraTest->cameraDevice->UpdateSettings(metaVec);

        CAMERA_LOGI("Now current camera xmage ability is %{public}s !",
                TranslateXMageAbilityToString(static_cast<camera_xmage_color_type>(xmageMode)).c_str());

        // 配置三路流信息
        cameraTest->intents = {PREVIEW, STILL_CAPTURE, VIDEO};
        cameraTest->StartStream(cameraTest->intents);

        // 捕获预览流
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);

        // 捕获拍照流，连拍
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);

        // 捕获拍照流，连拍
        cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

        // 后处理
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture,
                                                                        cameraTest->captureIdVideo};

        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture, cameraTest->streamIdVideo};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);

        sleep(1);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_015
 * @tc.desc: OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_015, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.count > 0) {
        EXPECT_TRUE(entry.data.i32 != nullptr);
        CAMERA_LOGI("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME: %{public}d", entry.data.i32[0]);
    } else {
        CAMERA_LOGI("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME not supported");
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_016
 * @tc.desc: OHOS_CONTROL_NIGHT_MODE_TRY_AE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_016, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &entry);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME> f value start.");
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_CONTROL_NIGHT_MODE_TRY_AE : %d\n", entry.data.i32[i]);
            int32_t value = entry.data.i32[i];
            meta->addEntry(OHOS_CONTROL_NIGHT_MODE_TRY_AE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_NIGHT_MODE_TRY_AE success!");
            TakePhotoWithTags(meta);
        }
        CAMERA_LOGI("print tag<OHOS_CONTROL_NIGHT_MODE_TRY_AE> f value end.");
    } else {
        CAMERA_LOGI("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME value count is 0");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_017
 * @tc.desc: OHOS_CONTROL_MANUAL_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_017, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &entry);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME> f value start.");
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_CONTROL_MANUAL_EXPOSURE_TIME : %d\n", entry.data.i32[i]);
            int32_t value = entry.data.i32[i];
            meta->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_MANUAL_EXPOSURE_TIME success!");
            TakePhotoWithTags(meta);
        }
        CAMERA_LOGI("print tag<OHOS_CONTROL_MANUAL_EXPOSURE_TIME> f value end.");
    } else {
        CAMERA_LOGI("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME value count is 0");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_018
 * @tc.desc: OHOS_CAMERA_MESURE_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_018, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_MESURE_EXPOSURE_TIME, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.count > 0) {
        EXPECT_TRUE(entry.data.i32 != nullptr);
        CAMERA_LOGI("OHOS_CAMERA_MESURE_EXPOSURE_TIME: %{public}d", entry.data.i32[0]);
    } else {
        CAMERA_LOGI("OHOS_CAMERA_MESURE_EXPOSURE_TIME not supported");
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_019
 * @tc.desc: OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_019, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.count > 0) {
        EXPECT_TRUE(entry.data.i32 != nullptr);
        CAMERA_LOGI("OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE: %{public}d", entry.data.i32[0]);
    } else {
        CAMERA_LOGI("OHOS_CAMERA_EXPOSURE_MODE_PREVIEW_STATE not supported");
    }
}

void CameraHdiUtTestV1_2::TakePhotoWithTags(std::shared_ptr<OHOS::Camera::CameraSetting> metaDate)
{
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(metaDate, metaVec);
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

HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_020, TestSize.Level1)
{
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Start Xmage control setting and verify
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t xmageMode = CAMERA_CUSTOM_COLOR_BRIGHT;
    meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &xmageMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);

    cameraTest->intents = {PREVIEW, STILL_CAPTURE, VIDEO};
    cameraTest->StartStream(cameraTest->intents);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_021, TestSize.Level1)
{
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Start Xmage control setting and verify
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t xmageMode = CAMERA_CUSTOM_COLOR_SOFT;
    meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &xmageMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);

    cameraTest->intents = {PREVIEW, STILL_CAPTURE, VIDEO};
    cameraTest->StartStream(cameraTest->intents);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_022
 * @tc.desc:OHOS_CAMERA_VIDEO_STABILIZATION_OFF, OHOS_CAMERA_VIDEO_STABILIZATION_AUTO
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_022, TestSize.Level1)
{
    //find Stabilization tag
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    CAMERA_LOGI("get OHOS_ABILITY_VIDEO_STABILIZATION_MODES success!");
    EXPECT_EQ(META_TYPE_BYTE, entry.data_type);
    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == OHOS_CAMERA_VIDEO_STABILIZATION_OFF) {
            CAMERA_LOGI("OHOS_CAMERA_VIDEO_STABILIZATION_OFF found!");
        } else if (entry.data.u8[i] == OHOS_CAMERA_VIDEO_STABILIZATION_AUTO) {
            CAMERA_LOGI("OHOS_CAMERA_VIDEO_STABILIZATION_AUTO found!");
        }
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_023
 * @tc.desc:OHOS_CAMERA_VIDEO_STABILIZATION_OFF
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_023, TestSize.Level1)
{
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    //start stream
    cameraTest->intents = {PREVIEW, VIDEO};
    cameraTest->StartStream(cameraTest->intents);

    //updateSettings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t videoStabiliMode = OHOS_CAMERA_VIDEO_STABILIZATION_OFF;
    meta->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabiliMode, DATA_COUNT);
    const int32_t deviceStreamId = cameraTest->streamIdPreview;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);

    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    //get preview capture and video
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    //release stream
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_024
 * @tc.desc:OHOS_CAMERA_VIDEO_STABILIZATION_AUTO
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_024, TestSize.Level1)
{
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    //start stream
    cameraTest->intents = {PREVIEW, VIDEO};
    cameraTest->StartStream(cameraTest->intents);

    //updateSettings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t videoStabiliMode = OHOS_CAMERA_VIDEO_STABILIZATION_AUTO;
    meta->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabiliMode, DATA_COUNT);
    const int32_t deviceStreamId = cameraTest->streamIdPreview;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);

    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    //get preview capture and video
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    //release stream
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_025
 * @tc.desc:SetCallbackV1_2, Callback object = nullptr;
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_025, TestSize.Level1)
{
    int32_t ret;
    // step 1: close cameraDevice
    cameraTest->Close();
    // step 2: get serviceV1_2
    cameraTest->serviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraHost::Get("camera_service", false);
    EXPECT_NE(cameraTest->serviceV1_2, nullptr);
    CAMERA_LOGI("V1_2::ICameraHost get success");
    // step 3: set callback object which is nullptr
    ret = cameraTest->serviceV1_2->SetCallbackV1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(ret, HDI::Camera::V1_2::INVALID_ARGUMENT);
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_026
 * @tc.desc:SetCallbackV1_2, Callback object exits;
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_026, TestSize.Level1)
{
    int32_t ret;
    // step 1: close cameraDevice
    cameraTest->Close();
    // step 2: get serviceV1_2
    cameraTest->serviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraHost::Get("camera_service", false);
    EXPECT_NE(cameraTest->serviceV1_2, nullptr);
    CAMERA_LOGI("V1_2::ICameraHost get success");
    // step 3: set callback object which is exits
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    ret = cameraTest->serviceV1_2->SetCallbackV1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_027
 * @tc.desc:SetFlashlightV1_2, turn off the flashlight with the camera closed
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_027, TestSize.Level1)
{
    int32_t ret;
    // step 1: close cameraDevice
    cameraTest->Close();
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    ret = cameraTest->serviceV1_2->SetCallbackV1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(ret, 0);
    // step 3: turn off the flashlight
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->statusV1_2 = 0.0f;
        cameraTest->rc = cameraTest->serviceV1_2->SetFlashlightV1_2(cameraTest->statusV1_2);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        // delay for obtaining statucCallback
        sleep(UT_SECOND_TIMES);
        EXPECT_EQ(OHOS::Camera::Test::statusCallback, HDI::Camera::V1_0::FLASHLIGHT_OFF);
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_028
 * @tc.desc:SetFlashlightV1_2, turn on the flashlight with the camera closed
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_028, TestSize.Level1)
{
    int32_t ret;
    // step 1: close cameraDevice
    cameraTest->Close();
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    ret = cameraTest->serviceV1_2->SetCallbackV1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(ret, 0);
    // step 3: turn off the flashlight
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->statusV1_2 = 1.0f;
        cameraTest->rc = cameraTest->serviceV1_2->SetFlashlightV1_2(cameraTest->statusV1_2);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        // delay for obtaining statucCallback
        sleep(UT_SECOND_TIMES);
        EXPECT_EQ(OHOS::Camera::Test::statusCallback, HDI::Camera::V1_0::FLASHLIGHT_ON);
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_029
 * @tc.desc:Turn on the flashlight with the camera open
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_029, TestSize.Level1)
{
    int32_t ret;
    // step 1: close cameraDevice
    cameraTest->Close();
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    ret = cameraTest->serviceV1_2->SetCallbackV1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(ret, 0);
    // step 3: open the cameraDevice
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    // step 4: turn on the flashlight
    cameraTest->statusV1_2 = 1.0f;
    cameraTest->rc = cameraTest->serviceV1_2->SetFlashlightV1_2(cameraTest->statusV1_2);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_2::DEVICE_CONFLICT);
    EXPECT_EQ(OHOS::Camera::Test::statusCallback, HDI::Camera::V1_0::FLASHLIGHT_UNAVAILABLE);
    // step 5: close the cameraDevice
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->Close();
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_030
 * @tc.desc:Turn off the flashlight with the camera open
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_030, TestSize.Level1)
{
    int32_t ret;
    // step 1: close cameraDevice
    cameraTest->Close();
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    ret = cameraTest->serviceV1_2->SetCallbackV1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(ret, 0);
    // step 3: open the cameraDevice
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    // step 4: turn on the flashlight
    cameraTest->statusV1_2 = 0.0f;
    cameraTest->rc = cameraTest->serviceV1_2->SetFlashlightV1_2(cameraTest->statusV1_2);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_2::DEVICE_CONFLICT);
    // step 5: close the cameraDevice
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    // delay for obtaining statusCallback
    sleep(UT_SECOND_TIMES);
    EXPECT_EQ(OHOS::Camera::Test::statusCallback, HDI::Camera::V1_0::FLASHLIGHT_UNAVAILABLE);
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_031
 * @tc.desc:Turn off the flashlight with the camera closed
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_031, TestSize.Level1)
{
    int32_t ret;
    // step 1: close cameraDevice
    cameraTest->Close();
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    ret = cameraTest->serviceV1_2->SetCallbackV1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(ret, 0);
    // step 3: open the cameraDevice
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    // step 4: turn on the flashlight
    cameraTest->statusV1_2 = 1.0f;
    cameraTest->rc = cameraTest->serviceV1_2->SetFlashlightV1_2(cameraTest->statusV1_2);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_2::DEVICE_CONFLICT);
    // step 5: close the cameraDevice
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->Close();
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    // step 6: trun off the flashlight
    cameraTest->statusV1_2 = 0.0f;
    cameraTest->rc = cameraTest->serviceV1_2->SetFlashlightV1_2(cameraTest->statusV1_2);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_2::NO_ERROR);
    // delay for obtaining statusCallback
    sleep(UT_SECOND_TIMES);
    EXPECT_EQ(OHOS::Camera::Test::statusCallback, HDI::Camera::V1_0::FLASHLIGHT_OFF);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_032
 * @tc.desc: OHOS_ABILITY_AVAILABLE_COLOR_SPACES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_032, TestSize.Level1)
{
    CAMERA_LOGI("CameraHdiUtTestV1_2 Camera_Device_Hdi_V1_2_032 start ...");
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &entry);
    printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES value count %d\n", entry.count);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        constexpr size_t step = 10; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES: %s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_033
 * @tc.desc: P3 color spaces
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_033, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_2_033 start ...");
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(
        cameraTest->streamOperatorCallback, cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreviewV1_2(cameraTest->streamInfoV1_1);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = 2294273;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    // capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfoCapture->v1_0.dataspace_ = 2294273;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(
		    OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->streamInfosV1_1.clear();
    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreviewV1_2(cameraTest->streamInfoV1_1);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = 2294278;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    // video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfoVideo->v1_0.dataspace_ = 2294278;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(
		    OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: CommitStreams_V1_1_SUPER_STAB
 * @tc.desc: CommitStreams_V1_1 for super stabilization mode, preview and video
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_SuperStub01, TestSize.Level1)
{
    // Check SUPER_STAB in OHOS_ABLITY_CAMERA_MODES tag
    bool superStabModeFlag = IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES,
        OHOS::HDI::Camera::V1_2::SUPER_STAB);
    EXPECT_EQ(superStabModeFlag, true);

    // Get Stream Operator
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // video streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // is streams supported V1_1
    std::shared_ptr<CameraMetadata> modeSetting = std::make_shared<CameraMetadata>(2, 128);
    int64_t expoTime = 0;
    modeSetting->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &expoTime, 1);
    int64_t colorGains[4] = {0};
    modeSetting->addEntry(OHOS_SENSOR_COLOR_CORRECTION_GAINS, &colorGains, 4);
    std::vector<uint8_t> modeSettingVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, modeSettingVec);
    StreamSupportType pType;
    cameraTest->rc = cameraTest->streamOperator_V1_1->IsStreamsSupported_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SUPER_STAB),
        modeSettingVec, cameraTest->streamInfosV1_1, pType);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    // create and commitstreams
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SUPER_STAB),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);

    // start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    // wait to stop
    uint32_t waitTime = 0;
    auto envStr = getenv("UT_SUPER_STAB_KEEP_SECOND");
    if (envStr != nullptr) {
        waitTime = atoi(envStr);
    }
    waitTime = (waitTime > 0 && waitTime < UT_SECOND_TIMES_MAX) ? waitTime : UT_SECOND_TIMES;
    std::cout << "wait for [ " << waitTime << " ] second, then stop capture." << std::endl;
    std::cout << "you can use env var UT_SUPER_STAB_KEEP_SECOND to set the wait time." << std::endl;
    sleep(waitTime);

    // stop stream
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_034
 * @tc.desc:Whether macro ability support
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_034, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MACRO_SUPPORTED, &entry);
    if (ret == 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        CAMERA_LOGI("OHOS_ABILITY_CAMERA_MACRO_SUPPORTED: %{public}d", entry.data.u8[0]);
    } else {
        CAMERA_LOGI("Macro not supported");
    }
}

void CustomCallback(uint64_t timestamp, const std::shared_ptr<CameraMetadata> ability,
    std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    time_t tt = static_cast<time_t>(timestamp);
    CAMERA_LOGD("callback invoke time: %{public}s.", ctime(&tt));

    common_metadata_header_t* data = ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_MACRO_STATUS, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        uint8_t value = entry.data.u8[0];
        // 查询到状态， 检测状态到 微距模式可开启
        if (OHOS_CAMERA_MACRO_ENABLE == value) {
            // 下发设置 开启微距模式
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            uint8_t macroControl = OHOS_CAMERA_MACRO_ENABLE;
            meta->addEntry(OHOS_CONTROL_CAMERA_MACRO, &macroControl, DATA_COUNT);
            // ability meta data serialization for updating
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);

            cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
            CAMERA_LOGD("Macro mode is set enabled.");
        }
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_035
 * @tc.desc: Update macro ability setting and check the callback
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_035, TestSize.Level1)
{
    // Start OHOS_ABILITY_CAMERA_MACRO_SUPPORTED ability query
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MACRO_SUPPORTED, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        uint8_t value = entry.data.u8[0];

        EXPECT_TRUE(value == OHOS_CAMERA_MACRO_NOT_SUPPORTED || value == OHOS_CAMERA_MACRO_SUPPORTED);

        // Macro ability is supported, then verify the callback
        if (OHOS_CAMERA_MACRO_SUPPORTED == value) {
            OHOS::Camera::Test::resultCallback_ = std::bind(CustomCallback, std::placeholders::_1,
                                std::placeholders::_2, cameraTest);
        }
    }

    std::this_thread::sleep_for (std::chrono::seconds(20));
    // 清除测试回调函数
    OHOS::Camera::Test::resultCallback_ = nullptr;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_2_036
 * @tc.desc: P3 color spaces
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_036, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_2_036 start ...");
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(
        cameraTest->streamOperatorCallback, cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreviewV1_2(cameraTest->streamInfoV1_1);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = 2294278;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    // capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfoCapture->v1_0.dataspace_ = 2294278;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(
		    OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->streamInfosV1_1.clear();
    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreviewV1_2(cameraTest->streamInfoV1_1);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = 2294273;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    // video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfoVideo->v1_0.dataspace_ = 2294273;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(
		    OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: PreCameraSwitch
 * @tc.desc: PreCameraSwitch cameraId:device/0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_037, TestSize.Level1)
{
    std::string cameraId = "device/0";

    cameraTest->rc = cameraTest->serviceV1_2->PreCameraSwitch(cameraId);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: PreCameraSwitch
 * @tc.desc: PreCameraSwitch cameraId:device/1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_038, TestSize.Level1)
{
    std::string cameraId = "device/1";

    cameraTest->rc = cameraTest->serviceV1_2->PreCameraSwitch(cameraId);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: PreCameraSwitch
 * @tc.desc: PreCameraSwitch cameraId:device/10
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_039, TestSize.Level1)
{
    std::string cameraId = "device/10";

    cameraTest->rc = cameraTest->serviceV1_2->PreCameraSwitch(cameraId);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
}

/**
 * @tc.name: PreCameraSwitch
 * @tc.desc: PreCameraSwitch cameraId:ABC
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_040, TestSize.Level1)
{
    std::string cameraId = "ABC";

    cameraTest->rc = cameraTest->serviceV1_2->PreCameraSwitch(cameraId);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
}

/**
 * @tc.name: PrelaunchWithOpMode
 * @tc.desc: PrelaunchWithOpMode cameraId:device/0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_041, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/0";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_2->PrelaunchWithOpMode(
        *cameraTest->prelaunchConfig, OHOS::HDI::Camera::V1_2::NORMAL);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: PrelaunchWithOpMode
 * @tc.desc: PrelaunchWithOpMode cameraId:device/1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_042, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/1";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_2->PrelaunchWithOpMode(
        *cameraTest->prelaunchConfig, OHOS::HDI::Camera::V1_2::NORMAL);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: PrelaunchWithOpMode
 * @tc.desc: PrelaunchWithOpMode cameraId:device/10
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_043, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/10";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_2->PrelaunchWithOpMode(
        *cameraTest->prelaunchConfig, OHOS::HDI::Camera::V1_2::NORMAL);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
}

/**
 * @tc.name: PrelaunchWithOpMode
 * @tc.desc: PrelaunchWithOpMode cameraId:ABC
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_044, TestSize.Level1)
{
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "ABC";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_2->PrelaunchWithOpMode(
        *cameraTest->prelaunchConfig, OHOS::HDI::Camera::V1_2::NORMAL);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
}

/**
 * @tc.name: Camera_Hdi_V1_2_045
 * @tc.desc: OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_045, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE, &entry);
    
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        printf("OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE f value count %d\n", entry.count);
        constexpr size_t step = 4; //print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << "";
            if ((i != 0) && (i % step == 0 || i == entry.count -1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE%s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
    }
}

/**
 * @tc.name: Camera_Hdi_V1_2_046
 * @tc.desc: OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_046, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        printf("OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE f value count %d\n", entry.count);
        constexpr size_t step = 4; //print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << "";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE%s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
    }
}

/**
 * @tc.name: Camera_Hdi_V1_2_047
 * @tc.desc: OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_047, TestSize.Level1)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float virtualApertureValue = 1.6;
    meta->addEntry(OHOS_CONTROL_CAMERA_VIRTUAL_APERTURE_VALUE, &virtualApertureValue, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);

    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Hdi_V1_2_048
 * @tc.desc: OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_048, TestSize.Level1)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float physicalApertureValue = 2;
    meta->addEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalApertureValue, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);

    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}
