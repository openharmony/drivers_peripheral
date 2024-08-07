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
#include "camera_professional_uttest_v1_3.h"
#include <functional>

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
using namespace OHOS::HDI::Camera;
constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;
constexpr uint32_t DATA_COUNT = 1;
constexpr uint32_t RESOLUTION_COUNT = 23;
constexpr uint32_t RESOLUTION_PARAM = 2;
uint32_t g_supportedResolution[RESOLUTION_COUNT][RESOLUTION_PARAM] = {
    {640, 400}, {640, 480}, {640, 640}, {720, 480}, {720, 540}, {720, 720}, {800, 480}, {800, 600},
    {864, 480}, {960, 720}, {1024, 768}, {1088, 1080}, {1088, 1088}, {1136, 480}, {1280, 592}, {1280, 720},
    {1280, 768}, {1280, 960}, {1440, 1080}, {1584, 720}, {1600, 1200}, {1920, 888}, {1920, 1080}
};
vector<float> supportedPhysicalApertureValues_;
void CameraProfessionalUtTestV1_3::SetUpTestCase(void) {}
void CameraProfessionalUtTestV1_3::TearDownTestCase(void) {}
void CameraProfessionalUtTestV1_3::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_0); // assert inside
}

void CameraProfessionalUtTestV1_3::TearDown(void)
{
    cameraTest->Close();
}

bool g_isModeExists(std::shared_ptr<CameraMetadata> ability, uint32_t tag, uint8_t value)
{
    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, tag, &entry);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(entry.count, 0);
    if (entry.data.u8 != nullptr) {
        for (int i = 0; i < entry.count; i++) {
            if (entry.data.u8[i] == value) {
                return true;
            }
        }
    } else {
        printf("Find CameraMetadata fail!\n");
        CAMERA_LOGE("Find CameraMetadata fail!");
    }
    return false;
}

bool GetSupportedPhysicalApertureValues(std::shared_ptr<CameraMetadata> ability)
{
    supportedPhysicalApertureValues_.clear();
    EXPECT_NE(ability, nullptr);
    common_metadata_header_t* data = ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        float entryValues[] = {entry.data.f[3], entry.data.f[7], entry.data.f[8], entry.data.f[9], entry.data.f[10],
            entry.data.f[14], entry.data.f[18]};
        for (size_t i = 0; i < sizeof(entryValues) / sizeof(float); i++) {
            supportedPhysicalApertureValues_.push_back(entryValues[i]);
        }
        return true;
    } else {
        printf("get tag<OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE> failed.");
        return false;
    }
}

void FillCaptureSetting(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    // Fill capture setting
    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t muteMode = static_cast<uint8_t>(OHOS_CAMERA_MUTE_MODE_OFF);
    modeSetting->addEntry(OHOS_CONTROL_MUTE_MODE, &muteMode, DATA_COUNT);
    uint8_t deferredImage = OHOS::HDI::Camera::V1_2::STILL_IMAGE;
    modeSetting->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredImage, DATA_COUNT);
    std::vector<uint8_t> controlVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, controlVec);
    cameraTest->abilityVec = controlVec;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_001
 * @tc.desc: OHOS_ABILITY_CAMERA_MODES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_001, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        for (size_t i = 0; i < entry.count; i++) {
            float value = entry.data.u8[i];
            if (value == OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO) {
                CAMERA_LOGI("PROFESSIONAL_PHOTO mode is supported");
            } else if (value == OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO) {
                CAMERA_LOGI("PROFESSIONAL_VIDEO mode is supported");
            }
        }
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_1_009
 * @tc.desc: OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_002, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        CAMERA_LOGE("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value start.");
        constexpr size_t step = 10; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGE("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGE("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value end.");
    }
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_003
 * @tc.desc: OHOS_CONTROL_FLASH_MODE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_003, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->Close();
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    //0:close, 1:open, 2:auto, 3:always_open
    for (uint8_t i = 0;i < 4;i++) {
        cameraTest->Init();
        cameraTest->Open(DEVICE_0);
        FillCaptureSetting(cameraTest);
        cameraTest->imageDataSaveSwitch = SWITCH_ON;

        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t flashMode = i;
        meta->addEntry(OHOS_CONTROL_FLASH_MODE, &flashMode, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        cameraTest->imageDataSaveSwitch = SWITCH_OFF;

        cameraTest->Close();
    }
    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_PREVIEW_PHYSICAL_CAMERA_ID, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_004
 * @tc.desc: EXTENDED_STREAM_INFO_RAW, OHOS_CAMERA_FORMAT_DNG, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_004, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // Capture extended streamInfo
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo;
    extendedStreamInfo.type =
        static_cast<OHOS::HDI::Camera::V1_1::ExtendedStreamInfoType>(OHOS::HDI::Camera::V1_3::EXTENDED_STREAM_INFO_RAW);
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer2 =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    extendedStreamInfo.bufferQueue = consumer2->CreateProducerSeq([this](void *addr, uint32_t size) {
        cameraTest->DumpImageFile(105, "dng", addr, size);
    });
    EXPECT_NE(extendedStreamInfo.bufferQueue, nullptr);
    EXPECT_NE(extendedStreamInfo.bufferQueue->producer_, nullptr);
    extendedStreamInfo.bufferQueue->producer_->SetQueueSize(UT_DATA_SIZE);
    extendedStreamInfo.width = 4096;
    extendedStreamInfo.height = 3072;
    extendedStreamInfo.format = OHOS_CAMERA_FORMAT_DNG;
    extendedStreamInfo.dataspace = 0;

    // Capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoCapture->extendedStreamInfos = {extendedStreamInfo};
    cameraTest->DefaultInfosProfessionalCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    // Create and commitstreams
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_005
 * @tc.desc: OHOS_CONTROL_SUPPORTED_COLOR_MODES, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_005, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    //0:normal, 1:bright, 2:soft
    for (uint8_t i = 0;i < 3;i++) {
        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t colorMode = i;
        meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorMode, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_006
 * @tc.desc: FOCUS_ASSIST_FLASH_MODES, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_006, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_ASSIST_FLASH_SUPPORTED_MODES, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (size_t i = 0;i < entry.count;i++) {
            if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_DEFAULT) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_DEFAULT mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_AUTO) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_AUTO mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_ON) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_ON mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_OFF) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_OFF mode is supported!");
            }
        }
    }

    for (uint8_t i = 0;i < entry.count;i++) {
        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t focusAssistFlashMode = entry.data.u8[i];
        meta->addEntry(OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &focusAssistFlashMode, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_006
 * @tc.desc: OHOS_CONTROL_ZOOM_RATIO, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_007, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float zoomRatio = 1.0f;
    meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_008
 * @tc.desc: OHOS_ABILITY_METER_MODES, OHOS_CONTROL_METER_MODE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_008, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_METER_MODES, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (size_t i = 0;i < entry.count;i++) {
            if (entry.data.u8[i] == OHOS_CAMERA_SPOT_METERING) {
                CAMERA_LOGI("OHOS_CAMERA_SPOT_METERING mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_REGION_METERING) {
                CAMERA_LOGI("OHOS_CAMERA_REGION_METERING mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_OVERALL_METERING) {
                CAMERA_LOGI("OHOS_CAMERA_OVERALL_METERING mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_CENTER_WEIGHTED_METERING) {
                CAMERA_LOGI("OHOS_CAMERA_CENTER_WEIGHTED_METERING mode is supported!");
            }
        }
    }

    for (uint8_t i = 0;i < entry.count;i++) {
        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t meteringMode = entry.data.u8[i];
        meta->addEntry(OHOS_CONTROL_METER_MODE, &meteringMode, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_009
 * @tc.desc: OHOS_ABILITY_ISO_VALUES, OHOS_CONTROL_ISO_VALUE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_009, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_ISO_VALUES, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t isoValue = 50;
    meta->addEntry(OHOS_CONTROL_ISO_VALUE, &isoValue, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;

    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_ISO_VALUE, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_010
 * @tc.desc: PHYSICAL_APERTURE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_010, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    GetSupportedPhysicalApertureValues(cameraTest->ability);

    for (uint8_t i = 0;i < supportedPhysicalApertureValues_.size();i++) {
        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        float physicalApertureValue = supportedPhysicalApertureValues_[i];
        meta->addEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalApertureValue, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;

    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_CAMERA_APERTURE_VALUE, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_011
 * @tc.desc: OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, OHOS_CONTROL_SENSOR_EXPOSURE_TIME, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_011, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    camera_rational_t sensorExposureTime = {250, 1000000};
    meta->addEntry(OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &sensorExposureTime, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);

    cameraTest->imageDataSaveSwitch = SWITCH_OFF;

    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_012
 * @tc.desc: AE_COMPENSATION, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_012, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_AE_COMPENSATION_RANGE, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_AE_COMPENSATION_STEP, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t aeExposureCompensation = 4;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_013
 * @tc.desc: OHOS_ABILITY_FOCUS_MODES, OHOS_CONTROL_FOCUS_MODE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_013, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_MODES, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (size_t i = 0;i < entry.count;i++) {
            if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_MODE_MANUAL) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_MODE_MANUAL mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_MODE_AUTO) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_MODE_AUTO mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_MODE_LOCKED) {
                CAMERA_LOGI("OHOS_CAMERA_FOCUS_MODE_LOCKED mode is supported!");
            }
        }
    }

    for (uint8_t i = 0;i < entry.count;i++) {
        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t focusMode = entry.data.u8[i];
        meta->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, DATA_COUNT);
        if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_MODE_MANUAL) {
            uint8_t focusedPoint[] = {1, 1, 1, 1};
            meta->addEntry(OHOS_CONTROL_FOCUSED_POINT, &focusedPoint, DATA_COUNT);
        }
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_014
 * @tc.desc: OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE, OHOS_CONTROL_LENS_FOCUS_DISTANCE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_014, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, STILL_CAPTURE};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            float lensFocusDistance = entry.data.f[i];
            meta->addEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &lensFocusDistance, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
            cameraTest->captureIds = {cameraTest->captureIdPreview};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_015
 * @tc.desc: OHOS_ABILITY_AWB_MODES, OHOS_CONTROL_AWB_MODE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_015, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_CONTROL_AWB_AVAILABLE_MODES, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (size_t i = 0;i < entry.count;i++) {
            if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_OFF) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_OFF mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_AUTO) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_AUTO mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_INCANDESCENT) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_INCANDESCENT mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_FLUORESCENT) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_FLUORESCENT mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_WARM_FLUORESCENT mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_DAYLIGHT) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_DAYLIGHT mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_TWILIGHT) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_TWILIGHT mode is supported!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_AWB_MODE_SHADE) {
                CAMERA_LOGI("OHOS_CAMERA_AWB_MODE_SHADE mode is supported!");
            }
            
            cameraTest->intents = {PREVIEW, STILL_CAPTURE};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            uint8_t awbMode = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
            cameraTest->captureIds = {cameraTest->captureIdPreview};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_CONTROL_AWB_AVAILABLE_MODES> failed.\n");
        CAMERA_LOGE("get tag<OHOS_CONTROL_AWB_AVAILABLE_MODES> failed.");
    }
        
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_016
 * @tc.desc: OHOS_ABILITY_EXPOSURE_HINT_SUPPORTED, OHOS_CONTROL_EXPOSURE_HINT_MODE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_016, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_EXPOSURE_HINT_SUPPORTED, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t exposureHintMode = 1;
    meta->addEntry(OHOS_CONTROL_EXPOSURE_HINT_MODE, &exposureHintMode, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;

    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_ALGO_MEAN_Y, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_017
 * @tc.desc: OHOS_ABILITY_SENSOR_WB_VALUES, OHOS_CONTROL_SENSOR_WB_VALUE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_017, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_SENSOR_WB_VALUES, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, STILL_CAPTURE};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            int32_t wbMode = entry.data.i32[i];
            meta->addEntry(OHOS_CONTROL_SENSOR_WB_VALUE, &wbMode, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
            cameraTest->captureIds = {cameraTest->captureIdPreview};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_ABILITY_SENSOR_WB_VALUES> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_SENSOR_WB_VALUES> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_018
 * @tc.desc: OHOS_CONTROL_FLASH_MODE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_018, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    //0:close, 1:open, 2:auto, 3:always_open
    for (uint8_t i = 0;i < 4;i++) {
        cameraTest->intents = {PREVIEW, VIDEO};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t flashMode = i;
        meta->addEntry(OHOS_CONTROL_FLASH_MODE, &flashMode, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;

    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_PREVIEW_PHYSICAL_CAMERA_ID, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_019
 * @tc.desc: OHOS_CONTROL_SUPPORTED_COLOR_MODES, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_019, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    //0:normal, 1:bright, 2:soft
    for (uint8_t i = 0;i < 3;i++) {
        cameraTest->intents = {PREVIEW, VIDEO};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t colorMode = i;
        meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorMode, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_020
 * @tc.desc: OHOS_CONTROL_ZOOM_RATIO, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_020, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, VIDEO};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float zoomRatio = 1.0f;
    meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_021
 * @tc.desc: OHOS_CONTROL_METER_MODE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_021, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_METER_MODES, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {

        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, VIDEO};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            uint8_t meteringMode = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_METER_MODE, &meteringMode, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_ABILITY_METER_MODES> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_METER_MODES> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_022
 * @tc.desc: OHOS_CONTROL_ISO_VALUE, OHOS_STATUS_ISO_VALUE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_022, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, VIDEO};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t isoValue = 50;
    meta->addEntry(OHOS_CONTROL_ISO_VALUE, &isoValue, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;

    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_ISO_VALUE, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_023
 * @tc.desc: OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, OHOS_STATUS_CAMERA_APERTURE_VALUE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_023, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    GetSupportedPhysicalApertureValues(cameraTest->ability);

    for (uint8_t i = 0;i < supportedPhysicalApertureValues_.size();i++) {
        cameraTest->intents = {PREVIEW, VIDEO};
        cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        float physicalApertureValue = supportedPhysicalApertureValues_[i];
        meta->addEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalApertureValue, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
    
    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_CAMERA_APERTURE_VALUE, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_024
 * @tc.desc: OHOS_CONTROL_SENSOR_EXPOSURE_TIME, OHOS_STATUS_SENSOR_EXPOSURE_TIME, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_024, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.r != nullptr && entry.count > 0) {
        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, VIDEO};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            camera_rational_t sensorExposureTime = {entry.data.r[i].numerator, entry.data.r[i].denominator};
            meta->addEntry(OHOS_CONTROL_SENSOR_EXPOSURE_TIME, &sensorExposureTime, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_SENSOR_EXPOSURE_TIME_RANGE> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
    
    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_STATUS_SENSOR_EXPOSURE_TIME, &callbackEntry);
    EXPECT_NE(callbackEntry.data.r, nullptr);
    CAMERA_LOGI("the value of OHOS_STATUS_SENSOR_EXPOSURE_TIME is %{public}d/%{public}d",
        callbackEntry.data.r[0].numerator, callbackEntry.data.r[0].denominator);
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_025
 * @tc.desc: OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_025, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, VIDEO};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t aeExposureCompensation = 4;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_026
 * @tc.desc: OHOS_CONTROL_FOCUS_MODE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_026, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_MODES, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, VIDEO};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            uint8_t focusMode = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, DATA_COUNT);
            if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_MODE_MANUAL) {
                uint8_t focusedPoint[] = {1, 1, 1, 1};
                meta->addEntry(OHOS_CONTROL_FOCUSED_POINT, &focusedPoint, DATA_COUNT);
            }
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_ABILITY_FOCUS_MODES> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_FOCUS_MODES> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_027
 * @tc.desc: OHOS_CONTROL_LENS_FOCUS_DISTANCE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_027, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, VIDEO};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            float lensFocusDistance = entry.data.f[i];
            meta->addEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &lensFocusDistance, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_LENS_INFO_MINIMUM_FOCUS_DISTANCE> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_028
 * @tc.desc: OHOS_CONTROL_AWB_MODE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_028, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_CONTROL_AWB_AVAILABLE_MODES, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, VIDEO};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            uint8_t awbMode = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_CONTROL_AWB_AVAILABLE_MODES> failed.\n");
        CAMERA_LOGE("get tag<OHOS_CONTROL_AWB_AVAILABLE_MODES> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_029
 * @tc.desc: OHOS_CONTROL_SENSOR_WB_VALUE, PROFESSIONAL_VIDEO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_029, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO)) {
        cout << "skip this test, because PROFESSIONAL_VIDEO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_SENSOR_WB_VALUES, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        for (uint8_t i = 0;i < entry.count;i++) {
            cameraTest->intents = {PREVIEW, VIDEO};
            cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_VIDEO);

            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            int32_t wbMode = entry.data.i32[i];
            meta->addEntry(OHOS_CONTROL_SENSOR_WB_VALUE, &wbMode, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        }
    } else {
        printf("get tag<OHOS_ABILITY_SENSOR_WB_VALUES> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_SENSOR_WB_VALUES> failed.");
    }
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name:Camera_Professional_Hdi_V1_3_030
 * @tc.desc:different resolution
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_030, TestSize.Level1)
{
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    
    for (uint8_t i = 0; i < RESOLUTION_COUNT; i++) {
        // Preview streamInfo
        cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
        cameraTest->streamInfoPre->v1_0.width_ = g_supportedResolution[i][0];
        cameraTest->streamInfoPre->v1_0.height_ = g_supportedResolution[i][1];
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
        
        // Capture streamInfo
        cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->DefaultInfosProfessionalCapture(cameraTest->streamInfoCapture);
        cameraTest->streamInfoCapture->v1_0.width_ = g_supportedResolution[i][0];
        cameraTest->streamInfoCapture->v1_0.height_ = g_supportedResolution[i][1];
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
        
        // Create and commit stream
        cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
            static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO),
            cameraTest->abilityVec);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        
        // Start capture
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        
        // Stop stream
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        cameraTest->streamInfosV1_1.clear();
    }
    
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_031
 * @tc.desc: OHOS_CONTROL_ISO_VALUE, OHOS_CONTROL_SUPPORTED_COLOR_MODES, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_031, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t isoValue = 50;
    meta->addEntry(OHOS_CONTROL_ISO_VALUE, &isoValue, DATA_COUNT);
    uint8_t colorMode = 1;
    meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &colorMode, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_032
 * @tc.desc: OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, OHOS_CONTROL_ZOOM_RATIO, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_032, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t focusAssistFlashMode = OHOS_CAMERA_FOCUS_ASSIST_FLASH_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_FOCUS_ASSIST_FLASH_SUPPORTED_MODE, &focusAssistFlashMode, DATA_COUNT);
    float zoomRatio = 1.0f;
    meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_033
 * @tc.desc: OHOS_CONTROL_METER_MODE, OHOS_CONTROL_ISO_VALUE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_033, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t meteringMode = OHOS_CAMERA_SPOT_METERING;
    meta->addEntry(OHOS_CONTROL_METER_MODE, &meteringMode, DATA_COUNT);
    int32_t isoValue = 50;
    meta->addEntry(OHOS_CONTROL_ISO_VALUE, &isoValue, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_034
 * @tc.desc: OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_034, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    GetSupportedPhysicalApertureValues(cameraTest->ability);
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float physicalApertureValue = supportedPhysicalApertureValues_[0];
    meta->addEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalApertureValue, DATA_COUNT);
    int32_t aeExposureCompensation = 4;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Professional_Hdi_V1_3_035
 * @tc.desc: OHOS_CONTROL_FOCUS_MODE, OHOS_CONTROL_AWB_MODE, PROFESSIONAL_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraProfessionalUtTestV1_3, Camera_Professional_Hdi_V1_3_035, TestSize.Level1)
{
    if (!g_isModeExists(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO)) {
        cout << "skip this test, because PROFESSIONAL_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    FillCaptureSetting(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartProfessionalStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::PROFESSIONAL_PHOTO);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t focusMode = OHOS_CAMERA_FOCUS_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, DATA_COUNT);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}