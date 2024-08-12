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
#include <functional>

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
    cameraTest->Open(DEVICE_0); // assert inside
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
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
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

/**
 * @tc.name:Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_001
 * @tc.desc:Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_001
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_001, TestSize.Level1)
{
    bool isExit = false;
    // stub codes
    std::vector<uint8_t> cameraModesVector;
    cameraModesVector.push_back(OHOS::HDI::Camera::V1_2::STILL_IMAGE);
    cameraModesVector.push_back(OHOS::HDI::Camera::V1_2::MOVING_IMAGE);
    cameraTest->ability->addEntry(OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY,
        cameraModesVector.data(), cameraModesVector.size());

    // real test
    isExit = IsTagValueExistsU8(cameraTest->ability,\
        OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY,\
        OHOS::HDI::Camera::V1_2::STILL_IMAGE);
    EXPECT_EQ(isExit, true);
    isExit = IsTagValueExistsU8(cameraTest->ability,\
        OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY,\
        OHOS::HDI::Camera::V1_2::MOVING_IMAGE);
    EXPECT_EQ(isExit, true);
}

void CameraHdiUtTestV1_2::TakePhoteWithDefferredImage(int PhotoCount)
{
    auto meta = std::make_shared<CameraSetting>(100, 100);
    uint8_t value = OHOS::HDI::Camera::V1_2::STILL_IMAGE;
    meta->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &value, sizeof(value));
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    // take photo
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartStream(cameraTest->intents);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    for (int i = 0; i < PhotoCount; i++) {
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    }
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

void CameraHdiUtTestV1_2::RemovePendingImages()
{
    std::vector<std::string> pendingImages;
    int ret = cameraTest->imageProcessSession_->GetPendingImages(pendingImages);
    EXPECT_EQ(ret, 0);
    if (pendingImages.size() != 0) {
        for (auto imageId = pendingImages.begin(); imageId != pendingImages.end(); ++imageId) {
            ret = cameraTest->imageProcessSession_->RemoveImage(*imageId);
            EXPECT_EQ(ret, 0);
        }
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_002
 * @tc.desc:Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_002
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_002, TestSize.Level1)
{
    int ret = 0;
    bool isImageProcessServiceExist = true;

    // real test
    bool isExit = IsTagValueExistsU8(cameraTest->ability,\
        OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY,\
        OHOS::HDI::Camera::V1_2::STILL_IMAGE);
    EXPECT_EQ(isExit, true);

    // get DefferredImageTestInit
    ret = cameraTest->DefferredImageTestInit();
    EXPECT_EQ(ret, 0);
    if (ret != 0) {
        CAMERA_LOGE("DefferredImageTestInit Fail!!!");
        printf("DefferredImageTestInit Fail!!!\r\n");
        isImageProcessServiceExist = false;
    }
    // 如果存在未处理的图片，则删除未处理的图片
    RemovePendingImages();
    // take photo using deferred image delivery
    TakePhoteWithDefferredImage(1);

    // image deferred delivery process
    ASSERT_EQ(isImageProcessServiceExist, true);
    int taskCount = 0;
    ret = cameraTest->imageProcessSession_->GetCoucurrency(OHOS::HDI::Camera::V1_2::HIGH_PREFORMANCE, taskCount);
    EXPECT_EQ(ret, 0);
    std::vector<std::string> pendingImages;
    ret = cameraTest->imageProcessSession_->GetPendingImages(pendingImages);
    EXPECT_EQ(ret, 0);
    EXPECT_GE(taskCount, 1);
    // 拍照的第一张图不走二段式，走后台
    ASSERT_EQ(pendingImages.size(), 0);
    sleep(UT_SECOND_TIMES);
    EXPECT_EQ(cameraTest->imageProcessCallback_->coutProcessDone_, ONE);
}

void CameraHdiUtTestV1_2::ProcessPendingImages(int ret)
{
    // image deferred delivery process
    int taskCount = 0;
    std::vector<std::string> pendingImages;
    ret = cameraTest->imageProcessSession_->GetCoucurrency(OHOS::HDI::Camera::V1_2::BALANCED, taskCount);
    EXPECT_EQ(ret, 0);
    ret = cameraTest->imageProcessSession_->GetPendingImages(pendingImages);
    EXPECT_EQ(ret, 0);
    EXPECT_GE(taskCount, 1);
    // 拍照的第一张图不走二段式，走后台
    ASSERT_EQ(pendingImages.size(), TWO);
    ret = cameraTest->imageProcessSession_->SetExecutionMode(OHOS::HDI::Camera::V1_2::BALANCED);
    EXPECT_EQ(ret, 0);
    ret = cameraTest->imageProcessSession_->SetExecutionMode(OHOS::HDI::Camera::V1_2::LOW_POWER);
    EXPECT_EQ(ret, 0);
    ret = cameraTest->imageProcessSession_->SetExecutionMode(OHOS::HDI::Camera::V1_2::HIGH_PREFORMANCE);
    EXPECT_EQ(ret, 0);
    // process the first image
    ret = cameraTest->imageProcessSession_->ProcessImage(pendingImages[0]);
    EXPECT_EQ(ret, 0);
    int count = 0;
    cameraTest->imageProcessCallback_->isDone_ = false;
    while (!cameraTest->imageProcessCallback_->isDone_ && count < SIXTEEN) {
        count++;
        usleep(UT_MICROSECOND_TIMES);
        CAMERA_LOGI("ProcessPendingImages ProcessImage 1 wait count:%{public}d", count);
    }
    cameraTest->imageProcessCallback_->isDone_ = false;
    EXPECT_EQ(cameraTest->imageProcessCallback_->coutProcessDone_, TWO);
    // process the second image
    ret = cameraTest->imageProcessSession_->ProcessImage(pendingImages[1]);
    EXPECT_EQ(ret, 0);
    count = 0;
    cameraTest->imageProcessCallback_->isDone_ = false;
    while (!cameraTest->imageProcessCallback_->isDone_ && count < SIXTEEN) {
        count++;
        usleep(UT_MICROSECOND_TIMES);
        CAMERA_LOGI("ProcessPendingImages ProcessImage 2 wait count:%{public}d", count);
    }
    cameraTest->imageProcessCallback_->isDone_ = false;
    EXPECT_EQ(cameraTest->imageProcessCallback_->coutProcessDone_, THREE);
    // process the third image, and test the Interrupt, Reset, RemoveImage Interfaces
    ret = cameraTest->imageProcessSession_->Interrupt();
    EXPECT_EQ(ret, 0);
    ret = cameraTest->imageProcessSession_->Reset();
    EXPECT_EQ(ret, 0);
    ret = cameraTest->imageProcessSession_->RemoveImage(pendingImages[1]);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(cameraTest->imageProcessCallback_->coutProcessDone_, THREE);
    EXPECT_EQ(cameraTest->imageProcessCallback_->countError_, 0);
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_003
 * @tc.desc:Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_003
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_Defferred_Delivery_Image_003, TestSize.Level1)
{
    int ret = 0;
    bool isImageProcessServiceExist = true;
    // real test
    bool isExit = IsTagValueExistsU8(cameraTest->ability,\
        OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY, OHOS::HDI::Camera::V1_2::STILL_IMAGE);
    EXPECT_EQ(isExit, true);
    // get DefferredImageTestInit
    ret = cameraTest->DefferredImageTestInit();
    EXPECT_EQ(ret, 0);
    if (ret != 0) {
        CAMERA_LOGE("DefferredImageTestInit Fail");
        printf("DefferredImageTestInit Fail\r\n");
        isImageProcessServiceExist = false;
    }
    // 如果存在未处理的图片，则删除未处理的图片
    RemovePendingImages();
    // take three photo using deferred image delivery, three times
    TakePhoteWithDefferredImage(3);
    ASSERT_EQ(isImageProcessServiceExist, true);
    // 进行二段式处理拍照图片
    ProcessPendingImages(ret);
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
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        CAMERA_LOGI("OHOS_ABILITY_SUPPORTED_COLOR_MODES: %{public}d", entry.data.u8[0]);
    } else {
        print("XMage not supported\n");
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
        case CAMERA_CUSTOM_COLOR_NORMAL: {
            res = TODEFINESTRING(CAMERA_CUSTOM_COLOR_NORMAL);
            break;
        }
        case CAMERA_CUSTOM_COLOR_BRIGHT: {
            res = TODEFINESTRING(CAMERA_CUSTOM_COLOR_BRIGHT);
            break;
        }
        case CAMERA_CUSTOM_COLOR_SOFT: {
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
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
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
        CAMERA_LOGE("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME not supported");
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
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
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
        CAMERA_LOGE("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME not supported");
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
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("get tag<OHOS_ABILITY_VIDEO_STABILIZATION_MODES> failed.\n");
        return;
    }
    CAMERA_LOGI("get OHOS_ABILITY_VIDEO_STABILIZATION_MODES success!");
    if (entry.data.u8 != nullptr && entry.count > 0) {
        for (int i = 0; i < entry.count; i++) {
            if (entry.data.u8[i] == OHOS_CAMERA_VIDEO_STABILIZATION_OFF) {
                CAMERA_LOGI("OHOS_CAMERA_VIDEO_STABILIZATION_OFF found!");
            } else if (entry.data.u8[i] == OHOS_CAMERA_VIDEO_STABILIZATION_AUTO) {
                CAMERA_LOGI("OHOS_CAMERA_VIDEO_STABILIZATION_AUTO found!");
            }
        }
    } else {
        printf("get tag<OHOS_ABILITY_VIDEO_STABILIZATION_MODES> failed.\n");
        CAMERA_LOGE("get tag<OHOS_ABILITY_VIDEO_STABILIZATION_MODES> failed.");
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
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if (i == entry.count - 1) {
                printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES: %s\n", ss.str().c_str());
                ss.clear();
            }
        }
    }
}

void CaptureByColorSpaces(std::vector<int32_t> captureColorSpaces, std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    if (!captureColorSpaces.empty()) {
        for (int32_t colorSpaces : captureColorSpaces) {
            printf("capture colorSpaces value %d\n", colorSpaces);
            // preview streamInfo
            cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
            cameraTest->streamInfoV1_1->v1_0.dataspace_ = colorSpaces;
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
            // capture streamInfo
            cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
            cameraTest->streamInfoCapture->v1_0.dataspace_ = colorSpaces;
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
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
            cameraTest->streamInfosV1_1.clear();
        }
    }
}

void VideoByColorSpaces(std::vector<int32_t> videoColorSpaces, std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    if (!videoColorSpaces.empty()) {
        for (int32_t colorSpaces : videoColorSpaces) {
            printf("video colorSpaces value %d\n", colorSpaces);
            // preview streamInfo
            cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
            cameraTest->streamInfoV1_1->v1_0.dataspace_ = colorSpaces;
            if (colorSpaces == OHOS_CAMERA_BT2020_HLG_FULL) {
                cameraTest->streamInfoV1_1->v1_0.format_ = OHOS_CAMERA_FORMAT_YCBCR_P010;
            }
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
            // video streamInfo
            cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
            cameraTest->streamInfoVideo->v1_0.dataspace_ = colorSpaces;
            if (colorSpaces == OHOS_CAMERA_BT2020_HLG_FULL) {
                cameraTest->streamInfoVideo->v1_0.format_ = OHOS_CAMERA_FORMAT_YCBCR_P010;
            }
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
            cameraTest->streamInfosV1_1.clear();
        }
    }
}

void SuperStubByColorSpaces(std::vector<int32_t> superStubColorSpaces, std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    if (!superStubColorSpaces.empty()) {
        for (int32_t colorSpaces : superStubColorSpaces) {
            printf("superStubColorSpaces colorSpaces value %d\n", colorSpaces);
            // preview streamInfo
            cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
            cameraTest->streamInfoV1_1->v1_0.dataspace_ = colorSpaces;
            if (colorSpaces == OHOS_CAMERA_BT2020_HLG_FULL) {
                cameraTest->streamInfoV1_1->v1_0.format_ = OHOS_CAMERA_FORMAT_YCBCR_P010;
            }
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
            // video streamInfo
            cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
            cameraTest->streamInfoVideo->v1_0.dataspace_ = colorSpaces;
            if (colorSpaces == OHOS_CAMERA_BT2020_HLG_FULL) {
                cameraTest->streamInfoVideo->v1_0.format_ = OHOS_CAMERA_FORMAT_YCBCR_P010;
            }
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
            cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
            cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
                static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SUPER_STAB),
                cameraTest->abilityVec);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
            sleep(UT_SECOND_TIMES);
            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
            cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
            cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
            cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
            cameraTest->streamInfosV1_1.clear();
        }
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_033
 * @tc.desc: Update macro ability setting and check the callback
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_033, TestSize.Level1)
{
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(
        cameraTest->streamOperatorCallback, cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &entry);
    printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES value count %d\n", entry.count);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        std::vector<int32_t> captureColorSpaces;
        std::vector<int32_t> videoColorSpaces;
        std::vector<int32_t> superStubColorSpaces;
        int32_t operatorMode = -2;
        for (size_t i = 0; i < entry.count - 1; i++) {
            if (operatorMode == -2 && entry.data.i32[i] == HDI::Camera::V1_2::OperationMode_V1_2::CAPTURE) {
                operatorMode = HDI::Camera::V1_2::OperationMode_V1_2::CAPTURE;
            } else if (operatorMode == -2 && entry.data.i32[i] == HDI::Camera::V1_2::OperationMode_V1_2::VIDEO) {
                operatorMode = HDI::Camera::V1_2::OperationMode_V1_2::VIDEO;
            } else if (operatorMode == -2 && entry.data.i32[i] == HDI::Camera::V1_2::OperationMode_V1_2::SUPER_STAB) {
                operatorMode = HDI::Camera::V1_2::OperationMode_V1_2::SUPER_STAB;
            } else if (entry.data.i32[i] == -1 && operatorMode != -2 && entry.data.i32[i + 1] == -1) {
                operatorMode = -2;
            } else if (entry.data.i32[i] == -1 && operatorMode != -2 && entry.data.i32[i + 1] != -1) {
                operatorMode = -1;
            } else if (operatorMode == HDI::Camera::V1_2::OperationMode_V1_2::CAPTURE) {
                captureColorSpaces.push_back(entry.data.i32[i]);
            } else if (operatorMode == HDI::Camera::V1_2::OperationMode_V1_2::VIDEO) {
                videoColorSpaces.push_back(entry.data.i32[i]);
            } else if (operatorMode == HDI::Camera::V1_2::OperationMode_V1_2::SUPER_STAB) {
                superStubColorSpaces.push_back(entry.data.i32[i]);
            } else if (operatorMode == -2 && entry.data.i32[i] > 0) {
                operatorMode = -1;
            }
        }
        CaptureByColorSpaces(captureColorSpaces, cameraTest);
        VideoByColorSpaces(videoColorSpaces, cameraTest);
        SuperStubByColorSpaces(superStubColorSpaces, cameraTest);
    }
}

/**
 * @tc.name: CommitStreams_V1_1_SUPER_STAB
 * @tc.desc: CommitStreams_V1_1 for super stabilization mode, preview and video
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static void UpdateSettingsForSuperStabMode(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    bool isTagExitst = IsTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_VIDEO_STABILIZATION_MODES,
        OHOS_CAMERA_VIDEO_STABILIZATION_HIGH);
    EXPECT_EQ(isTagExitst, true);
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t stabControl = OHOS_CAMERA_VIDEO_STABILIZATION_HIGH;
    meta->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &stabControl, DATA_COUNT);
    // ability meta data serialization for updating
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    CAMERA_LOGD("Macro mode is set enabled.");
}

HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_SuperStub01, TestSize.Level1)
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

    // Capture streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // create and commitstreams
    UpdateSettingsForSuperStabMode(cameraTest);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::NORMAL),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // start preview, video and capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);

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
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        CAMERA_LOGI("OHOS_ABILITY_CAMERA_MACRO_SUPPORTED: %{public}d", entry.data.u8[0]);
    } else {
        CAMERA_LOGI("Macro not supported");
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
    int32_t rc;
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    rc = cameraTest->serviceV1_2->SetCallback_V1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(rc, 0);
    // Start OHOS_ABILITY_CAMERA_MACRO_SUPPORTED ability query
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MACRO_SUPPORTED, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        cameraTest->intents = {PREVIEW, STILL_CAPTURE, VIDEO};
        cameraTest->StartStream(cameraTest->intents);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);
        cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
        sleep(1);
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture,
            cameraTest->captureIdVideo};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture,
            cameraTest->streamIdVideo};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        sleep(UT_SECOND_TIMES);
        common_metadata_header_t* data = cameraTest->deviceCallback->resultMeta->get();
        EXPECT_NE(data, nullptr);
        camera_metadata_item_t entry;
        int ret = FindCameraMetadataItem(data, OHOS_CAMERA_MACRO_STATUS, &entry);
        if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
            uint8_t value = entry.data.u8[0];
            // 查询到状态， 检测状态到 微距模式可开启
            if (OHOS_CAMERA_MACRO_ENABLE == value) {
                printf("Macro mode is set enabled.");
            } else {
                printf("Macro mode is not enabled.");
            }
        } else {
            printf("Macro mode is not enabled.");
        }
    }
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
            ss << entry.data.f[i] << " ";
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
            ss << entry.data.f[i] << " ";
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
 * @tc.desc: OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_047, TestSize.Level1)
{
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
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
    float physicalApertureValue = 2;
    meta->addEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalApertureValue, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Hdi_V1_2_048
 * @tc.desc: OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_RANGE, all value
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_048, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE, &entry);

    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        float entryValues[] = { entry.data.f[3], entry.data.f[7], entry.data.f[8], entry.data.f[9], entry.data.f[10],
            entry.data.f[14], entry.data.f[18] };
        for (size_t i = 0; i < sizeof(entryValues) / sizeof(float); i++) {
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
            float physicalApertureValue = entryValues[i];
            meta->addEntry(OHOS_CONTROL_CAMERA_PHYSICAL_APERTURE_VALUE, &physicalApertureValue, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
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

/**
 * @tc.name: Camera_Hdi_V1_2_050
 * @tc.desc: macro mode
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_050, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_2_050 start ...");
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

    // capture streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float zoomRatio = 15;
    uint8_t macroControl = OHOS_CAMERA_MACRO_ENABLE;
    meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
    meta->addEntry(OHOS_CONTROL_CAMERA_MACRO, &macroControl, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // is streams supported V1_1
    StreamSupportType pType;
    cameraTest->rc = cameraTest->streamOperator_V1_1->IsStreamsSupported_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::CAPTURE_MACRO),
        setting, cameraTest->streamInfosV1_1, pType);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::CAPTURE_MACRO),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_051, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_2_051 start ...");
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
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);

    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float zoomRatio = 15;
    uint8_t macroControl = OHOS_CAMERA_MACRO_ENABLE;
    meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
    meta->addEntry(OHOS_CONTROL_CAMERA_MACRO, &macroControl, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // is streams supported V1_1
    StreamSupportType tType;
    cameraTest->rc = cameraTest->streamOperator_V1_1->IsStreamsSupported_V1_1(
    static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::VIDEO_MACRO),
    setting, cameraTest->streamInfosV1_1, tType);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
    static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::VIDEO_MACRO),
    cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: Camera_Hdi_V1_2_052
 * @tc.desc: OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, OHOS_CONTROL_MANUAL_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_052, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("get OHOS_ABILITY_VIDEO_STABILIZATION_MODES success!");
    } else {
        return;
    }
    if (entry.data.i32 != nullptr && entry.count > 0) {
        for (size_t i = 0; i < entry.count; i++) {
            printf("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME:%d\n", entry.data.i32[i]);
            
            //update settings
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            int32_t manualExposureTime = entry.data.i32[i];
            meta->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &manualExposureTime, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        }
    } else {
        CAMERA_LOGI("NIGHT_MODE data can't find!");
        printf("NIGHT_MODE data can't find!\n");
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_053
 * @tc.desc:Whether moon ability support
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_053, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_MOON_CAPTURE_BOOST, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        CAMERA_LOGI("OHOS_ABILITY_MOON_CAPTURE_BOOST: %{public}d", entry.data.u8[0]);
    } else {
        CAMERA_LOGI("MoonCaptureBoost not supported");
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_054
 * @tc.desc: Update moon ability setting
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_2, Camera_Device_Hdi_V1_2_054, TestSize.Level1)
{
    int32_t rc;
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    rc = cameraTest->serviceV1_2->SetCallback_V1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(rc, 0);
    // Start OHOS_ABILITY_MOON_CAPTURE_BOOST ability query
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_MOON_CAPTURE_BOOST, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        constexpr float zoomRatio = 15;
        uint8_t stabControl = OHOS_CAMERA_MOON_CAPTURE_BOOST_ENABLE;
        meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
        meta->addEntry(OHOS_CONTROL_MOON_CAPTURE_BOOST, &stabControl, DATA_COUNT);
        // ability meta data serialization for updating
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        CAMERA_LOGD("MoonCaptureBoost mode is set enabled.");

        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartStream(cameraTest->intents);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);
        sleep(1);
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        sleep(UT_SECOND_TIMES);
        common_metadata_header_t* data = cameraTest->deviceCallback->resultMeta->get();
        EXPECT_NE(data, nullptr);
        camera_metadata_item_t entry;
        int ret = FindCameraMetadataItem(data, OHOS_STATUS_MOON_CAPTURE_DETECTION, &entry);
        if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
            uint8_t value = entry.data.u8[0];
            // 查询到状态， 检测状态到 月亮模式可开启
            if (OHOS_CAMERA_MOON_CAPTURE_BOOST_ENABLE == value) {
                printf("Moon mode is set enabled.");
            } else {
                printf("Moon mode is not enabled.");
            }
        } else {
            printf("Moon mode is not enabled.");
        }
    }
}