/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "camera_vendor_tag_test.h"

#include <dlfcn.h>
#include "camera_example_vendor_tags.h"

const char* g_exampleVendorTagLib = "libcamera_example_vendor_tag_impl.z.so";

void UtestCameraVendorTagTest::SetUpTestCase(void)
{}

void UtestCameraVendorTagTest::TearDownTestCase(void)
{}

void UtestCameraVendorTagTest::SetUp(void)
{
    if (cameraBase_ == nullptr)
    cameraBase_ = std::make_shared<TestCameraBase>();
    cameraBase_->UsbInit();
}

void UtestCameraVendorTagTest::TearDown(void)
{
    cameraBase_->Close();
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_001)
{
    constexpr int itemCapacitySize = 30;
    constexpr int dataCapacitySize = 2000;
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(itemCapacitySize, dataCapacitySize);
    const uint8_t sensorMode = 5;
    int ohosTag = EXAMPLE_VENDOR_SENSOR_MODE;
    if (!meta->addEntry(ohosTag, &sensorMode, 1)) {
        CAMERA_LOGE("%{public}s(%{public}d) add failed", GetCameraMetadataItemName(ohosTag), ohosTag);
        GTEST_SKIP();
    }
    CAMERA_LOGD("%{public}s(%{public}ld) add success", GetCameraMetadataItemName(ohosTag), ohosTag);

    common_metadata_header_t *data = meta->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, EXAMPLE_VENDOR_SENSOR_MODE, &entry);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_EQ(entry.data.u8[0], sensorMode);
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_002)
{
    ability_ = cameraBase_->GetCameraAbility();
    EXPECT_NE(ability_, nullptr);

    constexpr int itemCapacitySize = 30;
    constexpr int dataCapacitySize = 2000;
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(itemCapacitySize, dataCapacitySize);
    const uint8_t sensorMode = 1;
    int ohosTag = EXAMPLE_VENDOR_SENSOR_MODE;
    if (!meta->addEntry(ohosTag, &sensorMode, 1)) {
        CAMERA_LOGE("%{public}s(%{public}d) add failed", GetCameraMetadataItemName(ohosTag), ohosTag);
        GTEST_SKIP();
    }
    CAMERA_LOGD("%{public}s(%{public}ld) add success", GetCameraMetadataItemName(ohosTag), ohosTag);

    const uint8_t newSensorMode = 5;
    std::vector<uint8_t> sensorModeVector;
    sensorModeVector.push_back(newSensorMode);
    if (!meta->updateEntry(EXAMPLE_VENDOR_SENSOR_MODE, sensorModeVector.data(), sensorModeVector.size())) {
        CAMERA_LOGE("update %{public}s failed", GetCameraMetadataItemName(ohosTag));
    }

    common_metadata_header_t *data = meta->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, EXAMPLE_VENDOR_SENSOR_MODE, &entry);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_EQ(entry.data.u8[0], newSensorMode);
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_003)
{
    constexpr int itemCapacitySize = 30;
    constexpr int dataCapacitySize = 2000;
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(itemCapacitySize, dataCapacitySize);

    int ohosTag = EXAMPLE_VENDOR_SENSOR_MODE;
    auto ret = meta->addEntry(ohosTag, nullptr, 1);
    EXPECT_EQ(ret, false);
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_004)
{
    constexpr int itemCapacitySize = 30;
    constexpr int dataCapacitySize = 2000;
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(itemCapacitySize, dataCapacitySize);
    const int64_t sensorExposure = 34;
    int ohosTag = EXAMPLE_VENDOR_SENSOR_EXPOSURE;
    if (!meta->addEntry(ohosTag, &sensorExposure, 1)) {
        CAMERA_LOGE("%{public}s(%{public}d) add failed", GetCameraMetadataItemName(ohosTag), ohosTag);
        GTEST_SKIP();
    }
    CAMERA_LOGD("%{public}s(%{public}ld) add success", GetCameraMetadataItemName(ohosTag), ohosTag);

    const int64_t newSensorExposure = 5;
    std::vector<int64_t> sensorExposureVector;
    sensorExposureVector.push_back(newSensorExposure);
    if (!meta->updateEntry(EXAMPLE_VENDOR_SENSOR_EXPOSURE, sensorExposureVector.data(), sensorExposureVector.size())) {
        CAMERA_LOGE("update %{public}s failed", GetCameraMetadataItemName(ohosTag));
    }

    common_metadata_header_t *data = meta->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, EXAMPLE_VENDOR_SENSOR_EXPOSURE, &entry);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_EQ(entry.data.i64[0], newSensorExposure);
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_005)
{
    constexpr int itemCapacitySize = 30;
    constexpr int dataCapacitySize = 2000;
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(itemCapacitySize, dataCapacitySize);
    const int64_t sensorExposure = 34;
    int ohosTag = EXAMPLE_VENDOR_SENSOR_EXPOSURE;
    if (!meta->addEntry(ohosTag, &sensorExposure, 1)) {
        CAMERA_LOGE("%{public}s(%{public}d) add failed", GetCameraMetadataItemName(ohosTag), ohosTag);
        GTEST_SKIP();
    }
    CAMERA_LOGD("%{public}s(%{public}ld) add success", GetCameraMetadataItemName(ohosTag), ohosTag);

    common_metadata_header_t *data = meta->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, EXAMPLE_VENDOR_SENSOR_EXPOSURE, &entry);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_EQ(entry.data.i64[0], sensorExposure);
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_006)
{
    constexpr int itemCapacitySize = 30;
    constexpr int dataCapacitySize = 2000;
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(itemCapacitySize, dataCapacitySize);

    int ohosTag = EXAMPLE_VENDOR_SENSOR_EXPOSURE;
    auto ret = meta->addEntry(ohosTag, nullptr, 1);
    EXPECT_EQ(ret, false);
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_007)
{
    void* libHandle = dlopen(g_exampleVendorTagLib, RTLD_LAZY);
    if (libHandle == nullptr) {
        GTEST_SKIP() << "please push " << g_exampleVendorTagLib << " to the device." << std::endl;
    } else {
        dlclose(libHandle);
    }

    // Get the device manager
    cameraBase_->OpenUsbCamera();
    ability_ = cameraBase_->GetCameraAbility();
    EXPECT_NE(ability_, nullptr);

    // Get the stream manager
    cameraBase_->AchieveStreamOperator();

    // start stream
    cameraBase_->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);

     // updateSettings
    const uint32_t itemCapacity = 100;
    const uint32_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        itemCapacity, dataCapacity);
    const int64_t sensorExposure = 8888;
    int ohosTag = EXAMPLE_VENDOR_SENSOR_EXPOSURE;
    if (!meta->addEntry(ohosTag, &sensorExposure, 1)) {
        std::cout << "addEntry failed" << std::endl;
        GTEST_SKIP();
    }
    std::cout << GetCameraMetadataItemName(ohosTag) << "(" << ohosTag << ")" << "add success" << std::endl;
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);

    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_CAPTURE};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

TEST_F(UtestCameraVendorTagTest, camera_vendor_tag_008)
{
    void* libHandle = dlopen(g_exampleVendorTagLib, RTLD_LAZY);
    if (libHandle == nullptr) {
        GTEST_SKIP() << "please push " << g_exampleVendorTagLib << " to the device." << std::endl;
    } else {
        dlclose(libHandle);
    }

    std::vector<vendorTag_t> tagVec {};
    auto ret = GetAllVendorTags(tagVec);
    for (auto tag : tagVec) {
        std::cout << "tagId = " << tag.tagId << ", tagName = " << tag.tagName << "\n";
    }
    EXPECT_EQ(ret, CAM_META_SUCCESS);
}
