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
#include "camera_metadata_utils_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraMetadataUtilsTest::SetUpTestCase(void) {}
void CameraMetadataUtilsTest::TearDownTestCase(void) {}
void CameraMetadataUtilsTest::SetUp(void)
{
    printf("CameraMetadataUtilsTest start\r\n");
}

void CameraMetadataUtilsTest::TearDown(void)
{
    printf("CameraMetadataUtilsTest end\r\n");
}

static void PrintMetaDataInfo(const shared_ptr<CameraMetadata> &metadata)
{
    if (metadata == nullptr) {
        cout << "metadata is nullptr" <<endl;
        return;
    }
    common_metadata_header_t *header = metadata->get();
    if (header == nullptr) {
        cout << "header is nullptr" <<endl;
        return;
    }
    cout << "PrintMetaDataInfo begin++++++++++" << endl;
    cout << "version       : " << header->version << endl;
    cout << "size          : " << header->size << endl;
    cout << "item_count    : " << header->item_count << endl;
    cout << "item_capacity : " << header->item_capacity << endl;
    cout << "data_count    : " << header->data_count << endl;
    cout << "data_capacity : " << header->data_capacity << endl;
    cout << "PrintMetaDataInfo begin-----------" << endl;
}

/**
 * @tc.name: Metadata_Utils_001
 * @tc.desc: metadata = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataUtilsTest, Metadata_Utils_001, TestSize.Level1)
{
    int32_t ret;
    auto metaData = make_shared<CameraMetadata>(100, 200);
    int8_t cameraType[] = {10, 30};
    int32_t cameraFpsRange[] = {10, 30};
    uint32_t cameraMesureExposureTime[] = {10};
    int64_t sensorExposeTime[] = {30};
    float sensorInfoPhysicalSize[] = {0.1};
    float jpegGpsCoordinates[] = {0.1, 0.1};

    camera_rational_t controlAeCompenstationStep[] = {{1, 3}};
    metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 1);
    metaData->addEntry(OHOS_ABILITY_FPS_RANGES, cameraFpsRange, 2);
    metaData->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, cameraMesureExposureTime, 1);
    metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, sensorExposeTime, 1);
    metaData->addEntry(OHOS_SENSOR_INFO_PHYSICAL_SIZE, sensorInfoPhysicalSize, 1);
    metaData->addEntry(OHOS_JPEG_GPS_COORDINATES, jpegGpsCoordinates, 1);
    metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, controlAeCompenstationStep, 1);

    vector<uint8_t> metaVec;
    ret = MetadataUtils::ConvertMetadataToVec(metaData, metaVec);
    EXPECT_EQ(ret, true);
    shared_ptr<CameraMetadata> metaDataBack1;
    MetadataUtils::ConvertVecToMetadata(metaVec, metaDataBack1);
    EXPECT_NE(metaDataBack1, nullptr);

    MessageParcel messageParcel;
    ret = MetadataUtils::EncodeCameraMetadata(metaData, messageParcel);
    EXPECT_EQ(ret, true);
    shared_ptr<CameraMetadata> metaDataBack2;
    MetadataUtils::DecodeCameraMetadata(messageParcel, metaDataBack2);
    EXPECT_NE(metaDataBack2, nullptr);

    string metaString = MetadataUtils::EncodeToString(metaData);
    std::cout << "metaString: " << metaString << std::endl;
    auto metaDataBack3 = MetadataUtils::DecodeFromString(metaString);
    EXPECT_NE(metaDataBack3, nullptr);
}
/**
 * @tc.name: Metadata_Utils_002
 * @tc.desc: metadata = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataUtilsTest, Metadata_Utils_002, TestSize.Level1)
{
    int32_t ret;
    auto metaData = nullptr;
    vector<uint8_t> metaVec;
    ret = MetadataUtils::ConvertMetadataToVec(metaData, metaVec);
    EXPECT_EQ(ret, false);

    MessageParcel messageParcel;
    ret = MetadataUtils::EncodeCameraMetadata(metaData, messageParcel);
    EXPECT_EQ(ret, false);

    string metaString = MetadataUtils::EncodeToString(metaData);
    std::cout << "metaString: " << metaString << std::endl;
    EXPECT_EQ(metaString, "");
}

/**
 * @tc.name: Metadata_Utils_003
 * @tc.desc: metadata is empty
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataUtilsTest, Metadata_Utils_003, TestSize.Level1)
{
    int32_t ret;
    auto metaData = make_shared<CameraMetadata>(100, 200);
    vector<uint8_t> metaVec;
    ret = MetadataUtils::ConvertMetadataToVec(metaData, metaVec);
    EXPECT_EQ(ret, true);

    MessageParcel messageParcel;
    ret = MetadataUtils::EncodeCameraMetadata(metaData, messageParcel);
    EXPECT_EQ(ret, true);

    string metaString = MetadataUtils::EncodeToString(metaData);
    std::cout << "metaString: " << metaString << std::endl;
}

constexpr uint32_t MAX_SUPPORTED_TAGS = 1000;
constexpr uint32_t MAX_SUPPORTED_ITEMS = 2000;
constexpr uint32_t MAX_ITEM_CAPACITY = (1000 * 10);
constexpr uint32_t MAX_DATA_CAPACITY = (1000 * 10 * 10);

/**
 * @tc.name: Metadata_Utils_004
 * @tc.desc: metadata is invalid
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataUtilsTest, Metadata_Utils_004, TestSize.Level1)
{
    int32_t ret;
    uint8_t temp[20] = {0};
    vector<uint8_t> metaVec;

    auto metaData0 = make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_DATA_CAPACITY);
    for (int i = 0; i < MAX_SUPPORTED_TAGS + 1; i++) {
        metaData0->addEntry(OHOS_ABILITY_CAMERA_TYPE, temp, 1);
    }
    PrintMetaDataInfo(metaData0);
    ret = MetadataUtils::ConvertMetadataToVec(metaData0, metaVec);
    EXPECT_EQ(ret, false);

    auto metaData1 = make_shared<CameraMetadata>(MAX_ITEM_CAPACITY + 1, MAX_DATA_CAPACITY);
    PrintMetaDataInfo(metaData1);
    ret = MetadataUtils::ConvertMetadataToVec(metaData1, metaVec);
    EXPECT_EQ(ret, false);

    auto metaData2 = make_shared<CameraMetadata>(MAX_ITEM_CAPACITY, MAX_DATA_CAPACITY + 1);
    PrintMetaDataInfo(metaData2);
    ret = MetadataUtils::ConvertMetadataToVec(metaData2, metaVec);
    EXPECT_EQ(ret, false);

    auto metaData3 = make_shared<CameraMetadata>(MAX_ITEM_CAPACITY + 1, MAX_DATA_CAPACITY + 1);
    auto itemData0 = new uint8_t[MAX_SUPPORTED_ITEMS + 1];
    metaData3->addEntry(OHOS_ABILITY_CAMERA_TYPE, itemData0, MAX_SUPPORTED_ITEMS + 1);
    delete [] itemData0;
    PrintMetaDataInfo(metaData3);
    ret = MetadataUtils::ConvertMetadataToVec(metaData3, metaVec);
    EXPECT_EQ(ret, false);
}
