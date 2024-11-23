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
#include "camera_metadata_enum_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::HDI::Camera;

void CameraMetadataEnumTest::SetUpTestCase(void) {}
void CameraMetadataEnumTest::TearDownTestCase(void) {}
void CameraMetadataEnumTest::SetUp(void)
{
    printf("CameraMetadataEnumTest start\r\n");
}

void CameraMetadataEnumTest::TearDown(void)
{
    printf("CameraMetadataEnumTest end\r\n");
}


/**
 * @tc.name: Camera_Metedate_Enum_001
 * @tc.desc: OperationMode
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_001, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_001 start...\n");
    std::vector<int32_t> operationMode = {
        OHOS::HDI::Camera::V1_3::OperationMode::QUICK_SHOT_PHOTO,
        OHOS::HDI::Camera::V1_3::OperationMode::TIMELAPSE_PHOTO,
        OHOS::HDI::Camera::V1_3::OperationMode::FLUORESCENCE_PHOTO,
    };
    ASSERT_EQ(operationMode.empty(), false);
    for (int32_t i = 0; i < operationMode.size(); i++) {
        switch (operationMode[i]) {
            case 16 : {
                printf("OHOS::HDI::Camera::V1_3::OperationMode::CAMERA_CUSTOM_COLOR_NORMAL is here\n");
                break;
            }
            case 19 : {
                printf("OHOS::HDI::Camera::V1_3::OperationMode::CAMERA_CUSTOM_COLOR_NORMAL is here\n");
                break;
            }
            case 21 : {
                printf("OHOS::HDI::Camera::V1_3::OperationMode::CAMERA_CUSTOM_COLOR_NORMAL is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_002
 * @tc.desc: DeferredDeliveryImageType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_002, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_002 start...\n");
    std::vector<int> deferredDelivery = {
        OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::NONE,
        OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::MOVING_IMAGE,
    };
    ASSERT_EQ(deferredDelivery.empty(), false);
    for (int32_t i = 0; i < deferredDelivery.size(); i++) {
        switch (deferredDelivery[i]) {
            case 0 : {
                printf("OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::NONE is here\n");
                break;
            }
            case 2 : {
                printf("OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::MOVING_IMAGE is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_003
 * @tc.desc: SessionStatus
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_003, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_003 start...\n");
    std::vector<int> sessionStatus = {
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED,
    };
    ASSERT_EQ(sessionStatus.empty(), false);
    for (int32_t i = 0; i < sessionStatus.size(); i++) {
        switch (sessionStatus[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED is here\n");
                break;
            }
            case 2: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY is here\n");
                break;
            }
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT is here\n");
                break;
            }
            case 4: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_004
 * @tc.desc: ErrorCode
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_004, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_004 start...\n");
    std::vector<int> errorCode = {
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_INVALID_ID,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_PROCESS,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_TIMEOUT,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_HIGH_TEMPERATURE,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABNORMAL,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABORT,
    };
    ASSERT_EQ(errorCode.empty(), false);
    for (int32_t i = 0; i < errorCode.size(); i++) {
        switch (errorCode[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_INVALID_ID is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_PROCESS is here\n");
                break;
            }
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_HIGH_TEMPERATURE is here\n");
                break;
            }
            case 4: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABNORMAL is here\n");
                break;
            }
            case 5: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABORT is here\n");
                break;
            }
        }
    } 
}

/**
 * @tc.name: Camera_Metedate_Enum_005
 * @tc.desc: ExtendedStreamInfoType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Info_005, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_005 start...\n");
    std::vector<int> extendedStream = {
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_DEPTH,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_EXIF,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_GAINMAP,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_UNREFOCUS,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_LINEAR,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_FRAGMENT,
    };
    ASSERT_EQ(extendedStream.empty(), false);
    for (int32_t i = 0; i < extendedStream.size(); i++) {
        switch (extendedStream[i]) {
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_DEPTH is here\n");
                break;
            }
            case 6: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO is here\n");
                break;
            }
            case 7: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_EXIF is here\n");
                break;
            }
            case 8: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_GAINMAP is here\n");
                break;
            }
            case 9: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_UNREFOCUS is here\n");
                break;
            }
            case 10: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_LINEAR is here\n");
                break;
            }
            case 11: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_FRAGMENT is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_006
 * @tc.desc: StreamType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_006, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_006 start...\n");
    std::vector<int> streamyType = {
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_PREVIEW,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_VIDEO,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_STILL_CAPTURE,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_POST_VIEW,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_ANALYZE,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_CUSTOM,
    };
    ASSERT_EQ(streamyType.empty(), false);
    for (int32_t i = 0; i < streamyType.size(); i++) {
        switch (streamyType[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_PREVIEW is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_VIDEO is here\n");
                break;
            }
            case 2: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_STILL_CAPTURE is here\n");
                break;
            }
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::EXTENDED_STREAM_INFO_GAINMAP is here\n");
                break;
            }
            case 4: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::EXTENDED_STREAM_INFO_UNFOCUS is here\n");
                break;
            }
            case 5: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_CUSTOM is here\n");
                break;
            }
        }
    } 
}

/**
 * @tc.name: Camera_Metedate_Enum_007
 * @tc.desc: MediaStreamType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_007, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_007 start...\n");
    std::vector<int> mediaStream = {
        OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_METADATA,
        OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
    };
    ASSERT_EQ(mediaStream.empty(), false);
    for (int32_t i = 0; i < mediaStream.size(); i++) {
        switch (mediaStream[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_METADATA is here\n");
                break;
            }
            case 2: {
                printf("OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_007
 * @tc.desc: MediaStreamType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_008, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_008 start...\n");
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::ExecutionMode::DEFAULT, 3);
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::ErrorType::SENSOR_DATA_ERROR, 5);
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::EncodeType::ENCODE_TYPE_HEIC, 4);
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::StreamError::HIGH_TEMPERATURE_ERROR, 2);
}